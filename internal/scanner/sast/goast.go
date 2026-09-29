package sast

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"

	"github.com/cozygarage/sentinelflow/internal/scanner/fingerprint"
	"github.com/cozygarage/sentinelflow/internal/scanner/redact"
	"github.com/cozygarage/sentinelflow/pkg/api"
)

func (s *Scanner) scanGoAST(ctx context.Context, files []string, base string) ([]api.Finding, error) {
	var findings []api.Finding
	var hasTaintSource, hasShellSink bool
	fset := token.NewFileSet()
	for _, path := range files {
		if !strings.EqualFold(filepath.Ext(path), ".go") {
			continue
		}
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}
		src, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		f, err := parser.ParseFile(fset, path, src, parser.SkipObjectResolution)
		if err != nil {
			continue
		}
		rel := path
		if r, err := filepath.Rel(base, path); err == nil {
			rel = filepath.ToSlash(r)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			name := callName(call.Fun)
			if name == "os.Getenv" || name == "Get" || name == "http.Get" ||
				strings.HasSuffix(name, ".FormValue") || strings.HasSuffix(name, ".PostFormValue") {
				hasTaintSource = true
			}
			if name == "exec.Command" || name == "exec.CommandContext" {
				hasShellSink = true
			}
			pos := fset.Position(call.Pos())
			switch name {
			case "exec.Command", "exec.CommandContext":
				exe := 0
				if name == "exec.CommandContext" {
					exe = 1
				}
				if len(call.Args) > exe && !isStaticString(call.Args[exe]) {
					findings = append(findings, astFinding(rel, pos, "go-ast-exec-nonconst",
						"exec.Command with non-constant executable",
						"The executable path is not a string literal.", "cmd-inject", api.SeverityHigh, "CWE-78"))
				}
			case "db.Query", "db.QueryContext", "db.QueryRow", "db.QueryRowContext", "db.Exec", "db.ExecContext", "db.Prepare", "db.PrepareContext",
				"sql.Query", "tx.Query", "tx.QueryContext", "tx.QueryRow", "tx.QueryRowContext", "tx.Exec", "tx.ExecContext", "tx.Prepare", "tx.PrepareContext",
				"stmt.Query", "stmt.Exec", "stmt.QueryContext", "stmt.ExecContext":
				queryArg := 0
				if strings.HasSuffix(name, "Context") {
					queryArg = 1
				}
				if len(call.Args) > queryArg && looksLikeSQLArg(call.Args[queryArg]) && !isStaticString(call.Args[queryArg]) {
					findings = append(findings, astFinding(rel, pos, "go-ast-sql-nonconst",
						"SQL query with non-constant argument",
						"Pass a constant query string and bind parameters.", "sqli", api.SeverityHigh, "CWE-89"))
				}
			}
			return true
		})
	}
	if hasTaintSource && hasShellSink {
		findings = append(findings, scanGoShellTaintSSA(ctx, base, files)...)
	}
	return findings, nil
}

func astFinding(rel string, pos token.Position, rule, title, desc, category string, sev api.Severity, cwe string) api.Finding {
	f := api.Finding{
		ID:          fmt.Sprintf("SAST-%s-%s-%d", rule, pathToken(rel), pos.Line),
		Type:        api.FindingTypeInsecureCode,
		Severity:    sev,
		Title:       title,
		Description: desc,
		Location: api.Location{
			File: rel, StartLine: pos.Line, EndLine: pos.Line, Snippet: redact.Snippet(pos.String()),
		},
		Remediation: remediationFor(category),
		Scanner:     "sast",
		RuleID:      rule,
		CWE:         []string{cwe},
		Confidence:  0.75,
	}
	f.Fingerprint = fingerprint.Of(f)
	return f
}

func callName(fun ast.Expr) string {
	switch x := fun.(type) {
	case *ast.SelectorExpr:
		if id, ok := x.X.(*ast.Ident); ok {
			return id.Name + "." + x.Sel.Name
		}
		return x.Sel.Name
	case *ast.Ident:
		return x.Name
	}
	return ""
}

func isStaticString(e ast.Expr) bool {
	switch x := e.(type) {
	case *ast.BasicLit:
		return x.Kind == token.STRING
	case *ast.Ident:
		return false
	case *ast.BinaryExpr:
		return isStaticString(x.X) && isStaticString(x.Y)
	}
	return false
}

func looksLikeSQLArg(e ast.Expr) bool {
	if lit, ok := e.(*ast.BasicLit); ok && lit.Kind == token.STRING {
		s := strings.ToUpper(lit.Value)
		return strings.Contains(s, "SELECT") || strings.Contains(s, "INSERT") || strings.Contains(s, "UPDATE") || strings.Contains(s, "DELETE")
	}
	// Non-constant first arg to Query/Exec is treated as possible SQL.
	return !isStaticString(e)
}
