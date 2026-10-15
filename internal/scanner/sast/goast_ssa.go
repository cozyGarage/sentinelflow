package sast

import (
	"context"
	"go/constant"
	"go/types"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/cozygarage/sentinelflow/pkg/api"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

func scanGoTaintSSA(ctx context.Context, base string, files []string) []api.Finding {
	root, pattern, ok := goPackagePattern(base)
	if !ok {
		return nil
	}
	loaded, err := packages.Load(&packages.Config{
		Context: ctx, Dir: root, Mode: packages.LoadSyntax | packages.NeedModule,
		Env: append(os.Environ(), "GOPROXY=off", "GOSUMDB=off"),
	}, pattern)
	if err != nil {
		return nil
	}
	var roots []*packages.Package
	for _, pkg := range loaded {
		if pkg.Module != nil && pkg.Module.Main && pkg.Types != nil && !pkg.IllTyped {
			roots = append(roots, pkg)
		}
	}
	if len(roots) == 0 {
		return nil
	}
	prog, _ := ssautil.Packages(roots, ssa.InstantiateGenerics)
	prog.Build()

	scanned := make(map[string]string, len(files))
	for _, file := range files {
		if abs, err := filepath.Abs(file); err == nil {
			scanned[filepath.Clean(abs)] = filepath.ToSlash(relativePath(base, file))
		}
	}

	functions := make(map[*ssa.Function]bool)
	for fn := range ssautil.AllFunctions(prog) {
		pos := prog.Fset.Position(fn.Pos())
		if !pos.IsValid() {
			continue
		}
		abs, err := filepath.Abs(pos.Filename)
		if len(fn.Blocks) > 0 && err == nil && withinDir(root, abs) {
			functions[fn] = true
		}
	}
	// Two passes over the same rules reach a joint fixpoint:
	//   local:   parameters are seeded with their own label bits, so each
	//            function's return summary says which params flow to it;
	//   tainted: parameters receive real taint from every caller, which is what
	//            sinks inside callees need.
	// Call results use the callee summary in both maps, so a function that
	// returns a tainted param does not taint unrelated call sites.
	local := make(map[ssa.Value]taint)
	tainted := make(map[ssa.Value]taint)
	summary := make(map[*ssa.Function]taint)
	for fn := range functions {
		for i, param := range fn.Params {
			local[param] |= paramLabel(i)
		}
	}
	for changed := true; changed; {
		changed = false
		for fn := range functions {
			for _, block := range fn.Blocks {
				for _, instr := range block.Instrs {
					if propagateTaint(instr, local, true, functions, summary, tainted) {
						changed = true
					}
					if propagateTaint(instr, tainted, false, functions, summary, tainted) {
						changed = true
					}
					if ret, ok := instr.(*ssa.Return); ok {
						if t := ssaUnion(ret.Results, local); summary[fn]|t != summary[fn] {
							summary[fn] |= t
							changed = true
						}
					}
				}
			}
		}
	}

	var findings []api.Finding
	for fn := range functions {
		for _, block := range fn.Blocks {
			for _, instr := range block.Instrs {
				call := ssaCall(instr)
				if call == nil {
					continue
				}
				pos := prog.Fset.Position(instr.Pos())
				abs, err := filepath.Abs(pos.Filename)
				if err != nil {
					continue
				}
				rel, ok := scanned[filepath.Clean(abs)]
				if !ok {
					continue
				}
				if isSSAShellCall(call) && ssaShellInputTainted(call, tainted) {
					findings = append(findings, astFinding(rel, pos, "go-ast-shell-tainted",
						"User input passed to shell command",
						"Avoid passing request data to a shell; use a fixed executable and validated arguments.",
						"cmd-inject", api.SeverityCritical, "CWE-78"))
					continue
				}
				if sink, arg := matchSSASink(call); sink != nil && tainted[arg]&taintRequest != 0 {
					findings = append(findings, astFinding(rel, pos, sink.rule, sink.title, sink.desc, sink.category, sink.severity, sink.cwe))
				}
			}
		}
	}
	return findings
}

// taint records where a value came from. Environment variables are
// operator-controlled, so they only matter for the shell rule; request data
// matters for every sink.
type taint uint64

const (
	taintEnv taint = 1 << iota
	taintRequest
	taintReal = taintEnv | taintRequest
)

// paramLabel marks "flows from parameter i" in a function's local map.
func paramLabel(i int) taint {
	if i > 61 {
		return 0
	}
	return 1 << (2 + i)
}

// propagateTaint applies one instruction's flow rules to m and reports whether m changed.
// In the local map parameters keep their labels; in the global map they take
// real taint from call arguments.
func propagateTaint(instr ssa.Instruction, m map[ssa.Value]taint, isLocal bool,
	functions map[*ssa.Function]bool, summary map[*ssa.Function]taint, global map[ssa.Value]taint) bool {
	changed := false
	mark := func(value ssa.Value, t taint) {
		if value != nil && t != 0 && m[value]|t != m[value] {
			m[value] |= t
			changed = true
		}
	}
	value, isValue := instr.(ssa.Value)
	if call := ssaCall(instr); call != nil {
		callee := call.StaticCallee()
		if t := ssaSource(call); t != 0 && isValue {
			mark(value, t)
		}
		switch {
		case functions[callee]:
			if !isLocal {
				for i, arg := range call.Args {
					if i < len(callee.Params) {
						mark(callee.Params[i], m[arg]&taintReal)
					}
				}
			}
			if closure, ok := call.Value.(*ssa.MakeClosure); ok {
				for i, binding := range closure.Bindings {
					if i < len(callee.FreeVars) {
						// Free variables are context-insensitive: real taint only.
						mark(callee.FreeVars[i], global[binding]&taintReal)
					}
				}
			}
			if isValue {
				sum := summary[callee]
				t := sum & taintReal
				for i, arg := range call.Args {
					if sum&paramLabel(i) != 0 {
						t |= m[arg]
					}
				}
				mark(value, t)
			}
		case isValue && !isSSASanitizer(callee):
			// Unknown callee: assume the result carries its inputs' taint.
			t := ssaUnion(call.Args, m)
			if call.IsInvoke() {
				t |= m[call.Value]
			}
			mark(value, t)
		}
		return changed
	}
	switch x := instr.(type) {
	case *ssa.Store:
		root := ssaStorageRoot(x.Addr)
		t := m[x.Val]
		if _, isGlobal := root.(*ssa.Global); isGlobal {
			t &= taintReal // labels are per function; globals are shared
		}
		mark(x.Addr, t)
		mark(root, t)
	case *ssa.FieldAddr:
		if isHTTPRequest(x.X.Type()) {
			mark(x, taintRequest) // r.URL, r.Body, r.Header, r.Form, ...
		}
	case *ssa.Field:
		if isHTTPRequest(x.X.Type()) {
			mark(x, taintRequest)
		}
	}
	if isValue {
		mark(value, ssaOperandTaint(instr, m))
	}
	return changed
}

type ssaSink struct {
	pkg      string
	names    []string
	param    string // parameter name in the callee's signature
	rule     string
	title    string
	desc     string
	category string
	cwe      string
	severity api.Severity
}

var ssaSinks = []ssaSink{
	{pkg: "database/sql", names: []string{"Query", "QueryContext", "QueryRow", "QueryRowContext", "Exec", "ExecContext", "Prepare", "PrepareContext"},
		param: "query", rule: "go-ssa-sql-tainted", title: "User input in SQL query",
		desc: "Request data reaches the SQL text; bind it as a query parameter instead.", category: "sqli", cwe: "CWE-89", severity: api.SeverityCritical},
	{pkg: "os", names: []string{"Open", "OpenFile", "ReadFile", "WriteFile", "Create", "Remove", "RemoveAll", "ReadDir", "Mkdir", "MkdirAll"},
		param: "name", rule: "go-ssa-path-tainted", title: "User input in file path",
		desc: "Request data reaches a filesystem path; use os.Root, filepath.IsLocal, or filepath.Base on the input.", category: "path-traversal", cwe: "CWE-22", severity: api.SeverityHigh},
	{pkg: "os", names: []string{"RemoveAll"}, param: "path", rule: "go-ssa-path-tainted", title: "User input in file path",
		desc: "Request data reaches a filesystem path; use os.Root, filepath.IsLocal, or filepath.Base on the input.", category: "path-traversal", cwe: "CWE-22", severity: api.SeverityHigh},
	{pkg: "net/http", names: []string{"ServeFile"}, param: "name", rule: "go-ssa-path-tainted", title: "User input in file path",
		desc: "Request data reaches http.ServeFile; serve from an http.Dir / os.Root instead.", category: "path-traversal", cwe: "CWE-22", severity: api.SeverityHigh},
	{pkg: "net/http", names: []string{"Get", "Head", "Post", "PostForm", "NewRequest", "NewRequestWithContext"},
		param: "url", rule: "go-ssa-ssrf-tainted", title: "User input in outbound request URL",
		desc: "Request data chooses the URL of a server-side request; allowlist hosts before fetching.", category: "ssrf", cwe: "CWE-918", severity: api.SeverityHigh},
}

// matchSSASink returns the sink a static call hits and the argument to check.
func matchSSASink(call *ssa.CallCommon) (*ssaSink, ssa.Value) {
	fn := call.StaticCallee()
	if fn == nil || fn.Pkg == nil || fn.Pkg.Pkg == nil {
		return nil, nil
	}
	for i := range ssaSinks {
		sink := &ssaSinks[i]
		if fn.Pkg.Pkg.Path() != sink.pkg || !slices.Contains(sink.names, fn.Name()) {
			continue
		}
		params := fn.Signature.Params()
		for p := 0; p < params.Len(); p++ {
			if params.At(p).Name() != sink.param {
				continue
			}
			if fn.Signature.Recv() != nil {
				p++ // static method calls pass the receiver as Args[0]
			}
			if p < len(call.Args) {
				return sink, call.Args[p]
			}
		}
	}
	return nil, nil
}

// ssaSource reports the taint a call's result carries when it reads untrusted input.
func ssaSource(call *ssa.CallCommon) taint {
	var pkg, name, recv string
	var method bool
	if call.IsInvoke() { // interface method, e.g. echo.Context
		if call.Method.Pkg() == nil {
			return 0
		}
		pkg, name, method = call.Method.Pkg().Path(), call.Method.Name(), true
	} else if fn := call.StaticCallee(); fn != nil && fn.Pkg != nil && fn.Pkg.Pkg != nil {
		pkg, name, method = fn.Pkg.Pkg.Path(), fn.Name(), fn.Signature.Recv() != nil
		if method {
			recv = typeName(fn.Signature.Recv().Type())
		}
	} else {
		return 0
	}
	switch {
	case pkg == "os" && (name == "Getenv" || name == "LookupEnv"):
		return taintEnv
	case pkg == "net/http" && (recv == "Request" || recv == "Header") && slices.Contains([]string{"FormValue", "PostFormValue", "PathValue", "Cookie", "Cookies", "Get", "Values", "UserAgent", "Referer"}, name):
		return taintRequest
	case pkg == "net/url" && method && (name == "Get" || name == "Query"):
		return taintRequest
	case strings.HasPrefix(pkg, "github.com/gin-gonic/gin") && method && slices.Contains([]string{"Query", "DefaultQuery", "GetQuery", "QueryArray", "QueryMap", "Param", "PostForm", "DefaultPostForm", "GetPostForm", "PostFormArray", "GetHeader", "Cookie", "GetRawData"}, name):
		return taintRequest
	case strings.HasPrefix(pkg, "github.com/labstack/echo") && method && slices.Contains([]string{"QueryParam", "QueryParams", "QueryString", "Param", "ParamValues", "FormValue", "FormParams", "Cookie"}, name):
		return taintRequest
	case strings.HasPrefix(pkg, "github.com/go-chi/chi") && (name == "URLParam" || name == "URLParamFromCtx"):
		return taintRequest
	case strings.HasPrefix(pkg, "github.com/gorilla/mux") && name == "Vars":
		return taintRequest
	}
	return 0
}

// isSSASanitizer: results of these calls are safe to use in sinks.
func isSSASanitizer(fn *ssa.Function) bool {
	if fn == nil || fn.Pkg == nil || fn.Pkg.Pkg == nil {
		return false
	}
	pkg, name := fn.Pkg.Pkg.Path(), fn.Name()
	return pkg == "strconv" && (name == "Atoi" || strings.HasPrefix(name, "Parse")) ||
		(pkg == "path/filepath" || pkg == "path") && name == "Base"
}

func isHTTPRequest(t types.Type) bool {
	if p, ok := t.Underlying().(*types.Pointer); ok {
		t = p.Elem()
	}
	named, ok := types.Unalias(t).(*types.Named)
	return ok && named.Obj().Pkg() != nil && named.Obj().Pkg().Path() == "net/http" && named.Obj().Name() == "Request"
}

// typeName returns the name of a (pointer to a) named type, or "".
func typeName(t types.Type) string {
	if p, ok := t.Underlying().(*types.Pointer); ok {
		t = p.Elem()
	}
	if named, ok := types.Unalias(t).(*types.Named); ok {
		return named.Obj().Name()
	}
	return ""
}

func goPackagePattern(base string) (root, pattern string, ok bool) {
	dir := base
	if info, err := os.Stat(dir); err == nil && !info.IsDir() {
		dir = filepath.Dir(dir)
	}
	dir, err := filepath.Abs(dir)
	if err != nil {
		return "", "", false
	}
	for root = dir; ; root = filepath.Dir(root) {
		if _, err := os.Stat(filepath.Join(root, "go.mod")); err == nil {
			rel, err := filepath.Rel(root, dir)
			if err != nil {
				return "", "", false
			}
			if rel == "." {
				return root, "./...", true
			}
			return root, "./" + filepath.ToSlash(rel) + "/...", true
		}
		parent := filepath.Dir(root)
		if parent == root {
			return "", "", false
		}
	}
}

func relativePath(base, file string) string {
	baseDir := base
	if info, err := os.Stat(baseDir); err == nil && !info.IsDir() {
		baseDir = filepath.Dir(baseDir)
	}
	baseDir, _ = filepath.Abs(baseDir)
	file, _ = filepath.Abs(file)
	rel, err := filepath.Rel(baseDir, file)
	if err == nil {
		return rel
	}
	return file
}

func ssaCall(instr ssa.Instruction) *ssa.CallCommon {
	switch call := instr.(type) {
	case *ssa.Call:
		return call.Common()
	case *ssa.Go:
		return call.Common()
	case *ssa.Defer:
		return call.Common()
	default:
		return nil
	}
}

func isSSAShellCall(call *ssa.CallCommon) bool {
	fn := call.StaticCallee()
	if fn == nil || fn.Pkg == nil || fn.Pkg.Pkg == nil || fn.Pkg.Pkg.Path() != "os/exec" {
		return false
	}
	return fn.Name() == "Command" || fn.Name() == "CommandContext"
}

func ssaShellInputTainted(call *ssa.CallCommon, tainted map[ssa.Value]taint) bool {
	exeArg := 0
	if call.StaticCallee().Name() == "CommandContext" {
		exeArg = 1
	}
	if len(call.Args) <= exeArg+1 {
		return false
	}
	shell, ok := ssaString(call.Args[exeArg])
	if !ok {
		return false
	}
	shell = filepath.Base(shell)
	if shell != "sh" && shell != "bash" && shell != "dash" && shell != "zsh" && shell != "cmd" && shell != "cmd.exe" {
		return false
	}
	args := call.Args[exeArg+1:]
	for i := 0; i+1 < len(args); i++ {
		if flag, ok := ssaString(args[i]); ok && flag == "-c" && tainted[args[i+1]] != 0 {
			return true
		}
	}
	return len(args) == 1 && tainted[args[0]] != 0
}

func ssaStorageRoot(value ssa.Value) ssa.Value {
	for {
		switch x := value.(type) {
		case *ssa.IndexAddr:
			value = x.X
		case *ssa.FieldAddr:
			value = x.X
		default:
			return value
		}
	}
}

func ssaString(value ssa.Value) (string, bool) {
	constantValue, ok := value.(*ssa.Const)
	if !ok || constantValue.Value == nil || constantValue.Value.Kind() != constant.String {
		return "", false
	}
	return constant.StringVal(constantValue.Value), true
}

func ssaUnion(values []ssa.Value, tainted map[ssa.Value]taint) taint {
	var t taint
	for _, value := range values {
		t |= tainted[value]
	}
	return t
}

func ssaOperandTaint(instr ssa.Instruction, tainted map[ssa.Value]taint) taint {
	var t taint
	for _, operand := range instr.Operands(nil) {
		if operand != nil {
			t |= tainted[*operand]
		}
	}
	return t
}

func withinDir(root, file string) bool {
	rel, err := filepath.Rel(root, file)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
