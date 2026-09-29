package sast

import (
	"context"
	"go/constant"
	"go/token"
	"os"
	"path/filepath"
	"strings"

	"github.com/cozygarage/sentinelflow/pkg/api"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

func scanGoShellTaintSSA(ctx context.Context, base string, files []string) []api.Finding {
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
	tainted := make(map[ssa.Value]bool)
	taintedReturns := make(map[*ssa.Function]bool)
	for changed := true; changed; {
		changed = false
		mark := func(value ssa.Value) {
			if value != nil && !tainted[value] {
				tainted[value] = true
				changed = true
			}
		}
		for fn := range functions {
			for _, block := range fn.Blocks {
				for _, instr := range block.Instrs {
					if call := ssaCall(instr); call != nil {
						callee := call.StaticCallee()
						if isSSATaintSource(callee) {
							if value, ok := instr.(ssa.Value); ok {
								mark(value)
							}
						}
						if functions[callee] {
							for i, arg := range call.Args {
								if i < len(callee.Params) && tainted[arg] {
									mark(callee.Params[i])
								}
							}
							if closure, ok := call.Value.(*ssa.MakeClosure); ok {
								for i, binding := range closure.Bindings {
									if i < len(callee.FreeVars) && tainted[binding] {
										mark(callee.FreeVars[i])
									}
								}
							}
							if taintedReturns[callee] {
								if value, ok := instr.(ssa.Value); ok {
									mark(value)
								}
							}
						} else if value, ok := instr.(ssa.Value); ok && anySSATainted(call.Args, tainted) {
							mark(value)
						}
					}
					if ret, ok := instr.(*ssa.Return); ok && anySSATainted(ret.Results, tainted) && !taintedReturns[fn] {
						taintedReturns[fn] = true
						changed = true
					}
					if store, ok := instr.(*ssa.Store); ok && tainted[store.Val] {
						mark(store.Addr)
						mark(ssaStorageRoot(store.Addr))
					}
					if load, ok := instr.(*ssa.UnOp); ok && load.Op == token.MUL && tainted[load.X] {
						mark(load)
					}
					if value, ok := instr.(ssa.Value); ok {
						if _, isCall := instr.(*ssa.Call); !isCall && anySSAOperandsTainted(instr, tainted) {
							mark(value)
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
				if call == nil || !isSSAShellCall(call) || !ssaShellInputTainted(call, tainted) {
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
				findings = append(findings, astFinding(rel, pos, "go-ast-shell-tainted",
					"User input passed to shell command",
					"Avoid passing request data to a shell; use a fixed executable and validated arguments.",
					"cmd-inject", api.SeverityCritical, "CWE-78"))
			}
		}
	}
	return findings
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

func isSSATaintSource(fn *ssa.Function) bool {
	if fn == nil || fn.Pkg == nil || fn.Pkg.Pkg == nil {
		return false
	}
	name, pkg := fn.Name(), fn.Pkg.Pkg.Path()
	return pkg == "os" && name == "Getenv" ||
		pkg == "net/http" && (name == "FormValue" || name == "PostFormValue" || name == "Get") ||
		pkg == "net/url" && name == "Get"
}

func isSSAShellCall(call *ssa.CallCommon) bool {
	fn := call.StaticCallee()
	if fn == nil || fn.Pkg == nil || fn.Pkg.Pkg == nil || fn.Pkg.Pkg.Path() != "os/exec" {
		return false
	}
	return fn.Name() == "Command" || fn.Name() == "CommandContext"
}

func ssaShellInputTainted(call *ssa.CallCommon, tainted map[ssa.Value]bool) bool {
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
		if flag, ok := ssaString(args[i]); ok && flag == "-c" && tainted[args[i+1]] {
			return true
		}
	}
	return len(args) == 1 && tainted[args[0]]
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

func anySSATainted(values []ssa.Value, tainted map[ssa.Value]bool) bool {
	for _, value := range values {
		if tainted[value] {
			return true
		}
	}
	return false
}

func anySSAOperandsTainted(instr ssa.Instruction, tainted map[ssa.Value]bool) bool {
	for _, operand := range instr.Operands(nil) {
		if operand != nil && tainted[*operand] {
			return true
		}
	}
	return false
}

func withinDir(root, file string) bool {
	rel, err := filepath.Rel(root, file)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
