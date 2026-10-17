package dependencies

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/mod/modfile"
)

const maxGoGraphOutputBytes = 16 << 20
const maxGoGraphDiagnosticBytes = 4 << 10

func findGoWorkspace(moduleDir string) (string, bool, error) {
	current, err := filepath.Abs(moduleDir)
	if err != nil {
		return "", false, err
	}
	for {
		candidate := filepath.Join(current, "go.work")
		info, err := os.Stat(candidate)
		if err == nil {
			if info.IsDir() {
				return "", false, fmt.Errorf("%s is a directory", candidate)
			}
			return candidate, true, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", false, err
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", false, nil
		}
		current = parent
	}
}

func goWorkspaceIncludes(workspacePath, moduleDir string) (bool, error) {
	content, err := os.ReadFile(workspacePath)
	if err != nil {
		return false, err
	}
	work, err := modfile.ParseWork(workspacePath, content, nil)
	if err != nil {
		return false, err
	}
	workspaceDir := filepath.Dir(workspacePath)
	moduleAbs, err := filepath.Abs(moduleDir)
	if err != nil {
		return false, err
	}
	for _, use := range work.Use {
		memberDir := use.Path
		if !filepath.IsAbs(memberDir) {
			memberDir = filepath.Join(workspaceDir, memberDir)
		}
		memberDir, err = filepath.Abs(filepath.Clean(memberDir))
		if err != nil {
			return false, err
		}
		if filepath.Clean(memberDir) == filepath.Clean(moduleAbs) {
			return true, nil
		}
	}
	return false, nil
}

func (g *GoModScanner) scanWorkspace(ctx context.Context, currentGoMod string) ([]Dependency, error) {
	content, err := os.ReadFile(g.WorkspacePath)
	if err != nil {
		return nil, fmt.Errorf("read go.work: %w", err)
	}
	work, err := modfile.ParseWork(g.WorkspacePath, content, nil)
	if err != nil {
		return nil, fmt.Errorf("parse go.work: %w", err)
	}
	for _, replace := range work.Replace {
		if replace.New.Path == "" || replace.New.Version == "" {
			return nil, fmt.Errorf("resolve Go workspace: replacement for %s has no versioned module identity; local workspace replacements are not yet supported (SC-017)", replace.Old.Path)
		}
	}

	workspaceDir := filepath.Dir(g.WorkspacePath)
	memberCount := 0
	mainModules := make([]string, 0, len(work.Use))
	declared := make([]Dependency, 0)
	seenDirs, seenModulePaths := map[string]bool{}, map[string]bool{}
	currentIncluded := false
	currentAbs, err := filepath.Abs(currentGoMod)
	if err != nil {
		return nil, err
	}
	for _, use := range work.Use {
		moduleDir := use.Path
		if !filepath.IsAbs(moduleDir) {
			moduleDir = filepath.Join(workspaceDir, moduleDir)
		}
		moduleDir, err = filepath.Abs(filepath.Clean(moduleDir))
		if err != nil {
			return nil, err
		}
		if seenDirs[moduleDir] {
			return nil, fmt.Errorf("parse go.work: duplicate workspace module directory %s", moduleDir)
		}
		seenDirs[moduleDir] = true
		goModPath := filepath.Join(moduleDir, "go.mod")
		modContent, err := os.ReadFile(goModPath)
		if err != nil {
			return nil, fmt.Errorf("read workspace module go.mod %s: %w", goModPath, err)
		}
		parsed, err := modfile.Parse(goModPath, modContent, nil)
		if err != nil {
			return nil, fmt.Errorf("parse workspace module go.mod %s: %w", goModPath, err)
		}
		if parsed.Module == nil || parsed.Module.Mod.Path == "" {
			return nil, fmt.Errorf("workspace module %s has no module path", goModPath)
		}
		if seenModulePaths[parsed.Module.Mod.Path] {
			return nil, fmt.Errorf("parse go.work: duplicate workspace module path %s", parsed.Module.Mod.Path)
		}
		seenModulePaths[parsed.Module.Mod.Path] = true
		mainModules = append(mainModules, parsed.Module.Mod.Path)
		if filepath.Clean(currentAbs) == filepath.Clean(goModPath) {
			currentIncluded = true
		}
		memberCount++
		for _, replace := range parsed.Replace {
			if replace.New.Path == "" || replace.New.Version == "" {
				return nil, fmt.Errorf("resolve Go workspace: module %s has local replacement for %s; local replacements are not yet supported (SC-017)", parsed.Module.Mod.Path, replace.Old.Path)
			}
		}
		for _, req := range parsed.Require {
			line := 0
			if req.Syntax != nil {
				line = req.Syntax.Start.Line
			}
			dep := Dependency{Name: req.Mod.Path, Version: req.Mod.Version, Ecosystem: "go", FilePath: goModPath, Line: line, Dev: req.Indirect, Inventory: "go_work_graph"}
			declared = append(declared, dep)
		}
	}
	if memberCount == 0 {
		return nil, fmt.Errorf("parse go.work: workspace has no use modules")
	}
	if !currentIncluded {
		return nil, fmt.Errorf("resolve Go workspace: scanning module %s which is not listed in go.work use directives", currentGoMod)
	}
	sort.Strings(mainModules)
	sort.Slice(declared, func(i, j int) bool {
		if declared[i].Name != declared[j].Name {
			return declared[i].Name < declared[j].Name
		}
		if declared[i].FilePath != declared[j].FilePath {
			return declared[i].FilePath < declared[j].FilePath
		}
		return declared[i].Line < declared[j].Line
	})
	return g.resolveGraph(ctx, currentGoMod, declared, g.WorkspacePath, mainModules)
}

type goModuleEntry struct {
	Path    string
	Version string
	Main    bool
	Replace *struct {
		Path    string
		Version string
		Dir     string
	}
}

type cappedBuffer struct {
	bytes.Buffer
	limit    int
	overflow bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	remaining := b.limit - b.Len()
	if remaining <= 0 {
		b.overflow = true
		return 0, fmt.Errorf("output exceeds %d bytes", b.limit)
	}
	if len(p) > remaining {
		_, _ = b.Buffer.Write(p[:remaining])
		b.overflow = true
		return remaining, fmt.Errorf("output exceeds %d bytes", b.limit)
	}
	return b.Buffer.Write(p)
}

func (g *GoModScanner) resolveGraph(ctx context.Context, goModPath string, declared []Dependency, workspacePath string, mainModules []string) ([]Dependency, error) {
	binary := g.goCommand
	if binary == "" {
		binary = "go"
	}
	stdout, stderr := &cappedBuffer{limit: maxGoGraphOutputBytes}, &cappedBuffer{limit: maxGoGraphOutputBytes}
	cmd := exec.CommandContext(ctx, binary, "list", "-m", "-json", "-mod=readonly", "all")
	cmd.Dir = filepath.Dir(goModPath)
	cmd.Env = goGraphEnvironment(os.Environ(), g.AllowNetwork, workspacePath)
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if err := cmd.Run(); err != nil {
		switch {
		case ctx.Err() != nil:
			return nil, fmt.Errorf("resolve Go module graph: %w", ctx.Err())
		case stdout.overflow || stderr.overflow:
			return nil, fmt.Errorf("resolve Go module graph: output exceeded %d bytes", maxGoGraphOutputBytes)
		case errors.Is(err, exec.ErrNotFound) || errors.Is(err, os.ErrNotExist):
			return nil, fmt.Errorf("resolve Go module graph: Go tool %q is unavailable", binary)
		default:
			diagnostic := strings.TrimSpace(stderr.String())
			if len(diagnostic) > maxGoGraphDiagnosticBytes {
				diagnostic = diagnostic[:maxGoGraphDiagnosticBytes] + "..."
			}
			if diagnostic != "" {
				return nil, fmt.Errorf("resolve Go module graph: %w: %s", err, diagnostic)
			}
			return nil, fmt.Errorf("resolve Go module graph: %w", err)
		}
	}

	declaredByPath := make(map[string][]Dependency, len(declared))
	for _, dep := range declared {
		declaredByPath[dep.Name] = append(declaredByPath[dep.Name], dep)
	}
	decoder := json.NewDecoder(bytes.NewReader(stdout.Bytes()))
	resolved := make([]Dependency, 0, len(declared))
	mainPaths := make(map[string]bool)
	for {
		var module goModuleEntry
		err := decoder.Decode(&module)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("decode Go module graph: %w", err)
		}
		if module.Main {
			if module.Path == "" || mainPaths[module.Path] {
				return nil, fmt.Errorf("resolve Go module graph: workspace returned an empty or duplicate main module path")
			}
			mainPaths[module.Path] = true
			continue
		}
		if module.Path == "" || module.Version == "" {
			return nil, fmt.Errorf("resolve Go module graph: returned a module without path or version")
		}
		if module.Replace != nil {
			if module.Replace.Path == "" || module.Replace.Version == "" {
				return nil, fmt.Errorf("resolve Go module graph: replacement for %s has no versioned module identity; local replacements are not yet supported (SC-017)", module.Path)
			}
		}
		dep := Dependency{
			Name: module.Path, Version: module.Version, Ecosystem: "go",
			FilePath: goModPath, Inventory: "go_list_module",
		}
		if module.Replace != nil {
			dep.AdditionalAdvisoryCoordinates = []PackageCoordinate{{
				Name: module.Replace.Path, Version: module.Replace.Version, Ecosystem: "go",
			}}
		}
		if originals := declaredByPath[module.Path]; len(originals) > 0 {
			for _, original := range originals {
				attributed := dep
				attributed.FilePath = original.FilePath
				attributed.Line = original.Line
				attributed.Dev = original.Dev
				if workspacePath != "" {
					attributed.Inventory = "go_work_graph"
				}
				resolved = append(resolved, attributed)
			}
			continue
		}
		if workspacePath != "" {
			dep.FilePath = workspacePath
			dep.Inventory = "go_work_graph"
		}
		resolved = append(resolved, dep)
	}
	wantMainPaths := make(map[string]bool, len(mainModules))
	for _, main := range mainModules {
		wantMainPaths[main] = true
	}
	if len(mainPaths) != len(wantMainPaths) {
		return nil, fmt.Errorf("resolve Go module graph: expected main modules %v, got %v", sortedKeys(wantMainPaths), sortedKeys(mainPaths))
	}
	for main := range wantMainPaths {
		if !mainPaths[main] {
			return nil, fmt.Errorf("resolve Go module graph: workspace main module %s was not returned", main)
		}
	}
	sort.Slice(resolved, func(i, j int) bool {
		if resolved[i].Name != resolved[j].Name {
			return resolved[i].Name < resolved[j].Name
		}
		if resolved[i].FilePath != resolved[j].FilePath {
			return resolved[i].FilePath < resolved[j].FilePath
		}
		return resolved[i].Line < resolved[j].Line
	})
	return resolved, nil
}

func goGraphEnvironment(env []string, allowNetwork bool, workspacePath string) []string {
	values := map[string]string{"GOTOOLCHAIN": "local", "GOWORK": "off", "GOFLAGS": ""}
	if workspacePath != "" {
		values["GOWORK"] = workspacePath
	}
	if !allowNetwork {
		values["GOPROXY"] = "off"
		values["GOSUMDB"] = "off"
	}
	filtered := make([]string, 0, len(env)+len(values))
	for _, entry := range env {
		name, _, _ := strings.Cut(entry, "=")
		if _, replaced := values[name]; !replaced {
			filtered = append(filtered, entry)
		}
	}
	for name, value := range values {
		filtered = append(filtered, name+"="+value)
	}
	return filtered
}

func sortedKeys(values map[string]bool) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
