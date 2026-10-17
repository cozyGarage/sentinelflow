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
)

const maxGoGraphOutputBytes = 16 << 20
const maxGoGraphDiagnosticBytes = 4 << 10

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

func (g *GoModScanner) resolveGraph(ctx context.Context, goModPath string, declared []Dependency) ([]Dependency, error) {
	binary := g.goCommand
	if binary == "" {
		binary = "go"
	}
	stdout, stderr := &cappedBuffer{limit: maxGoGraphOutputBytes}, &cappedBuffer{limit: maxGoGraphOutputBytes}
	cmd := exec.CommandContext(ctx, binary, "list", "-m", "-json", "-mod=readonly", "all")
	cmd.Dir = filepath.Dir(goModPath)
	cmd.Env = goGraphEnvironment(os.Environ(), g.AllowNetwork)
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

	declaredByPath := make(map[string]Dependency, len(declared))
	for _, dep := range declared {
		declaredByPath[dep.Name] = dep
	}
	decoder := json.NewDecoder(bytes.NewReader(stdout.Bytes()))
	resolved := make([]Dependency, 0, len(declared))
	mainCount := 0
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
			mainCount++
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
		if original, ok := declaredByPath[module.Path]; ok {
			dep.Line = original.Line
			dep.Dev = original.Dev
		}
		resolved = append(resolved, dep)
	}
	if mainCount != 1 {
		return nil, fmt.Errorf("resolve Go module graph: expected one main module, got %d", mainCount)
	}
	sort.Slice(resolved, func(i, j int) bool { return resolved[i].Name < resolved[j].Name })
	return resolved, nil
}

func goGraphEnvironment(env []string, allowNetwork bool) []string {
	values := map[string]string{"GOTOOLCHAIN": "local", "GOWORK": "off", "GOFLAGS": ""}
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
