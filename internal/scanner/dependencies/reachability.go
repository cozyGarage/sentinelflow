package dependencies

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/cozygarage/sentinelflow/pkg/api"
)

// GovulncheckBin is the govulncheck executable; a variable so tests can swap it.
var GovulncheckBin = "govulncheck"

// ErrGovulncheckMissing means govulncheck is not on PATH.
var ErrGovulncheckMissing = errors.New("govulncheck not found on PATH")

// AnnotateGoReachability runs govulncheck in each Go module that has
// dependency findings and sets Reachable on them: true when the vulnerable
// symbol is called from this code, false when the module is only required or
// the package only imported. Non-Go findings are left untouched.
func AnnotateGoReachability(ctx context.Context, root string, findings []api.Finding) error {
	byDir := map[string][]int{}
	for i, f := range findings {
		if f.Scanner != "dependencies" || f.Metadata["ecosystem"] != "go" {
			continue
		}
		dir := filepath.Join(root, filepath.Dir(f.Location.File))
		byDir[dir] = append(byDir[dir], i)
	}
	if len(byDir) == 0 {
		return nil
	}
	if _, err := exec.LookPath(GovulncheckBin); err != nil {
		return ErrGovulncheckMissing
	}

	dirs := make([]string, 0, len(byDir))
	for d := range byDir {
		dirs = append(dirs, d)
	}
	sort.Strings(dirs)

	var errs []string
	for _, dir := range dirs {
		called, err := govulncheckCalled(ctx, dir)
		if err != nil {
			rel, _ := filepath.Rel(root, dir)
			errs = append(errs, fmt.Sprintf("%s: %v", filepath.ToSlash(rel), err))
			continue
		}
		for _, i := range byDir[dir] {
			reachable := called[findings[i].RuleID] || (findings[i].CVE != "" && called[findings[i].CVE])
			findings[i].Reachable = &reachable
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("govulncheck: %s", strings.Join(errs, "; "))
	}
	return nil
}

// govulncheckCalled returns the advisory IDs (GO-… plus aliases) whose
// vulnerable function is called from the module in dir.
func govulncheckCalled(ctx context.Context, dir string) (map[string]bool, error) {
	// Fixed binary name; dir is the module directory of a scanned go.mod.
	cmd := exec.CommandContext(ctx, GovulncheckBin, "-json", "-C", dir, "./...") // sentinelflow:ignore go-ast-exec-nonconst -- fixed tool binary
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	runErr := cmd.Run() // govulncheck exits non-zero when it finds vulnerabilities

	aliases := map[string][]string{}
	called := map[string]bool{}
	messages := 0
	dec := json.NewDecoder(&stdout)
	for {
		var msg struct {
			OSV *struct {
				ID      string   `json:"id"`
				Aliases []string `json:"aliases"`
			} `json:"osv"`
			Finding *struct {
				OSV   string `json:"osv"`
				Trace []struct {
					Function string `json:"function"`
				} `json:"trace"`
			} `json:"finding"`
		}
		if err := dec.Decode(&msg); err == io.EOF {
			break
		} else if err != nil {
			return nil, fmt.Errorf("parse output: %w", err)
		}
		messages++
		if msg.OSV != nil {
			aliases[msg.OSV.ID] = msg.OSV.Aliases
		}
		// Symbol-level findings name the vulnerable function; module/package-level ones do not.
		if f := msg.Finding; f != nil && len(f.Trace) > 0 && f.Trace[0].Function != "" {
			called[f.OSV] = true
		}
	}
	if messages == 0 && runErr != nil {
		return nil, fmt.Errorf("%v: %s", runErr, strings.TrimSpace(stderr.String()))
	}
	for id := range called {
		for _, a := range aliases[id] {
			called[a] = true
		}
	}
	return called, nil
}
