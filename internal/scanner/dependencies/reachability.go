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
// dependency findings. It sets Reachable=true for observed symbol call paths,
// false only for a correlated package-level observation in a completed
// symbol-level scan, and leaves unsupported or unobserved cases unknown.
// Non-Go findings are left untouched.
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
		observed, err := govulncheckCalled(ctx, dir)
		if err != nil {
			rel, _ := filepath.Rel(root, dir)
			errs = append(errs, fmt.Sprintf("%s: %v", filepath.ToSlash(rel), err))
		}
		for _, i := range byDir[dir] {
			findings[i].Reachable = nil
			module, moduleOK := findings[i].Metadata["package"].(string)
			version, versionOK := findings[i].Metadata["version"].(string)
			if !moduleOK || !versionOK || module == "" || version == "" {
				continue
			}
			state, ok := observed[reachabilityKey{advisory: findings[i].RuleID, module: module, version: version}]
			if !ok && findings[i].CVE != "" {
				state, ok = observed[reachabilityKey{advisory: findings[i].CVE, module: module, version: version}]
			}
			if ok && (err == nil || state.reachable) {
				reachable := state.reachable
				findings[i].Reachable = &reachable
			} else if err != nil {
				// A partial stream can prove a positive call path, but it cannot
				// prove that a finding was unreachable or absent.
				findings[i].Reachable = nil
			}
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("govulncheck: %s", strings.Join(errs, "; "))
	}
	return nil
}

// govulncheckCalled returns completed advisory observations scoped to the
// exact Go module path and version reported in each govulncheck trace.
type reachabilityState struct {
	reachable bool
}

type reachabilityKey struct {
	advisory string
	module   string
	version  string
}

type govulncheckReport struct {
	scanLevel  string
	configured bool
	states     map[reachabilityKey]reachabilityState
	aliases    map[string][]string
}

func govulncheckCalled(ctx context.Context, dir string) (map[reachabilityKey]reachabilityState, error) {
	// Fixed binary name; dir is the module directory of a scanned go.mod.
	cmd := exec.CommandContext(ctx, GovulncheckBin, "-json", "-C", dir, "./...") // sentinelflow:ignore go-ast-exec-nonconst -- fixed tool binary
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	runErr := cmd.Run()
	report, parseErr := decodeGovulncheck(&stdout)
	keys := make([]reachabilityKey, 0, len(report.states))
	for key := range report.states {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.advisory != b.advisory {
			return a.advisory < b.advisory
		}
		if a.module != b.module {
			return a.module < b.module
		}
		return a.version < b.version
	})
	for _, key := range keys {
		state := report.states[key]
		for _, alias := range report.aliases[key.advisory] {
			mergeReachability(report.states, reachabilityKey{advisory: alias, module: key.module, version: key.version}, state)
		}
	}
	if runErr != nil {
		runErr = fmt.Errorf("run failed: %w: %s", runErr, strings.TrimSpace(stderr.String()))
	}
	if report.scanLevel != "symbol" {
		parseErr = errors.Join(parseErr, fmt.Errorf("expected symbol-level analysis, got %q", report.scanLevel))
	}
	if err := errors.Join(runErr, parseErr); err != nil {
		return positiveReachability(report.states), err
	}
	return report.states, nil
}

// decodeGovulncheck consumes the complete JSON-lines protocol. Findings are
// observations, not a completion signal; completion is established only when
// the process succeeds and the stream reaches clean EOF after a valid config.
func decodeGovulncheck(input io.Reader) (govulncheckReport, error) {
	report := govulncheckReport{states: map[reachabilityKey]reachabilityState{}, aliases: map[string][]string{}}
	dec := json.NewDecoder(input)
	for {
		var fields map[string]json.RawMessage
		if err := dec.Decode(&fields); err == io.EOF {
			break
		} else if err != nil {
			return report, fmt.Errorf("parse output: %w", err)
		}
		if fields == nil {
			return report, errors.New("parse output: expected a JSON object")
		}
		kind, raw, err := oneGovulncheckMessage(fields)
		if err != nil {
			return report, err
		}
		if !report.configured && kind != "config" {
			return report, errors.New("invalid output: config must be the first message")
		}
		switch kind {
		case "config":
			if report.configured {
				return report, errors.New("invalid output: duplicate config message")
			}
			var config struct {
				ProtocolVersion string `json:"protocol_version"`
				ScanLevel       string `json:"scan_level"`
			}
			if err := json.Unmarshal(raw, &config); err != nil {
				return report, fmt.Errorf("parse config: %w", err)
			}
			if !strings.HasPrefix(config.ProtocolVersion, "v1.") {
				return report, fmt.Errorf("unsupported govulncheck protocol version %q", config.ProtocolVersion)
			}
			report.scanLevel = config.ScanLevel
			report.configured = true
		case "osv":
			var osv struct {
				ID      string   `json:"id"`
				Aliases []string `json:"aliases"`
			}
			if err := json.Unmarshal(raw, &osv); err != nil {
				return report, fmt.Errorf("parse osv: %w", err)
			}
			if osv.ID == "" {
				return report, errors.New("invalid output: OSV entry missing id")
			}
			report.aliases[osv.ID] = append(report.aliases[osv.ID], osv.Aliases...)
		case "finding":
			var finding struct {
				OSV   string `json:"osv"`
				Trace []struct {
					Module   string `json:"module"`
					Version  string `json:"version"`
					Package  string `json:"package"`
					Function string `json:"function"`
				} `json:"trace"`
			}
			if err := json.Unmarshal(raw, &finding); err != nil {
				return report, fmt.Errorf("parse finding: %w", err)
			}
			if finding.OSV == "" {
				return report, errors.New("invalid output: finding missing OSV id")
			}
			if len(finding.Trace) == 0 || finding.Trace[0].Module == "" || finding.Trace[0].Version == "" {
				continue
			}
			key := reachabilityKey{advisory: finding.OSV, module: finding.Trace[0].Module, version: finding.Trace[0].Version}
			if finding.Trace[0].Function != "" {
				mergeReachability(report.states, key, reachabilityState{reachable: true})
			} else if report.scanLevel == "symbol" && len(finding.Trace) == 1 && finding.Trace[0].Package != "" {
				mergeReachability(report.states, key, reachabilityState{reachable: false})
			}
		}
	}
	if !report.configured {
		return report, errors.New("invalid output: missing config message")
	}
	return report, nil
}

func oneGovulncheckMessage(fields map[string]json.RawMessage) (string, json.RawMessage, error) {
	var kind string
	var raw json.RawMessage
	for key, value := range fields {
		if len(value) == 0 || string(value) == "null" {
			continue
		}
		if kind != "" {
			return "", nil, errors.New("invalid output: message has multiple payloads")
		}
		kind, raw = key, value
	}
	switch kind {
	case "config", "osv", "finding", "progress", "SBOM":
		return kind, raw, nil
	default:
		return "", nil, fmt.Errorf("invalid output: unsupported message type %q", kind)
	}
}

func mergeReachability(states map[reachabilityKey]reachabilityState, key reachabilityKey, state reachabilityState) {
	_, exists := states[key]
	if !exists || state.reachable {
		states[key] = state
	}
}

func positiveReachability(states map[reachabilityKey]reachabilityState) map[reachabilityKey]reachabilityState {
	positive := make(map[reachabilityKey]reachabilityState, len(states))
	for key, state := range states {
		if state.reachable {
			positive[key] = state
		}
	}
	return positive
}
