package dependencies

import (
	"archive/zip"
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/cozygarage/sentinelflow/pkg/api"
)

// A govulncheck -json stream: GO-1 is called, GO-2 has a package-level
// observation but no called symbol, and GO-3 is called and aliased to a CVE.
const fakeGovulncheck = `#!/bin/sh
[ "$1" = "-json" ] && [ "$2" = "-C" ] && [ -n "$3" ] && [ "$4" = "./..." ] || exit 91
cat <<'JSON'
{"config":{"protocol_version":"v1.0.0","scan_level":"symbol"}}
{"osv":{"id":"GO-1","aliases":["CVE-1"]}}
{"osv":{"id":"GO-2"}}
{"osv":{"id":"GO-3","aliases":["CVE-3"]}}
{"finding":{"osv":"GO-1","trace":[{"module":"m","version":"v1.2.3","package":"m/p","function":"F"},{"module":"example.com/app","package":"example.com/app","function":"main"}]}}
{"finding":{"osv":"GO-2","trace":[{"module":"m","version":"v1.2.3","package":"m/p"}]}}
{"finding":{"osv":"GO-3","trace":[{"module":"m","version":"v1.2.3","package":"m/p","function":"G","receiver":"*T"}]}}
JSON
`

func TestAnnotateGoReachability(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "govulncheck")
	if err := os.WriteFile(bin, []byte(fakeGovulncheck), 0755); err != nil {
		t.Fatal(err)
	}
	old := GovulncheckBin
	GovulncheckBin = bin
	defer func() { GovulncheckBin = old }()

	goDep := func(rule, cve string) api.Finding {
		return goDependency(rule, cve)
	}
	findings := []api.Finding{
		goDep("GO-1", ""),
		goDep("GO-2", ""),
		goDep("GHSA-x", "CVE-3"), // matched through the GO-3 alias
		goDep("GO-9", ""),        // not reported by govulncheck at all
		{Scanner: "dependencies", RuleID: "GO-1", Metadata: map[string]any{"ecosystem": "npm"}},
	}
	if err := AnnotateGoReachability(context.Background(), t.TempDir(), findings); err != nil {
		t.Fatal(err)
	}
	want := []*bool{ptr(true), ptr(false), ptr(true), nil, nil}
	for i, w := range want {
		got := findings[i].Reachable
		if (got == nil) != (w == nil) || (got != nil && *got != *w) {
			t.Errorf("finding %d (%s): reachable=%v, want %v", i, findings[i].RuleID, deref(got), deref(w))
		}
	}
}

func TestSC041_GovulncheckFailureAfterFindingsRemainsUnknown(t *testing.T) {
	bin := writeFakeGovulncheck(t, fakeGovulncheck+"exit 1\n")
	old := GovulncheckBin
	GovulncheckBin = bin
	defer func() { GovulncheckBin = old }()

	findings := []api.Finding{
		goDependency("GO-1", ""),
		goDependency("GO-2", ""),
		goDependency("GO-9", ""),
	}
	if err := AnnotateGoReachability(context.Background(), t.TempDir(), findings); err == nil {
		t.Fatal("non-zero govulncheck exit in JSON mode must be an operational error")
	}
	if findings[0].Reachable == nil || !*findings[0].Reachable {
		t.Fatal("a positive symbol trace is usable even when the run later fails")
	}
	if findings[1].Reachable != nil || findings[2].Reachable != nil {
		t.Fatalf("failed run must leave negative/unmatched results unknown: %+v", findings)
	}
}

func TestSC042_GovulncheckTruncatedStreamPreservesOnlyPositiveEvidence(t *testing.T) {
	stream := `#!/bin/sh
[ "$1" = "-json" ] && [ "$2" = "-C" ] && [ -n "$3" ] && [ "$4" = "./..." ] || exit 91
cat <<'JSON'
{"config":{"protocol_version":"v1.0.0","scan_level":"symbol"}}
{"osv":{"id":"GO-1"}}
{"osv":{"id":"GO-2"}}
{"finding":{"osv":"GO-1","trace":[{"module":"m","version":"v1.2.3","package":"m/p","function":"F"}]}}
{"finding":{"osv":"GO-2","trace":[{"module":"m","version":"v1.2.3","package":"m/p"}]}}
{"finding":{"osv":"GO-3","trace":[
JSON
exit 0
`
	old := GovulncheckBin
	GovulncheckBin = writeFakeGovulncheck(t, stream)
	defer func() { GovulncheckBin = old }()
	findings := []api.Finding{goDependency("GO-1", ""), goDependency("GO-2", ""), goDependency("GO-9", "")}
	if err := AnnotateGoReachability(context.Background(), t.TempDir(), findings); err == nil {
		t.Fatal("truncated JSON must make reachability analysis fail")
	}
	if findings[0].Reachable == nil || !*findings[0].Reachable {
		t.Fatal("preserve positive evidence parsed before truncation")
	}
	if findings[1].Reachable != nil || findings[2].Reachable != nil {
		t.Fatalf("truncated stream cannot establish a negative result: %+v", findings)
	}
}

func TestSC042_CancelledGovulncheckKeepsReachabilityUnknown(t *testing.T) {
	stream := `#!/bin/sh
[ "$1" = "-json" ] && [ "$2" = "-C" ] && [ -n "$3" ] && [ "$4" = "./..." ] || exit 91
printf '%s\n' '{"config":{"protocol_version":"v1.0.0","scan_level":"symbol"}}'
exec sleep 30
`
	old := GovulncheckBin
	GovulncheckBin = writeFakeGovulncheck(t, stream)
	defer func() { GovulncheckBin = old }()
	findings := []api.Finding{goDependency("GO-9", "")}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := AnnotateGoReachability(ctx, t.TempDir(), findings); err == nil {
		t.Fatal("cancelled govulncheck must be reported as incomplete")
	}
	if findings[0].Reachable != nil {
		t.Fatalf("cancelled analysis cannot establish reachability: %+v", findings[0])
	}
}

func TestSC042_CompleteCleanStreamIsSuccessful(t *testing.T) {
	stream := `#!/bin/sh
[ "$1" = "-json" ] && [ "$2" = "-C" ] && [ -n "$3" ] && [ "$4" = "./..." ] || exit 91
printf '%s\n' '{"config":{"protocol_version":"v1.0.0","scan_level":"symbol"}}'
`
	old := GovulncheckBin
	GovulncheckBin = writeFakeGovulncheck(t, stream)
	defer func() { GovulncheckBin = old }()
	findings := []api.Finding{goDependency("GO-9", "")}
	if err := AnnotateGoReachability(context.Background(), t.TempDir(), findings); err != nil {
		t.Fatalf("valid clean JSON-mode completion should succeed: %v", err)
	}
	if findings[0].Reachable != nil {
		t.Fatalf("unmatched advisory is unknown even after a clean scan: %+v", findings[0])
	}
}

func TestSC042_EmptyFailureAndMalformedAdvisoryRemainUnknown(t *testing.T) {
	streams := []struct {
		name   string
		script string
	}{
		{name: "empty operational failure", script: "#!/bin/sh\nexit 2\n"},
		{name: "malformed advisory", script: "#!/bin/sh\nprintf '%s\\n' '{\"config\":{\"protocol_version\":\"v1.0.0\",\"scan_level\":\"symbol\"}}' '{\"osv\":{\"aliases\":[\"CVE-1\"]}}'\n"},
	}
	for _, tc := range streams {
		t.Run(tc.name, func(t *testing.T) {
			old := GovulncheckBin
			GovulncheckBin = writeFakeGovulncheck(t, tc.script)
			defer func() { GovulncheckBin = old }()
			findings := []api.Finding{goDependency("GO-1", "")}
			if err := AnnotateGoReachability(context.Background(), t.TempDir(), findings); err == nil {
				t.Fatal("incomplete or malformed stream must fail")
			}
			if findings[0].Reachable != nil {
				t.Fatalf("incomplete stream cannot set reachability: %+v", findings[0])
			}
		})
	}
}

func TestSC043_GovulncheckNegativeRequiresQualifiedPackageObservation(t *testing.T) {
	bin := writeFakeGovulncheck(t, fakeGovulncheck)
	old := GovulncheckBin
	GovulncheckBin = bin
	defer func() { GovulncheckBin = old }()
	findings := []api.Finding{goDependency("GO-2", ""), goDependency("GO-9", ""), goDependency("GHSA-x", "CVE-3")}
	wrongVersion := goDependency("GO-2", "")
	wrongVersion.Metadata["version"] = "v9.9.9"
	wrongModule := goDependency("GO-2", "")
	wrongModule.Metadata["package"] = "other.module"
	findings = append(findings, wrongVersion, wrongModule)
	if err := AnnotateGoReachability(context.Background(), t.TempDir(), findings); err != nil {
		t.Fatal(err)
	}
	if findings[0].Reachable == nil || *findings[0].Reachable {
		t.Fatalf("qualified symbol-level package observation should be false: %+v", findings[0])
	}
	if findings[1].Reachable != nil {
		t.Fatalf("unmatched advisory must remain unknown: %+v", findings[1])
	}
	if findings[2].Reachable == nil || !*findings[2].Reachable {
		t.Fatalf("qualified alias must map to its reachable advisory: %+v", findings[2])
	}
	if findings[3].Reachable != nil || findings[4].Reachable != nil {
		t.Fatalf("module/version mismatch must remain unknown: %+v", findings[3:])
	}
}

func TestSC043_NonSymbolScanCannotEstablishUnreachable(t *testing.T) {
	stream := strings.Replace(fakeGovulncheck, `"scan_level":"symbol"`, `"scan_level":"package"`, 1)
	bin := writeFakeGovulncheck(t, stream)
	old := GovulncheckBin
	GovulncheckBin = bin
	defer func() { GovulncheckBin = old }()
	findings := []api.Finding{goDependency("GO-2", "")}
	if err := AnnotateGoReachability(context.Background(), t.TempDir(), findings); err == nil {
		t.Fatal("package-level analysis cannot qualify a reachable-only negative")
	}
	if findings[0].Reachable != nil {
		t.Fatalf("unsupported scan level must leave reachability unknown: %+v", findings[0])
	}
}

// This opt-in qualification test uses the pinned upstream binary and a local,
// synthetic vulnerability database so the result is independent of live DB state.
func TestSC043_RealGovulncheckContract(t *testing.T) {
	bin := os.Getenv("SENTINELFLOW_REAL_GOVULNCHECK")
	if bin == "" {
		t.Skip("set SENTINELFLOW_REAL_GOVULNCHECK to qualify the real govulncheck binary")
	}
	if _, err := os.Stat(bin); err != nil {
		t.Fatal(err)
	}
	_, source, _, _ := runtime.Caller(0)
	fixtures := filepath.Clean(filepath.Join(filepath.Dir(source), "../../../testdata/real-govulncheck"))
	dbPath := filepath.Join(fixtures, "vulndb", "vulndb-v1")
	dbURL := (&url.URL{Scheme: "file", Path: filepath.ToSlash(dbPath)}).String()
	work := t.TempDir()
	proxyURL := makeGovulncheckProxy(t, fixtures, filepath.Join(work, "proxy"))
	moduleRoots := map[string]string{"absent": filepath.Join(fixtures, "modules", "absent")}
	moduleRoots["missing-module"] = t.TempDir()
	for _, name := range []string{"reachable", "imported"} {
		root := filepath.Join(work, name)
		if err := os.MkdirAll(root, 0755); err != nil {
			t.Fatal(err)
		}
		for _, file := range []string{"go.mod", "main.go"} {
			data, err := os.ReadFile(filepath.Join(fixtures, "modules", name, file))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, file), data, 0644); err != nil {
				t.Fatal(err)
			}
		}
		command := exec.Command("go", "mod", "download", "golang.org/vuln")
		command.Dir = root
		command.Env = append(os.Environ(), "GOPROXY="+proxyURL, "GOSUMDB=off")
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("prepare module fixture %s: %v: %s", name, err, output)
		}
		moduleRoots[name] = root
	}
	wrapper := filepath.Join(work, "govulncheck")
	script := fmt.Sprintf("#!/bin/sh\nexport GOPROXY=%q GOSUMDB=off\nexec %q -db %q \"$@\"\n", proxyURL, bin, dbURL)
	if err := os.WriteFile(wrapper, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	old := GovulncheckBin
	GovulncheckBin = wrapper
	defer func() { GovulncheckBin = old }()

	for _, tc := range []struct {
		name    string
		want    *bool
		wantErr bool
	}{
		{name: "reachable", want: ptr(true)},
		// govulncheck does not emit an observation for this symbol-only
		// advisory when the package is imported but its function is not called.
		// Absence is unknown, never an unreachable proof.
		{name: "imported-only", want: nil},
		{name: "absent", want: nil},
		{name: "missing-module", want: nil, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			findings := []api.Finding{{Scanner: "dependencies", RuleID: "GO-9999-9999", CVE: "CVE-9999-99999",
				Location: api.Location{File: "go.mod"}, Metadata: map[string]any{"ecosystem": "go", "package": "golang.org/vuln", "version": "v0.3.1"}},
			}
			root := moduleRoots[tc.name]
			err := AnnotateGoReachability(context.Background(), root, findings)
			if tc.wantErr {
				if err == nil {
					t.Fatal("real govulncheck must report a project without go.mod as an operational error")
				}
				if findings[0].Reachable != nil {
					t.Fatalf("operational failure cannot establish reachability: %+v", findings[0])
				}
				return
			}
			if err != nil {
				t.Fatalf("real govulncheck qualification failed: %v", err)
			}
			if (findings[0].Reachable == nil) != (tc.want == nil) || (findings[0].Reachable != nil && *findings[0].Reachable != *tc.want) {
				t.Fatalf("reachable=%v, want %v", deref(findings[0].Reachable), deref(tc.want))
			}
		})
	}
}

func makeGovulncheckProxy(t *testing.T, fixtures, proxy string) string {
	t.Helper()
	moduleDir := filepath.Join(fixtures, "modules", "vuln")
	moduleProxy := filepath.Join(proxy, "golang.org", "vuln", "@v")
	if err := os.MkdirAll(moduleProxy, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(moduleProxy, "list"), []byte("v0.3.1\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(moduleProxy, "v0.3.1.info"), []byte(`{"Version":"v0.3.1","Time":"2023-04-03T15:57:51Z"}`), 0644); err != nil {
		t.Fatal(err)
	}
	mod, err := os.ReadFile(filepath.Join(moduleDir, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(moduleProxy, "v0.3.1.mod"), mod, 0644); err != nil {
		t.Fatal(err)
	}
	archive, err := os.Create(filepath.Join(moduleProxy, "v0.3.1.zip"))
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(archive)
	for _, name := range []string{"go.mod", "vuln.go"} {
		data, err := os.ReadFile(filepath.Join(moduleDir, name))
		if err != nil {
			t.Fatal(err)
		}
		file, err := zw.Create("golang.org/vuln@v0.3.1/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	proxyURL := (&url.URL{Scheme: "file", Path: filepath.ToSlash(proxy)}).String()
	return strings.TrimSuffix(proxyURL, "/")
}

func goDependency(rule, cve string) api.Finding {
	return api.Finding{Scanner: "dependencies", RuleID: rule, CVE: cve,
		Location: api.Location{File: "svc/go.mod"}, Metadata: map[string]any{"ecosystem": "go", "package": "m", "version": "v1.2.3"}}
}

func writeFakeGovulncheck(t *testing.T, script string) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "govulncheck")
	if err := os.WriteFile(bin, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	return bin
}

func TestAnnotateGoReachabilityMissingBinary(t *testing.T) {
	old := GovulncheckBin
	GovulncheckBin = "definitely-not-installed-govulncheck"
	defer func() { GovulncheckBin = old }()
	f := []api.Finding{{Scanner: "dependencies", RuleID: "GO-1", Location: api.Location{File: "go.mod"}, Metadata: map[string]any{"ecosystem": "go"}}}
	if err := AnnotateGoReachability(context.Background(), t.TempDir(), f); err != ErrGovulncheckMissing {
		t.Fatalf("want ErrGovulncheckMissing, got %v", err)
	}
}

func ptr(b bool) *bool { return &b }

func deref(b *bool) any {
	if b == nil {
		return nil
	}
	return *b
}
