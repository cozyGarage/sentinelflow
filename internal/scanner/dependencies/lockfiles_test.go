package dependencies

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func depSet(deps []Dependency) string {
	var out []string
	for _, d := range deps {
		s := d.Ecosystem + ":" + d.Name + "@" + d.Version
		if d.Dev {
			s += "(dev)"
		}
		out = append(out, s)
	}
	sort.Strings(out)
	return strings.Join(out, " ")
}

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func TestParsePnpmLockVersions(t *testing.T) {
	cases := map[string]string{
		"v5": "lockfileVersion: 5.4\npackages:\n  /lodash/4.17.20:\n    dev: false\n  /@babel/core/7.0.0:\n    dev: true\n",
		"v6": "lockfileVersion: '6.0'\npackages:\n  /lodash@4.17.20:\n    dev: false\n  /@babel/core@7.0.0:\n    dev: true\n",
		"v9": "lockfileVersion: '9.0'\npackages:\n  lodash@4.17.20:\n    resolution: {integrity: x}\n  '@babel/core@7.0.0':\n    resolution: {integrity: y}\n  react-dom@18.0.0(react@18.0.0):\n    resolution: {integrity: z}\n",
	}
	want := map[string]string{
		"v5": "npm:@babel/core@7.0.0(dev) npm:lodash@4.17.20",
		"v6": "npm:@babel/core@7.0.0(dev) npm:lodash@4.17.20",
		"v9": "npm:@babel/core@7.0.0 npm:lodash@4.17.20 npm:react-dom@18.0.0",
	}
	for name, content := range cases {
		deps, err := parsePnpmLock([]byte(content), "pnpm-lock.yaml")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := depSet(deps); got != want[name] {
			t.Errorf("%s:\n got  %s\n want %s", name, got, want[name])
		}
	}
}

func TestNpmScannerFallsBackToPnpm(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "package.json", `{"dependencies":{"lodash":"^4.0.0"}}`)
	writeFile(t, dir, "pnpm-lock.yaml", "lockfileVersion: '9.0'\npackages:\n  lodash@4.17.20:\n    resolution: {integrity: x}\n")
	deps, err := (&NpmScanner{}).Scan(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := depSet(deps); got != "npm:lodash@4.17.20" {
		t.Fatalf("want exact pnpm version, got %s", got)
	}
}

func TestGradleComposerNuGet(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "gradle.lockfile", "# comment\ncom.google.guava:guava:31.1-jre=compileClasspath,runtimeClasspath\njunit:junit:4.13.2=testCompileClasspath,testRuntimeClasspath\nempty=annotationProcessor\n")
	writeFile(t, dir, "composer.lock", `{"packages":[{"name":"guzzlehttp/guzzle","version":"7.4.0"},{"name":"acme/fork","version":"dev-main"}],"packages-dev":[{"name":"phpunit/phpunit","version":"9.5.0"}]}`)
	writeFile(t, dir, "packages.lock.json", `{"version":1,"dependencies":{"net8.0":{"Newtonsoft.Json":{"type":"Direct","resolved":"13.0.1"},"MyLib":{"type":"Project"}}}}`)

	for _, tc := range []struct {
		eco  EcosystemScanner
		want string
	}{
		{&GradleScanner{}, "maven:com.google.guava:guava@31.1-jre maven:junit:junit@4.13.2(dev)"},
		{&ComposerScanner{}, "composer:guzzlehttp/guzzle@7.4.0 composer:phpunit/phpunit@9.5.0(dev)"},
		{&NuGetScanner{}, "nuget:Newtonsoft.Json@13.0.1"},
	} {
		if !tc.eco.Detect(dir) {
			t.Fatalf("%s: Detect false", tc.eco.Name())
		}
		deps, err := tc.eco.Scan(context.Background(), dir)
		if err != nil {
			t.Fatalf("%s: %v", tc.eco.Name(), err)
		}
		if got := depSet(deps); got != tc.want {
			t.Errorf("%s:\n got  %s\n want %s", tc.eco.Name(), got, tc.want)
		}
	}
}
