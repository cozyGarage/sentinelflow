package iac

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/cozygarage/sentinelflow/internal/config"
)

func writeTemp(t *testing.T, root, rel, content string) string {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return p
}

func rules(t *testing.T, root string) map[string]int {
	t.Helper()
	res, err := NewScanner(config.Default()).Scan(context.Background(), root, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int{}
	for _, f := range res.Findings {
		got[f.RuleID+"@"+filepath.ToSlash(f.Location.File)+":"+strconv.Itoa(f.Location.StartLine)]++
	}
	return got
}

func keys(m map[string]int) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestWorkflowRules(t *testing.T) {
	root := t.TempDir()
	writeTemp(t, root, ".github/workflows/bad.yml", `on:
  pull_request_target:
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: some/action@main
      - uses: some/pinned@0123456789abcdef0123456789abcdef01234567
      - uses: ./local
      - run: echo "${{ github.event.pull_request.title }}"
      - run: echo "${{ github.sha }}"
`)
	writeTemp(t, root, ".github/workflows/good.yml", `on: [push]
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567
      - env:
          TITLE: ${{ github.event.pull_request.title }}
        run: echo "$TITLE"
`)

	got := rules(t, root)
	want := []string{
		"gha-permissions-write-all@.github/workflows/bad.yml:3",
		"gha-pwn-request@.github/workflows/bad.yml:10",
		"gha-script-injection@.github/workflows/bad.yml:14",
		"gha-unpinned-action@.github/workflows/bad.yml:11",
		// actions/checkout@v4 (line 8) is low severity: below the default iac.severity of medium.
	}
	if strings.Join(keys(got), "\n") != strings.Join(want, "\n") {
		t.Fatalf("got:\n%s\nwant:\n%s", strings.Join(keys(got), "\n"), strings.Join(want, "\n"))
	}
}

func TestComposeRules(t *testing.T) {
	root := t.TempDir()
	writeTemp(t, root, "docker-compose.yml", `services:
  bad:
    image: x
    privileged: true
    network_mode: host
    cap_add: [SYS_ADMIN, NET_BIND_SERVICE]
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - type: bind
        source: /var/run/docker.sock
        target: /sock
  good:
    image: y
    volumes:
      - ./data:/data
`)
	got := rules(t, root)
	want := []string{
		"compose-dangerous-capability@docker-compose.yml:6",
		"compose-docker-socket@docker-compose.yml:8",
		"compose-docker-socket@docker-compose.yml:9",
		"compose-host-network@docker-compose.yml:5",
		"compose-privileged@docker-compose.yml:4",
	}
	if strings.Join(keys(got), "\n") != strings.Join(want, "\n") {
		t.Fatalf("got:\n%s\nwant:\n%s", strings.Join(keys(got), "\n"), strings.Join(want, "\n"))
	}
}

func TestWorkflowMissingPermissionsOnlyWhenAJobHasNone(t *testing.T) {
	root := t.TempDir()
	writeTemp(t, root, ".github/workflows/jobs-scoped.yml", "on: push\njobs:\n  a:\n    permissions:\n      contents: read\n    runs-on: x\n")
	writeTemp(t, root, ".github/workflows/open.yml", "on: push\njobs:\n  a:\n    runs-on: x\n")
	cfg := config.Default()
	cfg.Scanners.IaC.Severity = "low"
	res, err := NewScanner(cfg).Scan(context.Background(), root, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 || res.Findings[0].RuleID != "gha-permissions-missing" ||
		filepath.ToSlash(res.Findings[0].Location.File) != ".github/workflows/open.yml" || res.Findings[0].Location.StartLine != 3 {
		t.Fatalf("want one missing-permissions finding on open.yml:3, got %+v", res.Findings)
	}
}
