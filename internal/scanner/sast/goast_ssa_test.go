package sast

import (
	"context"
	"testing"

	"github.com/cozygarage/sentinelflow/internal/config"
)

func TestSSATaintSinksAcrossFiles(t *testing.T) {
	tmpDir := t.TempDir()
	writeGoModule(t, tmpDir)
	writeScanFile(t, tmpDir, "handler.go", `
package main

import (
	"database/sql"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
)

var db *sql.DB

func handler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	db.Query(buildQuery(id))                      // tainted across files: finding
	db.Query("SELECT * FROM t WHERE id = ?", id)  // parameterized: safe
	n, _ := strconv.Atoi(id)
	db.Query(buildQuery(strconv.Itoa(n)))         // sanitized by Atoi: safe

	os.ReadFile(filepath.Join("/data", r.PathValue("f")))   // finding
	os.ReadFile(filepath.Join("/data", filepath.Base(r.PathValue("f")))) // sanitized: safe
	os.Open(r.URL.Path)                                      // request field: finding

	http.Get(r.FormValue("url"))    // SSRF: finding
	http.Get(os.Getenv("UPSTREAM")) // operator config, not attacker input: safe
}
`)
	writeScanFile(t, tmpDir, "query.go", `
package main

func buildQuery(id string) string {
	return "SELECT * FROM t WHERE id = " + id
}
`)

	result, err := NewScanner(config.Default()).Scan(context.Background(), tmpDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := findingRules(result)
	// The Itoa line keeps its syntactic go-ast-sql-nonconst; the tainted line's is replaced.
	want := map[string]int{"go-ssa-sql-tainted": 1, "go-ast-sql-nonconst": 1, "go-ssa-path-tainted": 2, "go-ssa-ssrf-tainted": 1}
	for rule, n := range want {
		if got[rule] != n {
			t.Errorf("%s: got %d, want %d (all: %v)", rule, got[rule], n, got)
		}
	}
}

func TestSSAEnvStillTaintsShell(t *testing.T) {
	tmpDir := t.TempDir()
	writeGoModule(t, tmpDir)
	writeScanFile(t, tmpDir, "main.go", `
package main

import (
	"os"
	"os/exec"
)

func main() {
	exec.Command("sh", "-c", os.Getenv("CMD"))
}
`)
	result, err := NewScanner(config.Default()).Scan(context.Background(), tmpDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if findingRules(result)["go-ast-shell-tainted"] != 1 {
		t.Fatalf("env -> shell must still be reported: %+v", result.Findings)
	}
}
