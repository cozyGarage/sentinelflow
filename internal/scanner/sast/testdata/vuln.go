package demo

import (
	"fmt"
	"net/http"
	"os/exec"
	"path/filepath"
)

func sqliConcat(request struct{ Params map[string]string }) {
	_ = "SELECT * FROM users WHERE id = " + request.Params["id"]
}

func sqliFormat(id string) {
	_ = fmt.Sprintf("SELECT * FROM users WHERE id=%s", id)
}

func pathTrav() string {
	return base + "/../etc/passwd"
}

func pathJoin(request struct{ Path string }) string {
	return filepath.Join("/data", request.Path)
}

func ssrf(request struct{ URL string }) {
	_, _ = http.Get(request.URL)
}

func cmdExec(user string) {
	_ = exec.Command("sh", "-c", "echo "+user)
}

func cmdShell(userCmd string) {
	_ = exec.Command("bash", "-c", userCmd)
}

var base = "/var/app"
