package corpus

import (
	"os"
	"os/exec"
)

var root = "/var/app"

func openConfig() {
	f, _ := os.Open(root + "/../etc/passwd")
	_ = f
}

func run(bin string) {
	_ = exec.Command(bin, "-h")
}
