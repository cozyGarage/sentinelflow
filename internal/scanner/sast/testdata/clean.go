// Intentionally clean — must not trigger SAST false positives.
package demo

import "fmt"

func rem(pkg, ver string) string {
	return fmt.Sprintf("Update %s to version %s", pkg, ver)
}

func shellName() string {
	return "bash"
}
