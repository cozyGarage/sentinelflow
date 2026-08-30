package iac

import (
	"fmt"
	"hash/fnv"
	"path/filepath"
)

// pathToken returns a short stable hash of a relative file path for finding IDs.
func pathToken(relPath string) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(filepath.ToSlash(relPath)))
	return fmt.Sprintf("%08x", h.Sum32())
}
