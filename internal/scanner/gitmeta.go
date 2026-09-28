package scanner

import (
	"os"
	"os/exec"
	"strings"

	"github.com/cozygarage/sentinelflow/pkg/api"
)

func (e *Engine) collectGitMetadata(path string, meta *api.ScanMetadata) {
	if commit, err := gitOutput(path, "rev-parse", "HEAD"); err == nil {
		meta.GitCommit = strings.TrimSpace(commit)
	}
	if branch, err := gitOutput(path, "rev-parse", "--abbrev-ref", "HEAD"); err == nil {
		branch = strings.TrimSpace(branch)
		if branch != "" && branch != "HEAD" {
			meta.GitBranch = branch
		}
	}

	if meta.GitCommit == "" {
		meta.GitCommit = firstEnv("GITHUB_SHA", "CI_COMMIT_SHA", "BITBUCKET_COMMIT")
	}
	if meta.GitBranch == "" {
		meta.GitBranch = firstEnv("GITHUB_HEAD_REF", "GITHUB_REF_NAME", "CI_COMMIT_REF_NAME", "BITBUCKET_BRANCH")
		meta.GitBranch = strings.TrimPrefix(meta.GitBranch, "refs/heads/")
	}
}

func gitOutput(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func firstEnv(keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
	}
	return ""
}
