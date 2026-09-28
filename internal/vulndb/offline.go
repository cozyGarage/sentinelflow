package vulndb

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const osvBucket = "https://osv-vulnerabilities.storage.googleapis.com"

// UpdateOffline downloads an OSV ecosystem zip into the local cache directory.
func UpdateOffline(ctx context.Context, ecosystem string) (string, error) {
	eco := strings.TrimSpace(ecosystem)
	if eco == "" {
		eco = "Go"
	}
	dir := filepath.Join(DefaultCacheDir(), "offline", eco)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", err
	}
	url := osvBucket + "/" + eco + "/all.zip"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download %s: status %d", url, resp.StatusCode)
	}
	tmp, err := os.CreateTemp(dir, "osv-*.zip")
	if err != nil {
		return "", err
	}
	if _, err := io.Copy(tmp, resp.Body); err != nil {
		tmp.Close()
		return "", err
	}
	name := tmp.Name()
	tmp.Close()
	defer os.Remove(name)

	zr, err := zip.OpenReader(name)
	if err != nil {
		return "", err
	}
	defer zr.Close()
	for _, zf := range zr.File {
		if zf.FileInfo().IsDir() {
			continue
		}
		if err := extractZipMember(dir, zf); err != nil {
			return "", err
		}
	}
	return dir, nil
}

func extractZipMember(dir string, zf *zip.File) error {
	name := filepath.ToSlash(zf.Name)
	if strings.Contains(name, "..") {
		return fmt.Errorf("refusing path %s", zf.Name)
	}
	dest := filepath.Join(dir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
		return err
	}
	rc, err := zf.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, rc)
	return err
}
