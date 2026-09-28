// Package unpack extracts archives with zip-slip, symlink, size, and ratio guards.
package unpack

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	DefaultMaxDepth    = 3
	DefaultMaxBytes    = 1 << 30
	DefaultMinRatioDen = 100 // uncompressed <= compressed * 100
)

type Limits struct {
	MaxDepth int
	MaxBytes int64
	MaxRatio int64 // uncompressed/compressed cap; 0 = DefaultMinRatioDen
}

func (l Limits) withDefaults() Limits {
	if l.MaxDepth <= 0 {
		l.MaxDepth = DefaultMaxDepth
	}
	if l.MaxBytes <= 0 {
		l.MaxBytes = DefaultMaxBytes
	}
	if l.MaxRatio <= 0 {
		l.MaxRatio = DefaultMinRatioDen
	}
	return l
}

type File struct {
	Path    string // slash-separated path inside the archive
	Size    int64
	Data    []byte
	IsDir   bool
	Symlink string
}

type Result struct {
	Files []File
	Bytes int64
}

// Zip extracts a zip file into memory (not onto disk), enforcing limits.
func Zip(ctx context.Context, path string, limits Limits) (*Result, error) {
	limits = limits.withDefaults()
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, err
	}
	defer zr.Close()

	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	compressed := info.Size()
	if compressed <= 0 {
		compressed = 1
	}

	out := &Result{}
	for _, zf := range zr.File {
		select {
		case <-ctx.Done():
			return out, ctx.Err()
		default:
		}
		name, err := sanitize(zf.Name)
		if err != nil {
			return nil, err
		}
		if zf.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("unpack: symlink rejected: %s", name)
		}
		if strings.HasSuffix(name, "/") {
			continue
		}
		if zf.UncompressedSize64 > uint64(limits.MaxBytes) {
			return nil, fmt.Errorf("unpack: member %s exceeds max extracted bytes", name)
		}
		rc, err := zf.Open()
		if err != nil {
			return nil, err
		}
		data, err := readLimited(rc, limits.MaxBytes-out.Bytes)
		rc.Close()
		if err != nil {
			return nil, fmt.Errorf("unpack %s: %w", name, err)
		}
		out.Bytes += int64(len(data))
		if out.Bytes > limits.MaxBytes {
			return nil, fmt.Errorf("unpack: extracted size exceeds %d bytes", limits.MaxBytes)
		}
		if out.Bytes > compressed*limits.MaxRatio {
			return nil, fmt.Errorf("unpack: compression ratio too high (zip bomb?)")
		}
		out.Files = append(out.Files, File{Path: name, Size: int64(len(data)), Data: data})
	}
	return out, nil
}

// TarGz extracts a gzip-compressed tar.
func TarGz(ctx context.Context, path string, limits Limits) (*Result, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	defer gz.Close()
	return tarReader(ctx, gz, path, limits)
}

// Tar extracts an uncompressed tar.
func Tar(ctx context.Context, path string, limits Limits) (*Result, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return tarReader(ctx, f, path, limits)
}

func tarReader(ctx context.Context, r io.Reader, path string, limits Limits) (*Result, error) {
	limits = limits.withDefaults()
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	compressed := info.Size()
	if compressed <= 0 {
		compressed = 1
	}
	tr := tar.NewReader(r)
	out := &Result{}
	for {
		select {
		case <-ctx.Done():
			return out, ctx.Err()
		default:
		}
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		name, err := sanitize(hdr.Name)
		if err != nil {
			return nil, err
		}
		if hdr.Typeflag == tar.TypeSymlink || hdr.Typeflag == tar.TypeLink {
			return nil, fmt.Errorf("unpack: symlink rejected: %s", name)
		}
		if hdr.Typeflag == tar.TypeDir {
			continue
		}
		data, err := readLimited(tr, limits.MaxBytes-out.Bytes)
		if err != nil {
			return nil, fmt.Errorf("unpack %s: %w", name, err)
		}
		out.Bytes += int64(len(data))
		if out.Bytes > limits.MaxBytes {
			return nil, fmt.Errorf("unpack: extracted size exceeds %d bytes", limits.MaxBytes)
		}
		if out.Bytes > compressed*limits.MaxRatio {
			return nil, fmt.Errorf("unpack: compression ratio too high (zip bomb?)")
		}
		out.Files = append(out.Files, File{Path: name, Size: int64(len(data)), Data: data})
	}
	return out, nil
}

func sanitize(name string) (string, error) {
	name = strings.ReplaceAll(name, "\\", "/")
	name = strings.TrimPrefix(name, "./")
	if name == "" {
		return "", fmt.Errorf("unpack: empty member name")
	}
	if filepath.IsAbs(name) || strings.HasPrefix(name, "/") {
		return "", fmt.Errorf("unpack: absolute path rejected: %s", name)
	}
	clean := filepath.ToSlash(filepath.Clean(name))
	if strings.HasPrefix(clean, "../") || clean == ".." || strings.Contains(clean, "/../") {
		return "", fmt.Errorf("unpack: zip-slip rejected: %s", name)
	}
	return clean, nil
}

func readLimited(r io.Reader, remain int64) ([]byte, error) {
	if remain <= 0 {
		return nil, fmt.Errorf("size limit exceeded")
	}
	var buf []byte
	tmp := make([]byte, 32*1024)
	var n int64
	for {
		c, err := r.Read(tmp)
		if c > 0 {
			n += int64(c)
			if n > remain {
				return nil, fmt.Errorf("size limit exceeded")
			}
			buf = append(buf, tmp[:c]...)
		}
		if err == io.EOF {
			return buf, nil
		}
		if err != nil {
			return nil, err
		}
	}
}
