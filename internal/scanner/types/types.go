// Package types provides shared scanner contracts used by the engine and scanners.
package types

import (
	"context"
	"os"
	"sync"

	"github.com/cozygarage/sentinelflow/pkg/api"
)

// ScanOptions contains options for a scan operation.
type ScanOptions struct {
	Files       []string
	Concurrency int
}

// ScannerResult is the standard result type returned by scanners.
type ScannerResult struct {
	Findings   []api.Finding
	FilesCount int
	Warnings   []string
}

// AsScanOptions extracts ScanOptions from the opaque opts value.
func AsScanOptions(opts interface{}) (ScanOptions, bool) {
	switch o := opts.(type) {
	case ScanOptions:
		return o, true
	case *ScanOptions:
		if o != nil {
			return *o, true
		}
	}
	return ScanOptions{}, false
}

// ResolveFiles returns a pre-collected file list when available, otherwise falls back.
func ResolveFiles(path string, opts interface{}, fallback func(string) ([]string, error)) ([]string, error) {
	if so, ok := AsScanOptions(opts); ok && len(so.Files) > 0 {
		info, err := os.Stat(path)
		if err == nil && info.IsDir() {
			return so.Files, nil
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return []string{path}, nil
	}
	return fallback(path)
}

// EffectiveConcurrency picks scanner-specific, global, then default concurrency.
func EffectiveConcurrency(opts interface{}, scannerSpecific, fallback int) int {
	if so, ok := AsScanOptions(opts); ok && so.Concurrency > 0 {
		if scannerSpecific > 0 {
			return scannerSpecific
		}
		return so.Concurrency
	}
	if scannerSpecific > 0 {
		return scannerSpecific
	}
	if fallback > 0 {
		return fallback
	}
	return 4
}

// RunWorkers processes items with a fixed-size worker pool.
func RunWorkers(ctx context.Context, concurrency int, items []string, fn func(string)) {
	if concurrency <= 0 {
		concurrency = 4
	}
	if len(items) == 0 {
		return
	}
	if concurrency > len(items) {
		concurrency = len(items)
	}

	jobs := make(chan string)
	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
					fn(item)
				}
			}
		}()
	}

sendLoop:
	for _, item := range items {
		select {
		case <-ctx.Done():
			break sendLoop
		case jobs <- item:
		}
	}
	close(jobs)
	wg.Wait()
}
