package scanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/cozygarage/sentinelflow/internal/config"
)

// BenchmarkEngineInitialization benchmarks scanner engine creation
func BenchmarkEngineInitialization(b *testing.B) {
	cfg := &config.Config{
		Scanners: config.ScannersConfig{
			Secrets:      config.SecretsConfig{Enabled: true},
			IaC:          config.IaCConfig{Enabled: true},
			Dependencies: config.DependenciesConfig{Enabled: true},
		},
		Policies: config.PoliciesConfig{Enabled: true},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = NewEngine(cfg)
	}
}

// BenchmarkScanSmallProject benchmarks scanning a small project (10 files)
func BenchmarkScanSmallProject(b *testing.B) {
	tmpDir := b.TempDir()

	// Create 10 test files
	for i := 0; i < 10; i++ {
		content := "package main\nfunc main() {}\n"
		os.WriteFile(filepath.Join(tmpDir, "file"+string(rune(i))+".go"), []byte(content), 0644)
	}

	cfg := &config.Config{
		Scanners: config.ScannersConfig{
			Secrets: config.SecretsConfig{Enabled: true},
		},
	}

	engine := NewEngine(cfg)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = engine.Scan(ctx, tmpDir)
	}
}

// BenchmarkScanMediumProject benchmarks scanning a medium project (100 files)
func BenchmarkScanMediumProject(b *testing.B) {
	tmpDir := b.TempDir()

	// Create 100 test files
	for i := 0; i < 100; i++ {
		content := "package main\nfunc main() {}\n"
		filename := filepath.Join(tmpDir, "file"+string(rune(i%26+97))+string(rune(i/26+97))+".go")
		os.WriteFile(filename, []byte(content), 0644)
	}

	cfg := &config.Config{
		Scanners: config.ScannersConfig{
			Secrets: config.SecretsConfig{Enabled: true},
			IaC:     config.IaCConfig{Enabled: true},
		},
	}

	engine := NewEngine(cfg)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = engine.Scan(ctx, tmpDir)
	}
}

// BenchmarkScanLargeProject benchmarks scanning a large project (1000 files)
func BenchmarkScanLargeProject(b *testing.B) {
	tmpDir := b.TempDir()

	// Create directory structure
	for dir := 0; dir < 10; dir++ {
		dirPath := filepath.Join(tmpDir, "pkg"+string(rune(dir+48)))
		os.MkdirAll(dirPath, 0755)

		for file := 0; file < 100; file++ {
			content := "package main\nfunc main() {}\n"
			filename := filepath.Join(dirPath, "file"+string(rune(file%26+97))+string(rune(file/26+97))+".go")
			os.WriteFile(filename, []byte(content), 0644)
		}
	}

	cfg := &config.Config{
		Scanners: config.ScannersConfig{
			Secrets:      config.SecretsConfig{Enabled: true},
			IaC:          config.IaCConfig{Enabled: true},
			Dependencies: config.DependenciesConfig{Enabled: true},
		},
	}

	engine := NewEngine(cfg)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = engine.Scan(ctx, tmpDir)
	}
}

// BenchmarkFileCollection benchmarks the file collection process
func BenchmarkFileCollection(b *testing.B) {
	tmpDir := b.TempDir()

	// Create 500 files
	for i := 0; i < 500; i++ {
		content := "test content"
		filename := filepath.Join(tmpDir, "file"+string(rune(i%26+97))+string(rune(i/26+97))+".txt")
		os.WriteFile(filename, []byte(content), 0644)
	}

	cfg := &config.Config{}
	engine := NewEngine(cfg)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = engine.collectFiles(context.Background(), tmpDir)
	}
}

// BenchmarkConcurrentScanning benchmarks concurrent scanner execution
func BenchmarkConcurrentScanning(b *testing.B) {
	tmpDir := b.TempDir()

	// Create test files with different types
	os.WriteFile(filepath.Join(tmpDir, "main.go"), []byte("package main"), 0644)
	os.WriteFile(filepath.Join(tmpDir, "main.tf"), []byte("resource \"aws_s3_bucket\" {}"), 0644)
	os.WriteFile(filepath.Join(tmpDir, "Dockerfile"), []byte("FROM nginx:latest"), 0644)
	os.WriteFile(filepath.Join(tmpDir, "package.json"), []byte(`{"dependencies": {}}`), 0644)

	cfg := &config.Config{
		Scanners: config.ScannersConfig{
			Secrets:      config.SecretsConfig{Enabled: true},
			IaC:          config.IaCConfig{Enabled: true},
			Dependencies: config.DependenciesConfig{Enabled: true},
		},
		Policies: config.PoliciesConfig{Enabled: true},
	}

	engine := NewEngine(cfg)
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = engine.Scan(ctx, tmpDir)
	}
}
