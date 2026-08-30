// Package adapter provides adapters to integrate scanner implementations with the engine
package adapter

import (
	"context"

	"github.com/cozygarage/sentinelflow/internal/config"
	"github.com/cozygarage/sentinelflow/internal/scanner/container"
	"github.com/cozygarage/sentinelflow/internal/scanner/dependencies"
	"github.com/cozygarage/sentinelflow/internal/scanner/iac"
	"github.com/cozygarage/sentinelflow/internal/scanner/license"
	"github.com/cozygarage/sentinelflow/internal/scanner/policy"
	"github.com/cozygarage/sentinelflow/internal/scanner/sast"
	"github.com/cozygarage/sentinelflow/internal/scanner/secrets"
	"github.com/cozygarage/sentinelflow/internal/scanner/types"
)

// ScannerResult is the standard result type
type ScannerResult = types.ScannerResult

// Scanner defines the interface for all security scanners
type Scanner interface {
	Name() string
	Supports(path string) bool
	Scan(ctx context.Context, path string, opts interface{}) (*ScannerResult, error)
}

// SecretsAdapter wraps the secrets scanner
type SecretsAdapter struct {
	scanner *secrets.Scanner
}

// NewSecretsAdapter creates a new secrets scanner adapter
func NewSecretsAdapter(cfg *config.Config) *SecretsAdapter {
	return &SecretsAdapter{scanner: secrets.NewScanner(cfg)}
}

func (a *SecretsAdapter) Name() string             { return a.scanner.Name() }
func (a *SecretsAdapter) Supports(path string) bool { return a.scanner.Supports(path) }
func (a *SecretsAdapter) Scan(ctx context.Context, path string, opts interface{}) (*ScannerResult, error) {
	return a.scanner.Scan(ctx, path, opts)
}

// IaCAdapter wraps the IaC scanner
type IaCAdapter struct {
	scanner *iac.Scanner
}

// NewIaCAdapter creates a new IaC scanner adapter
func NewIaCAdapter(cfg *config.Config) *IaCAdapter {
	return &IaCAdapter{scanner: iac.NewScanner(cfg)}
}

func (a *IaCAdapter) Name() string             { return a.scanner.Name() }
func (a *IaCAdapter) Supports(path string) bool { return a.scanner.Supports(path) }
func (a *IaCAdapter) Scan(ctx context.Context, path string, opts interface{}) (*ScannerResult, error) {
	return a.scanner.Scan(ctx, path, opts)
}

// DependenciesAdapter wraps the dependencies scanner
type DependenciesAdapter struct {
	scanner *dependencies.Scanner
}

// NewDependenciesAdapter creates a new dependencies scanner adapter
func NewDependenciesAdapter(cfg *config.Config) *DependenciesAdapter {
	return &DependenciesAdapter{scanner: dependencies.NewScanner(cfg)}
}

func (a *DependenciesAdapter) Name() string             { return a.scanner.Name() }
func (a *DependenciesAdapter) Supports(path string) bool { return a.scanner.Supports(path) }
func (a *DependenciesAdapter) Scan(ctx context.Context, path string, opts interface{}) (*ScannerResult, error) {
	return a.scanner.Scan(ctx, path, opts)
}

// PolicyAdapter wraps the policy scanner
type PolicyAdapter struct {
	scanner *policy.Scanner
}

// NewPolicyAdapter creates a new policy scanner adapter
func NewPolicyAdapter(cfg *config.Config) *PolicyAdapter {
	return &PolicyAdapter{scanner: policy.NewScanner(cfg)}
}

func (a *PolicyAdapter) Name() string             { return a.scanner.Name() }
func (a *PolicyAdapter) Supports(path string) bool { return a.scanner.Supports(path) }
func (a *PolicyAdapter) Scan(ctx context.Context, path string, opts interface{}) (*ScannerResult, error) {
	return a.scanner.Scan(ctx, path, opts)
}

// SASTAdapter wraps the SAST scanner
type SASTAdapter struct {
	scanner *sast.Scanner
}

func NewSASTAdapter(cfg *config.Config) *SASTAdapter {
	return &SASTAdapter{scanner: sast.NewScanner(cfg)}
}

func (a *SASTAdapter) Name() string             { return a.scanner.Name() }
func (a *SASTAdapter) Supports(path string) bool { return a.scanner.Supports(path) }
func (a *SASTAdapter) Scan(ctx context.Context, path string, opts interface{}) (*ScannerResult, error) {
	return a.scanner.Scan(ctx, path, opts)
}

// ContainerAdapter wraps the container scanner
type ContainerAdapter struct {
	scanner *container.Scanner
}

func NewContainerAdapter(cfg *config.Config) *ContainerAdapter {
	return &ContainerAdapter{scanner: container.NewScanner(cfg)}
}

func (a *ContainerAdapter) Name() string             { return a.scanner.Name() }
func (a *ContainerAdapter) Supports(path string) bool { return a.scanner.Supports(path) }
func (a *ContainerAdapter) Scan(ctx context.Context, path string, opts interface{}) (*ScannerResult, error) {
	return a.scanner.Scan(ctx, path, opts)
}

// LicenseAdapter wraps the license scanner
type LicenseAdapter struct {
	scanner *license.Scanner
}

func NewLicenseAdapter(cfg *config.Config) *LicenseAdapter {
	return &LicenseAdapter{scanner: license.NewScanner(cfg)}
}

func (a *LicenseAdapter) Name() string             { return a.scanner.Name() }
func (a *LicenseAdapter) Supports(path string) bool { return a.scanner.Supports(path) }
func (a *LicenseAdapter) Scan(ctx context.Context, path string, opts interface{}) (*ScannerResult, error) {
	return a.scanner.Scan(ctx, path, opts)
}
