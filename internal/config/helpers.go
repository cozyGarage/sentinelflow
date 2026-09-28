package config

import "strings"

// EffectiveMaxFileSize returns the engine file-size cap (default 5 MiB).
func (c *Config) EffectiveMaxFileSize() int64 {
	if c == nil || c.Scanners.MaxFileSize <= 0 {
		return 5 * 1024 * 1024
	}
	return c.Scanners.MaxFileSize
}

// ExternalMode returns a normalized adapter mode (default off).
func ExternalMode(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "auto":
		return "auto"
	case "required":
		return "required"
	default:
		return "off"
	}
}
