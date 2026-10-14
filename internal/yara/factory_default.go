//go:build !yara

package yara

import (
	"errors"
	"log/slog"

	"aether/internal/config"
)

// New initializes the appropriate YARA engine. In default builds without the yara tag,
// it returns the pure Go NoopEngine.
func New(cfg *config.Config, logger *slog.Logger, devRpath bool) Engine {
	return NewNoopEngine()
}

// VersionInfo returns YARA runtime version details.
func VersionInfo() string {
	return "disabled (native heuristics only)"
}

// ValidateRulesDir returns an error indicating that YARA is not compiled in.
func ValidateRulesDir(dir string) (*ValidationResult, error) {
	return nil, errors.New("YARA engine is not compiled into this binary (compile with make build-yara-static or use -tags yara)")
}
