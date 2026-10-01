//go:build !yara

package yara

import (
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
	return "not compiled in"
}
