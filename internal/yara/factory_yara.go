//go:build yara

package yara

import (
	"log/slog"

	"aether/internal/config"
)

// New initializes the YARA-X engine when compiled with the yara build tag.
func New(cfg *config.Config, logger *slog.Logger, devRpath bool) Engine {
	return NewYaraXEngine(cfg, logger, devRpath)
}

// VersionInfo returns the compiled YARA-X runtime version and rules status.
func VersionInfo() string {
	return YaraXVersionInfo()
}
