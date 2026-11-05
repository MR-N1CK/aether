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

// IsCompiledIn reports whether the YARA-X compiled engine is built into this binary.
func IsCompiledIn() bool {
	return true
}

// ValidateRulesDir compiles all *.yar and *.yara files in dir and returns validation results.
func ValidateRulesDir(dir string) (*ValidationResult, error) {
	return YaraXValidateRulesDir(dir)
}

// SignatureEngineKind identifies which signature backend this binary runs.
func SignatureEngineKind() string {
	return "yara-x"
}
