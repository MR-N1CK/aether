//go:build !yara

package yara

import (
	"log/slog"

	"aether/internal/config"
)

// New initializes the appropriate signature engine. In default builds without
// the yara tag, it returns the pure-Go FallbackEngine, which interprets the
// embedded YARA-subset rule source so default binaries retain 100% of the
// embedded signature coverage.
func New(cfg *config.Config, logger *slog.Logger, devRpath bool) Engine {
	return NewFallbackEngine(cfg, logger)
}

// VersionInfo returns the signature engine version details.
func VersionInfo() string {
	return FallbackVersion + " (embedded core rules)"
}

// IsCompiledIn reports whether the YARA-X compiled engine is built into this binary.
func IsCompiledIn() bool {
	return false
}

// SignatureEngineKind identifies which signature backend this binary runs.
func SignatureEngineKind() string {
	return "pure-go-fallback"
}

// ValidateRulesDir returns an error indicating that the YARA-X compiler is
// not available in this build (the pure-Go fallback loads simple subset rules
// via the normal rules-dir scan path instead of ad-hoc validation).
func ValidateRulesDir(dir string) (*ValidationResult, error) {
	return nil, errYaraNotCompiledIn
}

var errYaraNotCompiledIn = constError("YARA-X engine is not compiled into this binary (compile with make build-yara-static or use -tags yara)")

type constError string

func (e constError) Error() string { return string(e) }
