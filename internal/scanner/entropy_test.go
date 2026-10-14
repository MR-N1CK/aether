package scanner_test

import (
	"crypto/rand"
	"math"
	"testing"

	"aether/internal/config"
	"aether/internal/report"
	"aether/internal/scanner"
)

func TestShannonEntropy(t *testing.T) {
	// 1. Empty data
	if e := scanner.ShannonEntropy(nil); e != 0.0 {
		t.Fatalf("expected 0.0 for nil, got %f", e)
	}
	if e := scanner.ShannonEntropy([]byte{}); e != 0.0 {
		t.Fatalf("expected 0.0 for empty slice, got %f", e)
	}

	// 2. Uniform byte distribution (all 256 byte values equally distributed)
	uniform := make([]byte, 256)
	for i := 0; i < 256; i++ {
		uniform[i] = byte(i)
	}
	eUniform := scanner.ShannonEntropy(uniform)
	if math.Abs(eUniform-8.0) > 0.001 {
		t.Fatalf("expected entropy ~8.0 for uniform distribution, got %f", eUniform)
	}

	// 3. Constant byte distribution (zero entropy)
	constant := make([]byte, 256)
	for i := range constant {
		constant[i] = 0x41 // 'A'
	}
	eConst := scanner.ShannonEntropy(constant)
	if eConst != 0.0 {
		t.Fatalf("expected 0.0 for constant data, got %f", eConst)
	}

	// 4. Typical English ASCII text (entropy ~ 4.0 - 5.0)
	ascii := []byte("The quick brown fox jumps over the lazy dog. Linux threat hunting static DFIR analysis.")
	eASCII := scanner.ShannonEntropy(ascii)
	if eASCII < 3.5 || eASCII > 5.5 {
		t.Fatalf("expected ASCII entropy between 3.5 and 5.5, got %f", eASCII)
	}

	// 5. High-entropy random data (entropy > 7.8)
	randomData := make([]byte, 2048)
	_, _ = rand.Read(randomData)
	eRand := scanner.ShannonEntropy(randomData)
	if eRand < 7.8 {
		t.Fatalf("expected random data entropy >= 7.8, got %f", eRand)
	}
}

func TestMaxWindowEntropy(t *testing.T) {
	// 512 bytes of zeros followed by 512 bytes of random
	zeros := make([]byte, 512)
	randomData := make([]byte, 512)
	_, _ = rand.Read(randomData)

	combined := append(zeros, randomData...)
	maxE := scanner.MaxWindowEntropy(combined, 256)
	if maxE < 7.0 {
		t.Fatalf("expected max window entropy >= 7.0, got %f", maxE)
	}

	allZeros := scanner.MaxWindowEntropy(zeros, 256)
	if allZeros != 0.0 {
		t.Fatalf("expected 0.0 max window entropy for all zeros, got %f", allZeros)
	}
}

func TestWindowEntropyFraction(t *testing.T) {
	// 1024 bytes of random data -> all windows should exceed 7.0
	randomData := make([]byte, 1024)
	_, _ = rand.Read(randomData)
	frac := scanner.WindowEntropyFraction(randomData, 256, 7.0)
	if frac < 0.9 {
		t.Fatalf("expected fraction >= 0.9 for pure random data, got %f", frac)
	}

	// 1024 bytes of ASCII -> fraction exceeding 7.0 should be 0.0
	asciiData := make([]byte, 1024)
	for i := range asciiData {
		asciiData[i] = byte('a' + (i % 26))
	}
	fracASCII := scanner.WindowEntropyFraction(asciiData, 256, 7.0)
	if fracASCII != 0.0 {
		t.Fatalf("expected fraction 0.0 for ASCII data, got %f", fracASCII)
	}
}

func TestCheckHighEntropyELF(t *testing.T) {
	cfg := config.NewDefaultConfig()

	// 1. Non-ELF file -> nil
	nonELF := []byte("Not an ELF file")
	if m := scanner.CheckHighEntropyELF("/tmp/not_elf", nonELF, cfg); m != nil {
		t.Fatalf("expected nil for non-ELF, got %v", m)
	}

	// 2. Benign ELF with low/moderate entropy in /tmp
	// ELF magic \x7fELF
	benignELF := append([]byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0}, make([]byte, 1024)...)
	if m := scanner.CheckHighEntropyELF("/tmp/benign_elf", benignELF, cfg); m != nil {
		t.Fatalf("expected nil for low-entropy ELF in /tmp, got %v", m)
	}

	// 3. High-entropy ELF outside volatile directories -> nil
	packedBytes := make([]byte, 2048)
	_, _ = rand.Read(packedBytes)
	copy(packedBytes[:4], []byte{0x7f, 'E', 'L', 'F'})
	if m := scanner.CheckHighEntropyELF("/usr/bin/packed_ls", packedBytes, cfg); m != nil {
		t.Fatalf("expected nil for high-entropy ELF outside tmp/dev dirs, got %v", m)
	}

	// 4. High-entropy ELF in /tmp -> ALERT 85
	mAlert := scanner.CheckHighEntropyELF("/tmp/packed_implant", packedBytes, cfg)
	if mAlert == nil {
		t.Fatalf("expected High_Entropy_ELF_In_Tmp match for high entropy ELF in /tmp")
	}
	if mAlert.Name != "High_Entropy_ELF_In_Tmp" {
		t.Errorf("expected rule High_Entropy_ELF_In_Tmp, got %s", mAlert.Name)
	}
	if mAlert.Severity != report.SeverityAlert {
		t.Errorf("expected severity Alert, got %s", mAlert.Severity)
	}
	if mAlert.Score != 85 {
		t.Errorf("expected score 85, got %d", mAlert.Score)
	}

	// 5. High-entropy ELF in /dev/shm -> ALERT 85
	mDevShm := scanner.CheckHighEntropyELF("/dev/shm/dropper", packedBytes, cfg)
	if mDevShm == nil {
		t.Fatalf("expected match for ELF in /dev/shm")
	}
}

func TestCheckHighEntropyScript(t *testing.T) {
	cfg := config.NewDefaultConfig()

	// 1. Benign script -> nil
	benignBash := []byte("#!/bin/bash\necho 'hello world'\nls -la /tmp\nexit 0\n")
	if m := scanner.CheckHighEntropyScript("/opt/scripts/deploy.sh", benignBash, cfg); m != nil {
		t.Fatalf("expected nil for benign bash script, got %v", m)
	}

	// 2. High-entropy file with compressed extension (.gz, .zip, .png) -> skipped
	randomData := make([]byte, 2048)
	_, _ = rand.Read(randomData)
	if m := scanner.CheckHighEntropyScript("/tmp/archive.tar.gz", randomData, cfg); m != nil {
		t.Fatalf("expected nil for .tar.gz archive, got %v", m)
	}
	if m := scanner.CheckHighEntropyScript("/home/user/photo.png", randomData, cfg); m != nil {
		t.Fatalf("expected nil for .png image, got %v", m)
	}

	// 3. Script with large encrypted payload block (>30% windows >7.5) -> WARNING 60
	scriptHeader := []byte("#!/bin/bash\nPAYLOAD=\"")
	scriptFooter := []byte("\"\neval $PAYLOAD\n")
	payload := make([]byte, 2048)
	_, _ = rand.Read(payload)

	suspiciousScript := append(scriptHeader, payload...)
	suspiciousScript = append(suspiciousScript, scriptFooter...)

	mScript := scanner.CheckHighEntropyScript("/tmp/stage2.sh", suspiciousScript, cfg)
	if mScript == nil {
		t.Fatalf("expected High_Entropy_Script match for embedded shellcode script")
	}
	if mScript.Name != "High_Entropy_Script" {
		t.Errorf("expected rule High_Entropy_Script, got %s", mScript.Name)
	}
	if mScript.Severity != report.SeverityWarning {
		t.Errorf("expected severity Warning, got %s", mScript.Severity)
	}
	if mScript.Score != 60 {
		t.Errorf("expected score 60, got %d", mScript.Score)
	}
}
