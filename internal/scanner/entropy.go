package scanner

import (
	"fmt"
	"math"
	"path/filepath"
	"strings"

	"aether/internal/config"
	"aether/internal/report"
)

// ShannonEntropy calculates the Shannon entropy (in bits per byte, 0.0 to 8.0) of a byte slice.
func ShannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0.0
	}

	var counts [256]int
	for _, b := range data {
		counts[b]++
	}

	total := float64(len(data))
	var entropy float64
	for _, count := range counts {
		if count > 0 {
			p := float64(count) / total
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

// MaxWindowEntropy calculates the maximum Shannon entropy across sliding windows of size windowSize.
// A step size is used for efficiency on larger buffers.
func MaxWindowEntropy(data []byte, windowSize int) float64 {
	if len(data) <= windowSize {
		return ShannonEntropy(data)
	}

	step := windowSize / 4
	if step < 1 {
		step = 1
	}

	maxEntropy := 0.0
	for i := 0; i+windowSize <= len(data); i += step {
		e := ShannonEntropy(data[i : i+windowSize])
		if e > maxEntropy {
			maxEntropy = e
			if maxEntropy >= 7.99 {
				return 8.0
			}
		}
	}

	return maxEntropy
}

// WindowEntropyFraction returns the fraction of sliding windows whose entropy exceeds the threshold.
func WindowEntropyFraction(data []byte, windowSize int, threshold float64) float64 {
	if len(data) < windowSize {
		if ShannonEntropy(data) >= threshold {
			return 1.0
		}
		return 0.0
	}

	step := windowSize / 4
	if step < 1 {
		step = 1
	}

	totalWindows := 0
	highEntropyWindows := 0

	for i := 0; i+windowSize <= len(data); i += step {
		totalWindows++
		if ShannonEntropy(data[i:i+windowSize]) >= threshold {
			highEntropyWindows++
		}
	}

	if totalWindows == 0 {
		return 0.0
	}

	return float64(highEntropyWindows) / float64(totalWindows)
}

func isUnderTempOrDev(path string, cfg *config.Config) bool {
	cleanPath := filepath.Clean(path)
	tempDirs := []string{"/tmp", "/var/tmp", "/dev/shm"}
	if cfg != nil && len(cfg.Scan.TempDirs) > 0 {
		tempDirs = cfg.Scan.TempDirs
	}

	for _, dir := range tempDirs {
		cleanDir := filepath.Clean(dir)
		if cleanPath == cleanDir || strings.HasPrefix(cleanPath, cleanDir+"/") {
			return true
		}
	}

	if strings.HasPrefix(cleanPath, "/dev/") && !strings.HasPrefix(cleanPath, "/dev/pts") {
		return true
	}

	return false
}

// CheckHighEntropyELF inspects ELF binaries in volatile directories for high entropy (packing/encryption).
func CheckHighEntropyELF(path string, data []byte, cfg *config.Config) *HeuristicMatch {
	if !IsELF(data) || len(data) < 512 {
		return nil
	}

	if !isUnderTempOrDev(path, cfg) {
		return nil
	}

	entropy := ShannonEntropy(data)
	if entropy > 7.0 {
		return &HeuristicMatch{
			Name:     "High_Entropy_ELF_In_Tmp",
			Reason:   fmt.Sprintf("Executable ELF in %s has unusually high Shannon entropy (%.2f/8.00), typical of packed, compressed, or encrypted malware", path, entropy),
			Score:    85,
			Severity: report.SeverityAlert,
		}
	}

	return nil
}

// CheckHighEntropyScript inspects non-ELF text or script files for large high-entropy embedded payloads.
func CheckHighEntropyScript(path string, data []byte, cfg *config.Config) *HeuristicMatch {
	if IsELF(data) || len(data) < 1024 {
		return nil
	}

	// Skip common compressed or media extensions which naturally have high entropy
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".gz", ".xz", ".bz2", ".zip", ".tar", ".tgz", ".zst", ".7z",
		".png", ".jpg", ".jpeg", ".gif", ".webp", ".mp3", ".mp4",
		".iso", ".img", ".deb", ".rpm", ".apk", ".jar", ".woff", ".woff2":
		return nil
	}

	// Check if more than 30% of 512-byte windows exceed entropy 7.0
	fraction := WindowEntropyFraction(data, 512, 7.0)
	if fraction >= 0.30 {
		return &HeuristicMatch{
			Name:     "High_Entropy_Script",
			Reason:   fmt.Sprintf("Script/payload file %s contains large high-entropy byte blocks (>7.0/8.00 across %.0f%% of file), characteristic of embedded shellcode or encrypted stager", path, fraction*100),
			Score:    60,
			Severity: report.SeverityWarning,
		}
	}

	return nil
}
