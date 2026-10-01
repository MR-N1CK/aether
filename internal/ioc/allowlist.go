package ioc

import (
	"bufio"
	"io"
	"os"
	"strings"
)

// Allowlist maintains a set of trusted known-good SHA256 hashes.
type Allowlist struct {
	hashes map[string]string // sha256 -> description
}

// NewAllowlist creates an empty allowlist.
func NewAllowlist() *Allowlist {
	return &Allowlist{
		hashes: make(map[string]string),
	}
}

// LoadFile reads trusted hashes from a file (<sha256> # <description>).
func (a *Allowlist) LoadFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	return a.LoadReader(f)
}

// LoadReader parses an allowlist stream.
func (a *Allowlist) LoadReader(r io.Reader) error {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "#", 2)
		hashStr := strings.ToLower(strings.TrimSpace(parts[0]))
		desc := "Known-good trusted binary"
		if len(parts) > 1 {
			desc = strings.TrimSpace(parts[1])
		}

		if len(hashStr) == 64 {
			a.hashes[hashStr] = desc
		}
	}
	return scanner.Err()
}

// Contains checks if the given SHA256 hash is in the allowlist.
func (a *Allowlist) Contains(sha256Hash string) (bool, string) {
	desc, ok := a.hashes[strings.ToLower(strings.TrimSpace(sha256Hash))]
	return ok, desc
}

// Count returns the number of active allowlisted hashes.
func (a *Allowlist) Count() int {
	return len(a.hashes)
}
