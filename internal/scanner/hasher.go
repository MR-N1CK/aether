package scanner

import (
	"os"

	"aether/internal/hasher"
)

// FileHashes holds cryptographic hashes calculated in a single streaming pass.
type FileHashes = hasher.FileHashes

// HashStreamResult holds calculated hashes and leading header bytes for heuristic checks.
type HashStreamResult = hasher.HashStreamResult

// StreamHashAndHeader delegates to internal/hasher.StreamHashAndHeader.
func StreamHashAndHeader(f *os.File) (*HashStreamResult, error) {
	return hasher.StreamHashAndHeader(f)
}

// HashFromBytes delegates to internal/hasher.HashFromBytes.
func HashFromBytes(data []byte) *HashStreamResult {
	return hasher.HashFromBytes(data)
}
