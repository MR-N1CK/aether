package scanner

import (
	"os"

	"aether/internal/safeopen"
)

// Re-export safeopen types and errors for backwards compatibility
type FileDescriptor = safeopen.FileDescriptor

type ErrOversizeFile = safeopen.ErrOversizeFile

var (
	ErrNotRegularFile = safeopen.ErrNotRegularFile
	ErrFileTooLarge   = safeopen.ErrFileTooLarge
	ErrPermission     = safeopen.ErrPermission
	ErrVanished       = safeopen.ErrVanished
)

func OpenRegularReadOnly(path string, maxFileSize int64) (*FileDescriptor, error) {
	return safeopen.OpenRegularReadOnly(path, maxFileSize)
}

func OpenReadOnly(path string) (*os.File, error) {
	return safeopen.OpenReadOnly(path)
}

func ReadFileReadOnly(path string, maxBytes int64) ([]byte, error) {
	return safeopen.ReadFileReadOnly(path, maxBytes)
}
