package safeopen

import (
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

var (
	ErrNotRegularFile = errors.New("file is not a regular file")
	ErrFileTooLarge   = errors.New("file exceeds maximum scan filesize")
	ErrPermission     = errors.New("permission denied")
	ErrVanished       = errors.New("file vanished or does not exist")
)

// ErrOversizeFile provides structured metadata when a file exceeds the maximum scan filesize.
type ErrOversizeFile struct {
	Path string
	Size int64
	Max  int64
}

func (e *ErrOversizeFile) Error() string {
	return fmt.Sprintf("file exceeds maximum scan filesize (size %d > %d) on %q", e.Size, e.Max, e.Path)
}

func (e *ErrOversizeFile) Is(target error) bool {
	return target == ErrFileTooLarge
}

// FileDescriptor holds the opened read-only file and its verified fstat metadata.
type FileDescriptor struct {
	File *os.File
	Stat unix.Stat_t
}

// Read implements io.Reader.
func (fd *FileDescriptor) Read(p []byte) (n int, err error) {
	if fd == nil || fd.File == nil {
		return 0, os.ErrInvalid
	}
	return fd.File.Read(p)
}

// Close closes the underlying file descriptor.
func (fd *FileDescriptor) Close() error {
	if fd == nil || fd.File == nil {
		return nil
	}
	return fd.File.Close()
}

// OpenRegularReadOnly opens a target file strictly in read-only mode using
// O_RDONLY|O_NOATIME|O_NONBLOCK|O_CLOEXEC (falling back to O_RDONLY|O_NONBLOCK|O_CLOEXEC
// if O_NOATIME returns EPERM).
func OpenRegularReadOnly(path string, maxFileSize int64) (*FileDescriptor, error) {
	flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NONBLOCK | unix.O_NOATIME
	fd, err := unix.Open(path, flags, 0)
	if errors.Is(err, syscall.EPERM) {
		// Non-owners or non-root users cannot use O_NOATIME; fallback without it
		flags = unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NONBLOCK
		fd, err = unix.Open(path, flags, 0)
	}
	if err != nil {
		if errors.Is(err, syscall.ENOENT) {
			return nil, fmt.Errorf("%w: %q", ErrVanished, path)
		}
		if errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) {
			return nil, fmt.Errorf("%w: %q", ErrPermission, path)
		}
		return nil, fmt.Errorf("read-only open failed for %q: %w", path, err)
	}

	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("fstat failed on %q: %w", path, err)
	}

	// Verify target is strictly a regular file
	if (stat.Mode & unix.S_IFMT) != unix.S_IFREG {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("%w (mode: 0%o) on %q", ErrNotRegularFile, stat.Mode, path)
	}

	// Verify size before reading
	if maxFileSize > 0 && stat.Size > maxFileSize {
		_ = unix.Close(fd)
		return nil, &ErrOversizeFile{
			Path: path,
			Size: stat.Size,
			Max:  maxFileSize,
		}
	}

	return &FileDescriptor{
		File: os.NewFile(uintptr(fd), path),
		Stat: stat,
	}, nil
}

// OpenReadOnly opens a target file strictly in read-only mode, guaranteeing forensic
// purity with O_NOATIME fallback.
func OpenReadOnly(path string) (*os.File, error) {
	flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOATIME
	fd, err := unix.Open(path, flags, 0)
	if errors.Is(err, syscall.EPERM) {
		flags = unix.O_RDONLY | unix.O_CLOEXEC
		fd, err = unix.Open(path, flags, 0)
	}
	if err != nil {
		return nil, fmt.Errorf("read-only open failed for %q: %w", path, err)
	}
	return os.NewFile(uintptr(fd), path), nil
}

// ReadFileReadOnly reads up to maxBytes from the given file path in strict read-only mode.
func ReadFileReadOnly(path string, maxBytes int64) ([]byte, error) {
	desc, err := OpenRegularReadOnly(path, maxBytes)
	if err != nil {
		return nil, err
	}
	defer desc.Close()

	if maxBytes > 0 {
		return io.ReadAll(io.LimitReader(desc.File, maxBytes))
	}
	return io.ReadAll(desc.File)
}
