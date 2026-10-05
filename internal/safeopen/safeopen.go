package safeopen

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

var (
	ErrNotRegularFile     = errors.New("file is not a regular file")
	ErrFileTooLarge       = errors.New("file exceeds maximum scan filesize")
	ErrPermission         = os.ErrPermission
	ErrVanished           = os.ErrNotExist
	ErrSymlinkEscapesRoot = errors.New("symlink target escapes root filesystem boundary")
	ErrSymlinkLoop        = errors.New("too many levels of symbolic links (symlink loop)")
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

// ResolveUnderRoot resolves any path within the specified root using chroot semantics.
// - Absolute symlink targets are re-rooted under root.
// - ".." cannot climb above root.
// - Symlink loops are detected (max 40 hops).
// - The final resolved path is guaranteed to have root as prefix.
// Returns hostPath (on current filesystem), canonical virtPath (as seen inside root), isSymlink, and error.
func ResolveUnderRoot(root, targetPath string) (hostPath string, virtPath string, isSymlink bool, err error) {
	cleanRoot := filepath.Clean(root)
	if cleanRoot == "" || cleanRoot == "." {
		cleanRoot = "/"
	}

	// Normalize targetPath to virtual path components
	cleanTarget := filepath.Clean(targetPath)
	var virtTarget string
	if cleanRoot != "/" && (cleanTarget == cleanRoot || strings.HasPrefix(cleanTarget, cleanRoot+string(filepath.Separator))) {
		rel, _ := filepath.Rel(cleanRoot, cleanTarget)
		virtTarget = "/" + strings.TrimPrefix(filepath.ToSlash(rel), "/")
	} else if filepath.IsAbs(cleanTarget) {
		virtTarget = filepath.ToSlash(cleanTarget)
	} else {
		virtTarget = "/" + strings.TrimPrefix(filepath.ToSlash(cleanTarget), "/")
	}

	segments := strings.Split(strings.TrimPrefix(virtTarget, "/"), "/")
	var curVirt []string
	remaining := segments
	hops := 0
	const maxHops = 40
	traversedSymlink := false

	for len(remaining) > 0 {
		c := remaining[0]
		remaining = remaining[1:]

		if c == "" || c == "." {
			continue
		}
		if c == ".." {
			if len(curVirt) > 0 {
				curVirt = curVirt[:len(curVirt)-1]
			}
			// Cannot climb above root
			continue
		}

		curVirt = append(curVirt, c)

		// Build intermediate host path
		var curHost string
		if cleanRoot == "/" {
			curHost = "/" + strings.Join(curVirt, "/")
		} else {
			curHost = filepath.Join(cleanRoot, filepath.Join(curVirt...))
		}

		lst, lErr := os.Lstat(curHost)
		if lErr != nil {
			if os.IsNotExist(lErr) {
				// Intermediate or leaf path does not exist
				if len(remaining) > 0 {
					for _, rem := range remaining {
						if rem == ".." {
							if len(curVirt) > 0 {
								curVirt = curVirt[:len(curVirt)-1]
							}
						} else if rem != "" && rem != "." {
							curVirt = append(curVirt, rem)
						}
					}
					remaining = nil
				}
				finalVirt := "/" + strings.Join(curVirt, "/")
				var finalHost string
				if cleanRoot == "/" {
					finalHost = finalVirt
				} else {
					finalHost = filepath.Join(cleanRoot, filepath.Join(curVirt...))
				}
				return finalHost, finalVirt, traversedSymlink, fmt.Errorf("%w: %q", ErrVanished, finalHost)
			}
			finalVirt := "/" + strings.Join(curVirt, "/")
			return curHost, finalVirt, traversedSymlink, lErr
		}

		if (lst.Mode() & os.ModeSymlink) != 0 {
			traversedSymlink = true
			hops++
			if hops > maxHops {
				finalVirt := "/" + strings.Join(curVirt, "/")
				return curHost, finalVirt, true, ErrSymlinkLoop
			}

			target, rErr := os.Readlink(curHost)
			if rErr != nil {
				finalVirt := "/" + strings.Join(curVirt, "/")
				return curHost, finalVirt, true, rErr
			}

			// Pop the symlink component itself
			curVirt = curVirt[:len(curVirt)-1]

			cleanLinkTarget := filepath.ToSlash(target)
			if strings.HasPrefix(cleanLinkTarget, "/") {
				// Absolute symlink: re-root at virtual root!
				curVirt = nil
				targetSegs := strings.Split(strings.TrimPrefix(cleanLinkTarget, "/"), "/")
				remaining = append(targetSegs, remaining...)
			} else {
				// Relative symlink: relative to current directory (curVirt)
				targetSegs := strings.Split(cleanLinkTarget, "/")
				remaining = append(targetSegs, remaining...)
			}
		}
	}

	finalVirt := "/" + strings.Join(curVirt, "/")
	var finalHost string
	if cleanRoot == "/" {
		finalHost = finalVirt
	} else {
		finalHost = filepath.Join(cleanRoot, filepath.Join(curVirt...))
	}

	// Confinement invariant check
	if cleanRoot != "/" {
		cleanedFinal := filepath.Clean(finalHost)
		if cleanedFinal != cleanRoot && !strings.HasPrefix(cleanedFinal, cleanRoot+string(filepath.Separator)) {
			return finalHost, finalVirt, traversedSymlink, ErrSymlinkEscapesRoot
		}
	}

	return finalHost, finalVirt, traversedSymlink, nil
}

// ReadFileReadOnlyUnderRoot reads a file located under rootFS using chroot containment semantics.
func ReadFileReadOnlyUnderRoot(root, targetPath string, maxBytes int64) ([]byte, error) {
	hostPath, _, _, err := ResolveUnderRoot(root, targetPath)
	if err != nil {
		return nil, err
	}
	return ReadFileReadOnly(hostPath, maxBytes)
}

// OpenRegularReadOnlyUnderRoot opens a regular file located under rootFS using chroot containment semantics.
func OpenRegularReadOnlyUnderRoot(root, targetPath string, maxFileSize int64) (*FileDescriptor, string, error) {
	hostPath, virtPath, _, err := ResolveUnderRoot(root, targetPath)
	if err != nil {
		return nil, virtPath, err
	}
	desc, err := OpenRegularReadOnly(hostPath, maxFileSize)
	return desc, virtPath, err
}
