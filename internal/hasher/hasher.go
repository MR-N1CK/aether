package hasher

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"sync"
)

const bufferSize = 64 * 1024 // 64KB chunk buffer

var bufferPool = sync.Pool{
	New: func() any {
		b := make([]byte, bufferSize)
		return &b
	},
}

// FileHashes holds cryptographic hashes calculated in a single streaming pass.
type FileHashes struct {
	MD5    string
	SHA1   string
	SHA256 string
}

// HashStreamResult holds calculated hashes and leading header bytes for heuristic checks.
type HashStreamResult struct {
	Hashes    FileHashes
	Header    []byte // Up to first 16 bytes for magic bytes (e.g. ELF)
	BytesRead int64
}

// StreamHashAndHeader reads the file descriptor in a single pass using pooled memory,
// calculating MD5, SHA1, and SHA256 simultaneously via io.MultiWriter without loading
// the file into memory.
func StreamHashAndHeader(f *os.File) (*HashStreamResult, error) {
	bufPtr := bufferPool.Get().(*[]byte)
	defer bufferPool.Put(bufPtr)
	buf := *bufPtr

	hMD5 := md5.New()
	hSHA1 := sha1.New()
	hSHA256 := sha256.New()
	multiWriter := io.MultiWriter(hMD5, hSHA1, hSHA256)

	var header []byte
	var totalRead int64

	for {
		n, err := f.Read(buf)
		if n > 0 {
			totalRead += int64(n)

			// Capture the first up to 16 bytes for header inspection
			if len(header) < 16 {
				needed := 16 - len(header)
				if n < needed {
					header = append(header, buf[:n]...)
				} else {
					header = append(header, buf[:needed]...)
				}
			}

			// Stream chunk into all hash functions simultaneously
			if _, wErr := multiWriter.Write(buf[:n]); wErr != nil {
				return nil, wErr
			}
		}

		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
	}

	return &HashStreamResult{
		Hashes: FileHashes{
			MD5:    hex.EncodeToString(hMD5.Sum(nil)),
			SHA1:   hex.EncodeToString(hSHA1.Sum(nil)),
			SHA256: hex.EncodeToString(hSHA256.Sum(nil)),
		},
		Header:    header,
		BytesRead: totalRead,
	}, nil
}

// HashFromBytes calculates MD5, SHA1, SHA256 and header from a pre-buffered slice.
func HashFromBytes(data []byte) *HashStreamResult {
	hMD5 := md5.Sum(data)
	hSHA1 := sha1.Sum(data)
	hSHA256 := sha256.Sum256(data)

	var header []byte
	if len(data) >= 16 {
		header = make([]byte, 16)
		copy(header, data[:16])
	} else {
		header = make([]byte, len(data))
		copy(header, data)
	}

	return &HashStreamResult{
		Hashes: FileHashes{
			MD5:    hex.EncodeToString(hMD5[:]),
			SHA1:   hex.EncodeToString(hSHA1[:]),
			SHA256: hex.EncodeToString(hSHA256[:]),
		},
		Header:    header,
		BytesRead: int64(len(data)),
	}
}
