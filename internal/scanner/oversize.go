package scanner

import (
	"context"
	"fmt"
	"io"

	"aether/internal/report"
	"aether/internal/yara"
)

// resolveFileHashAndData determines the cryptographic hashes and inspectable byte buffer for a file.
// It handles oversize streaming, memory budgeting, hardlink caching, and YARA oversize skip tracking.
func (s *Scanner) resolveFileHashAndData(
	ctx context.Context,
	desc *FileDescriptor,
	virtPath string,
	inoKey InodeKey,
	yScanner yara.Scanner,
) (*HashStreamResult, []byte, bool, error) {
	statSize := desc.Stat.Size
	var fileData []byte
	var hashRes *HashStreamResult
	isHashedOversize := false
	isHardlinkCandidate := desc.Stat.Nlink > 1

	if statSize > s.cfg.Scan.MaxFileSize {
		isHashedOversize = true
		if isHardlinkCandidate {
			if val, found := s.hashCache.Load(inoKey); found {
				hashRes = val.(*HashStreamResult)
			}
		}
		if hashRes == nil {
			sRes, sErr := StreamHashAndHeader(desc.File)
			if sErr != nil {
				return nil, nil, false, sErr
			}
			hashRes = sRes
			if isHardlinkCandidate {
				s.hashCache.Store(inoKey, hashRes)
			}
		}
		if s.yaraEngine != nil && s.yaraEngine.Enabled() {
			if yEngine, ok := s.yaraEngine.(interface{ RecordSkipOversize() }); ok {
				yEngine.RecordSkipOversize()
			}
		}
	} else if isHardlinkCandidate && func() bool {
		val, found := s.hashCache.Load(inoKey)
		if found {
			hashRes = val.(*HashStreamResult)
			return true
		}
		return false
	}() {
		if s.yaraEngine != nil && s.yaraEngine.Enabled() && yScanner != nil && statSize <= s.cfg.Scan.YaraMaxFileSize && statSize >= 0 {
			buf, capSize, bErr := s.memoryBudget.Acquire(ctx, statSize)
			if bErr == nil {
				defer s.memoryBudget.Release(buf, capSize)
				n, _ := io.ReadFull(desc.File, buf)
				fileData = buf[:n]
			}
		}
	} else {
		if statSize > s.cfg.Scan.YaraMaxFileSize {
			// Stream hash file without buffering entire content
			sRes, sErr := StreamHashAndHeader(desc.File)
			if sErr != nil {
				return nil, nil, false, sErr
			}
			hashRes = sRes
			if isHardlinkCandidate {
				s.hashCache.Store(inoKey, hashRes)
			}
			if s.yaraEngine != nil && s.yaraEngine.Enabled() {
				if yEngine, ok := s.yaraEngine.(interface{ RecordSkipOversize() }); ok {
					yEngine.RecordSkipOversize()
				}
				oversizeFinding := report.NewFinding(
					"filesystem",
					report.SeverityInfo,
					virtPath,
					fmt.Sprintf("file size (%d bytes) exceeds YARA max filesize limit (%d bytes); YARA scan skipped (stream-hashed for IOCs)", statSize, s.cfg.Scan.YaraMaxFileSize),
					"YARA_Skipped_Oversize",
				)
				oversizeFinding.Hashes["MD5"] = hashRes.Hashes.MD5
				oversizeFinding.Hashes["SHA1"] = hashRes.Hashes.SHA1
				oversizeFinding.Hashes["SHA256"] = hashRes.Hashes.SHA256
				oversizeFinding.Metadata["size"] = statSize
				oversizeFinding.Metadata["oversize"] = true
				oversizeFinding.Metadata["score"] = 0
				s.accumulator.Add(virtPath, "YARA_Skipped_Oversize", oversizeFinding.Reason, report.SeverityInfo, 0, oversizeFinding)
			}
		} else {
			buf, capSize, bErr := s.memoryBudget.Acquire(ctx, statSize)
			if bErr != nil {
				return nil, nil, false, bErr
			}
			defer s.memoryBudget.Release(buf, capSize)

			n, rErr := io.ReadFull(desc.File, buf)
			if rErr != nil && rErr != io.EOF && rErr != io.ErrUnexpectedEOF {
				return nil, nil, false, rErr
			}
			data := buf[:n]
			hashRes = HashFromBytes(data)
			if isHardlinkCandidate {
				s.hashCache.Store(inoKey, hashRes)
			}
			fileData = data
		}
	}

	return hashRes, fileData, isHashedOversize, nil
}
