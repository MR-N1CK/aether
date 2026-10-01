package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
)

// Reporter handles storing, streaming, and summarizing scan findings concurrently.
type Reporter interface {
	// Report records a new finding in a thread-safe manner.
	Report(f Finding)
	// Findings returns a snapshot copy of all recorded findings.
	Findings() []Finding
	// Summary returns finding counts by severity.
	Summary() (total int, alerts int, warnings int, notices int, infos int)
	// Close flushes any pending writes and closes open file handles.
	Close() error
}

// ConcurrentReporter is a thread-safe implementation of Reporter.
type ConcurrentReporter struct {
	mu          sync.RWMutex
	findings    []Finding
	jsonFile    *os.File
	jsonEncoder *json.Encoder
	writer      io.Writer
}

// NewConcurrentReporter initializes a thread-safe reporter. If jsonPath is provided,
// findings will be streamed as newline-delimited JSON or formatted JSON upon completion.
func NewConcurrentReporter(jsonPath string) (*ConcurrentReporter, error) {
	cr := &ConcurrentReporter{
		findings: make([]Finding, 0),
	}

	if jsonPath != "" {
		if jsonPath == "-" {
			cr.writer = os.Stdout
			cr.jsonEncoder = json.NewEncoder(os.Stdout)
		} else {
			// Enforce write flags for output report file only (scanned files remain read-only)
			f, err := os.OpenFile(jsonPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
			if err != nil {
				return nil, fmt.Errorf("failed to open json output file: %w", err)
			}
			cr.jsonFile = f
			cr.writer = f
			cr.jsonEncoder = json.NewEncoder(f)
		}
	}

	return cr, nil
}

// Report safely adds a finding and optionally streams it to the JSON destination.
func (r *ConcurrentReporter) Report(f Finding) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.findings = append(r.findings, f)

	if r.jsonEncoder != nil {
		_ = r.jsonEncoder.Encode(f)
	}
}

// Findings returns a shallow copy of all recorded findings.
func (r *ConcurrentReporter) Findings() []Finding {
	r.mu.RLock()
	defer r.mu.RUnlock()

	copied := make([]Finding, len(r.findings))
	copy(copied, r.findings)
	return copied
}

// Summary calculates the tally of findings by severity in a thread-safe manner.
func (r *ConcurrentReporter) Summary() (total int, alerts int, warnings int, notices int, infos int) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	total = len(r.findings)
	for _, f := range r.findings {
		switch f.Severity {
		case SeverityAlert:
			alerts++
		case SeverityWarning:
			warnings++
		case SeverityNotice:
			notices++
		case SeverityInfo:
			infos++
		}
	}
	return
}

// Close flushes and closes the report file handle if open.
func (r *ConcurrentReporter) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.jsonFile != nil {
		err := r.jsonFile.Sync()
		closeErr := r.jsonFile.Close()
		r.jsonFile = nil
		r.jsonEncoder = nil
		if err != nil {
			return err
		}
		return closeErr
	}
	return nil
}
