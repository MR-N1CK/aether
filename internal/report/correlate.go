package report

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// CorrelationContext captures structured static/runtime cross-domain correlation records.
type CorrelationContext struct {
	CorrelationID    string                `json:"correlation_id"`
	PrimaryTarget    string                `json:"primary_target"`
	PrimaryPID       int                   `json:"primary_pid,omitempty"`
	PrimaryHash      string                `json:"primary_hash,omitempty"`
	DomainsInvolved  []CorroboratingDomain `json:"domains_involved"`
	EvidenceStrength EvidenceStrength      `json:"evidence_strength"`
	Verdict          Verdict               `json:"verdict"`
	Severity         Severity              `json:"severity,omitempty"`
	Confidence       Confidence            `json:"confidence,omitempty"`
	Signals          []CorroboratingSignal `json:"signals"`
}

// CorrelationIndex provides indexed lookups across accumulated findings and runtime state.
type CorrelationIndex struct {
	PathToFindings   map[string][]*Finding
	HashToFindings   map[string][]*Finding
	PIDToFindings    map[int][]*Finding
	SocketToFindings map[string][]*Finding
}

// NewCorrelationIndex creates an empty initialized CorrelationIndex.
func NewCorrelationIndex() *CorrelationIndex {
	return &CorrelationIndex{
		PathToFindings:   make(map[string][]*Finding),
		HashToFindings:   make(map[string][]*Finding),
		PIDToFindings:    make(map[int][]*Finding),
		SocketToFindings: make(map[string][]*Finding),
	}
}

// NormalizeFindingPath returns a cleaned, canonical path suitable for cross-domain lookup.
func NormalizeFindingPath(p string) string {
	if p == "" {
		return ""
	}
	cleaned := strings.TrimSpace(p)
	// Strip " -> <target>" from process paths
	if idx := strings.Index(cleaned, " -> "); idx != -1 {
		cleaned = cleaned[idx+4:]
	}
	// Strip " (deleted)" suffix
	cleaned = strings.TrimSuffix(cleaned, " (deleted)")
	// Strip bracketed comm names like "[sshd]"
	if strings.HasPrefix(cleaned, "[") && strings.HasSuffix(cleaned, "]") {
		return cleaned
	}
	return filepath.Clean(cleaned)
}

// DetermineFindingDomain returns the operational domain of a finding.
func DetermineFindingDomain(f *Finding) CorroboratingDomain {
	if f == nil {
		return DomainFilesystem
	}

	pathLower := strings.ToLower(f.Path)
	ruleLower := strings.ToLower(f.RuleName)

	switch {
	case strings.HasPrefix(pathLower, "/proc/net/") || strings.Contains(ruleLower, "socket") || strings.Contains(ruleLower, "listener") || strings.EqualFold(f.Module, "network"):
		return DomainNetwork
	case strings.HasPrefix(pathLower, "/proc/") || strings.Contains(ruleLower, "process") || strings.EqualFold(f.Module, "process"):
		return DomainProcess
	case strings.Contains(pathLower, "cron") || strings.Contains(pathLower, "systemd") || strings.Contains(pathLower, "/etc/rc") || strings.Contains(pathLower, "/etc/init") || strings.Contains(ruleLower, "persistence") || strings.EqualFold(f.Module, "persistence"):
		return DomainPersistence
	case strings.Contains(ruleLower, "ioc") || strings.EqualFold(f.Module, "ioc"):
		return DomainIOC
	default:
		return DomainFilesystem
	}
}

// isAggregateFinding reports whether the finding is a directory-level
// grouping artifact (multiple files rolled up under a parent directory)
// rather than a single concrete artifact. Aggregates carry no single path a
// process, socket, or unit could corroborate, so they never participate in
// cross-domain elevation — elevating "/usr/bin" because some unit references
// some file beneath it is the classic legitimate-daemon false positive.
func isAggregateFinding(f *Finding) bool {
	return f.Count > 1 || len(f.Paths) > 1
}

// isTriageDismissed reports whether the operator has explicitly suppressed or
// acknowledged the finding. Dismissed findings are excluded from correlation
// entirely: they neither corroborate other findings nor get escalated, so an
// acknowledged artifact can never resurface as MALICIOUS through the back door.
func isTriageDismissed(f *Finding) bool {
	if f.Metadata == nil {
		return false
	}
	if v, ok := f.Metadata["suppressed"].(bool); ok && v {
		return true
	}
	if v, ok := f.Metadata["acknowledged"].(bool); ok && v {
		return true
	}
	return false
}

// CorrelateFindings performs a cross-domain correlation pass over accumulated findings.
// It links static filesystem, running process, network socket, and persistence findings.
// Findings with >= 2 distinct independent domains are elevated to ALERT (StrengthCorroborated).
func CorrelateFindings(findings []Finding) []Finding {
	if len(findings) == 0 {
		return findings
	}

	idx := NewCorrelationIndex()

	// 1. Populate Correlation Index
	for i := range findings {
		f := &findings[i]

		if isTriageDismissed(f) || isAggregateFinding(f) {
			continue
		}

		// Ensure EvidenceRecord is populated
		if f.EvidenceRecord == nil {
			PopulateFindingDetails(f)
		}

		// Index by TargetPath & Path
		normPath := NormalizeFindingPath(f.Path)
		if normPath != "" && !strings.HasPrefix(normPath, "[") {
			idx.PathToFindings[normPath] = append(idx.PathToFindings[normPath], f)
		}
		if f.EvidenceRecord != nil && f.EvidenceRecord.TargetPath != "" {
			evNorm := NormalizeFindingPath(f.EvidenceRecord.TargetPath)
			if evNorm != "" && evNorm != normPath && !strings.HasPrefix(evNorm, "[") {
				idx.PathToFindings[evNorm] = append(idx.PathToFindings[evNorm], f)
			}
		}

		// Index by SHA256
		if f.EvidenceRecord != nil && f.EvidenceRecord.SHA256 != "" {
			idx.HashToFindings[f.EvidenceRecord.SHA256] = append(idx.HashToFindings[f.EvidenceRecord.SHA256], f)
		}
		if h, ok := f.Hashes["SHA256"]; ok && h != "" {
			idx.HashToFindings[h] = append(idx.HashToFindings[h], f)
		}

		// Index by PID
		pid := 0
		if f.EvidenceRecord != nil && f.EvidenceRecord.PID > 0 {
			pid = f.EvidenceRecord.PID
		} else if p, ok := f.Metadata["pid"].(int); ok && p > 0 {
			pid = p
		} else if p, ok := f.Metadata["pid"].(float64); ok && p > 0 {
			pid = int(p)
		}
		if pid > 0 {
			idx.PIDToFindings[pid] = append(idx.PIDToFindings[pid], f)
		}

		// Index by Socket info
		if f.EvidenceRecord != nil && f.EvidenceRecord.SocketInfo != "" {
			idx.SocketToFindings[f.EvidenceRecord.SocketInfo] = append(idx.SocketToFindings[f.EvidenceRecord.SocketInfo], f)
		}
	}

	// 2. Discover Cross-Domain Links
	// Map from finding pointer to list of CorroboratingSignals
	signalsMap := make(map[*Finding][]CorroboratingSignal)

	addSignal := func(target *Finding, sig CorroboratingSignal) {
		existing := signalsMap[target]
		for _, s := range existing {
			if s.Domain == sig.Domain && s.RuleName == sig.RuleName && s.TargetRef == sig.TargetRef {
				return
			}
		}
		signalsMap[target] = append(signalsMap[target], sig)
	}

	for i := range findings {
		f := &findings[i]
		if isTriageDismissed(f) {
			continue
		}
		domain := DetermineFindingDomain(f)
		normPath := NormalizeFindingPath(f.Path)

		// Link Filesystem <-> Process
		if domain == DomainFilesystem {
			// Check if any running process matches this filesystem finding path
			if procs, ok := idx.PathToFindings[normPath]; ok {
				for _, pf := range procs {
					if DetermineFindingDomain(pf) == DomainProcess {
						pid := pf.Metadata["pid"]
						if pid == nil && pf.EvidenceRecord != nil {
							pid = pf.EvidenceRecord.PID
						}
						comm := pf.Metadata["comm"]
						if comm == nil && pf.EvidenceRecord != nil {
							comm = pf.EvidenceRecord.Comm
						}
						targetRef := fmt.Sprintf("PID: %v (%v)", pid, comm)

						// Corroborate filesystem finding with process
						addSignal(f, CorroboratingSignal{
							Domain:      DomainProcess,
							RuleName:    pf.RuleName,
							Description: pf.Reason,
							TargetRef:   targetRef,
							Confidence:  "HIGH",
							Timestamp:   time.Now().UTC(),
						})
						// Corroborate process finding with filesystem
						addSignal(pf, CorroboratingSignal{
							Domain:      DomainFilesystem,
							RuleName:    f.RuleName,
							Description: f.Reason,
							TargetRef:   fmt.Sprintf("Path: %s", normPath),
							Confidence:  "HIGH",
							Timestamp:   time.Now().UTC(),
						})
					}
				}
			}

			// Check SHA256 match
			if f.EvidenceRecord != nil && f.EvidenceRecord.SHA256 != "" {
				if procs, ok := idx.HashToFindings[f.EvidenceRecord.SHA256]; ok {
					for _, pf := range procs {
						if DetermineFindingDomain(pf) == DomainProcess {
							addSignal(f, CorroboratingSignal{
								Domain:      DomainProcess,
								RuleName:    pf.RuleName,
								Description: pf.Reason,
								TargetRef:   fmt.Sprintf("ExeHash: %s", f.EvidenceRecord.SHA256),
								Confidence:  "HIGH",
								Timestamp:   time.Now().UTC(),
							})
						}
					}
				}
			}
		}

		// Link Process <-> Network
		if domain == DomainProcess {
			pid := 0
			if f.EvidenceRecord != nil && f.EvidenceRecord.PID > 0 {
				pid = f.EvidenceRecord.PID
			} else if p, ok := f.Metadata["pid"].(int); ok {
				pid = p
			}
			if pid > 0 {
				if netFindings, ok := idx.PIDToFindings[pid]; ok {
					for _, nf := range netFindings {
						if DetermineFindingDomain(nf) == DomainNetwork {
							sockInfo := ""
							if nf.EvidenceRecord != nil {
								sockInfo = nf.EvidenceRecord.SocketInfo
							}
							if sockInfo == "" {
								sockInfo = fmt.Sprintf("%v:%v", nf.Metadata["local_ip"], nf.Metadata["local_port"])
							}
							targetRef := fmt.Sprintf("Socket: %s", sockInfo)

							// Corroborate process with network
							addSignal(f, CorroboratingSignal{
								Domain:      DomainNetwork,
								RuleName:    nf.RuleName,
								Description: nf.Reason,
								TargetRef:   targetRef,
								Confidence:  "HIGH",
								Timestamp:   time.Now().UTC(),
							})
							// Corroborate network with process
							addSignal(nf, CorroboratingSignal{
								Domain:      DomainProcess,
								RuleName:    f.RuleName,
								Description: f.Reason,
								TargetRef:   fmt.Sprintf("PID: %d (%v)", pid, f.Metadata["comm"]),
								Confidence:  "HIGH",
								Timestamp:   time.Now().UTC(),
							})
						}
					}
				}
			}
		}

		// Link Persistence <-> Filesystem / Process
		if domain == DomainPersistence {
			// If persistence target references a known path
			if related, ok := idx.PathToFindings[normPath]; ok {
				for _, rf := range related {
					rfDomain := DetermineFindingDomain(rf)
					if rfDomain != DomainPersistence {
						targetRef := fmt.Sprintf("Persistence: %s", f.Path)
						addSignal(rf, CorroboratingSignal{
							Domain:      DomainPersistence,
							RuleName:    f.RuleName,
							Description: f.Reason,
							TargetRef:   targetRef,
							Confidence:  "HIGH",
							Timestamp:   time.Now().UTC(),
						})
						addSignal(f, CorroboratingSignal{
							Domain:      rfDomain,
							RuleName:    rf.RuleName,
							Description: rf.Reason,
							TargetRef:   fmt.Sprintf("Target: %s", rf.Path),
							Confidence:  "HIGH",
							Timestamp:   time.Now().UTC(),
						})
					}
				}
			}
		}
	}

	// 3. Multi-Hop Propagation: propagate Process -> Network signals to linked Filesystem findings
	for i := range findings {
		f := &findings[i]
		if isTriageDismissed(f) {
			continue
		}
		if DetermineFindingDomain(f) == DomainFilesystem {
			// If f is corroborated by Process P, copy P's Network and Persistence signals to f
			normPath := NormalizeFindingPath(f.Path)
			if procs, ok := idx.PathToFindings[normPath]; ok {
				for _, pf := range procs {
					if DetermineFindingDomain(pf) == DomainProcess {
						if pSignals, ok := signalsMap[pf]; ok {
							for _, ps := range pSignals {
								if ps.Domain == DomainNetwork || ps.Domain == DomainPersistence {
									addSignal(f, ps)
								}
							}
						}
					}
				}
			}
		}
	}

	// 4. Multi-Vector Corroboration Evaluator & Verdict Elevation
	for i := range findings {
		f := &findings[i]
		signals := signalsMap[f]
		if len(signals) == 0 {
			continue
		}
		if isTriageDismissed(f) || isAggregateFinding(f) {
			continue
		}

		// Collect unique domains
		ownDomain := DetermineFindingDomain(f)
		domainSet := make(map[CorroboratingDomain]bool)
		domainSet[ownDomain] = true
		for _, s := range signals {
			domainSet[s.Domain] = true
		}

		// Format corroborating signal reference strings
		var signalRefs []string
		for _, s := range signals {
			ref := fmt.Sprintf("%s:%s", s.Domain, s.TargetRef)
			signalRefs = append(signalRefs, ref)
		}
		sort.Strings(signalRefs)

		// Check if evidence is already Direct or Incomplete
		isDirect := f.EvidenceRecord != nil && f.EvidenceRecord.EvidenceStrength == StrengthDirect
		isIncomplete := f.EvidenceRecord != nil && f.EvidenceRecord.EvidenceStrength == StrengthIncomplete
		isDocMetadata := f.EvidenceRecord != nil && f.EvidenceRecord.ContextProfile == "doc_metadata"
		isHistorical := f.EvidenceRecord != nil && f.EvidenceRecord.ContextProfile == "historical_artifact"

		if isIncomplete || isDocMetadata || isHistorical {
			continue
		}

		// Multi-domain corroboration requires >= 2 distinct operational domains
		if len(domainSet) >= 2 {
			var domainNames []string
			for d := range domainSet {
				domainNames = append(domainNames, string(d))
			}
			sort.Strings(domainNames)

			if f.EvidenceRecord == nil {
				PopulateFindingDetails(f)
			}

			f.EvidenceRecord.EvidenceStrength = StrengthCorroborated
			f.EvidenceRecord.CorroboratingSignals = signalRefs
			f.EvidenceRecord.CorroborationDetails = signals

			// Elevate to MALICIOUS / ALERT / HIGH confidence
			f.Verdict = VerdictMalicious
			f.Severity = SeverityAlert
			f.Confidence = ConfidenceHigh
			f.ConfidenceRationale = fmt.Sprintf("Multi-vector threat confirmed by independent operational corroboration across %d domains (%s).",
				len(domainSet), strings.Join(domainNames, ", "))
			f.EvidenceRecord.ConfidenceRationale = f.ConfidenceRationale
		} else if !isDirect {
			// Single domain corroboration: enhance confidence to MEDIUM/HIGH but preserve single-vector verdict boundary
			if f.EvidenceRecord != nil {
				f.EvidenceRecord.CorroboratingSignals = signalRefs
				f.EvidenceRecord.CorroborationDetails = signals
			}
		}
	}

	return findings
}
