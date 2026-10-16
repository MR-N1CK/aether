package scanner

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"math"
	"path/filepath"
	"strings"
	"sync/atomic"

	"golang.org/x/sys/unix"

	"aether/internal/config"
	"aether/internal/ioc"
	"aether/internal/report"
	"aether/internal/yara"
)

// inspectFile opens a file race-safely, computes/caches hashes per (dev, ino),
// evaluates heuristics, IOCs, and YARA rules from the in-memory buffer.
func (s *Scanner) inspectFile(ctx context.Context, path string, yScanner yara.Scanner, skippedSuppressed *atomic.Int64) (bool, error) {
	scanned, _, err := s.inspectFileWithOversize(ctx, path, yScanner, skippedSuppressed)
	return scanned, err
}

func (s *Scanner) inspectFileWithOversize(ctx context.Context, path string, yScanner yara.Scanner, skippedSuppressed *atomic.Int64) (bool, bool, error) {
	if isSwapFile(path) {
		return false, false, ErrNotRegularFile
	}

	hashOversizeMax := s.cfg.Scan.HashOversizeMax
	if hashOversizeMax <= 0 {
		hashOversizeMax = config.DefaultHashOversizeMax
	}
	if hashOversizeMax < s.cfg.Scan.MaxFileSize {
		hashOversizeMax = s.cfg.Scan.MaxFileSize
	}

	desc, err := OpenRegularReadOnly(path, hashOversizeMax)
	if err != nil {
		return false, false, err
	}
	defer desc.Close()

	cleanRoot := filepath.Clean(s.cfg.Scan.Root)
	isOffline := cleanRoot != "" && cleanRoot != "/"
	virtPath := path
	if isOffline {
		if rel, err := filepath.Rel(cleanRoot, path); err == nil {
			virtPath = "/" + strings.TrimPrefix(filepath.ToSlash(rel), "/")
		}
	}

	// Hardlink deduplication: cache & reuse hashing result per (dev, ino)
	inoKey := InodeKey{
		Dev: uint64(desc.Stat.Dev),
		Ino: uint64(desc.Stat.Ino),
	}

	hashRes, fileData, isHashedOversize, releasePooled, rErr := s.resolveFileHashAndData(ctx, desc, virtPath, inoKey, yScanner)
	if releasePooled != nil {
		// The pooled backing buffer stays charged until every consumer below
		// (hash IOC check, heuristics, decode, YARA) has finished reading fileData.
		defer releasePooled()
	}
	if rErr != nil {
		return false, false, rErr
	}

	// 1. Evaluate Hash IOC matches
	var hashMatch *ioc.MatchResult
	if m := s.iocEngine.CheckHash(hashRes.Hashes.SHA256); m != nil {
		hashMatch = m
	} else if m := s.iocEngine.CheckHash(hashRes.Hashes.SHA1); m != nil {
		hashMatch = m
	} else if m := s.iocEngine.CheckHash(hashRes.Hashes.MD5); m != nil {
		hashMatch = m
	}

	// 2. Check for known benign path suppression
	mode := uint32(desc.Stat.Mode)
	uid := uint32(desc.Stat.Uid)
	isBenign, benignReason := s.iocEngine.IsKnownBenign(virtPath, uid)

	// 3. Evaluate Path/Filename IOC matches (run for EVERY path)
	pathMatch := s.iocEngine.CheckPath(virtPath)

	// 4. Evaluate Heuristics (run for EVERY path)
	hasOtherSignal := (hashMatch != nil) || (pathMatch != nil)
	base := filepath.Base(virtPath)
	isSUIDorSGID := (mode & (unix.S_ISUID | unix.S_ISGID)) != 0
	isHiddenAndExec := strings.HasPrefix(base, ".") && (mode&0111 != 0)

	// Suppression never applies if the file is SUID/SGID, hidden AND executable, or matched by a hash/path IOC
	canSuppress := isBenign && !isSUIDorSGID && !isHiddenAndExec && !hasOtherSignal

	var hELF *HeuristicMatch
	if !canSuppress && !isHashedOversize {
		hELF = CheckELFInTempOrDev(virtPath, hashRes.Header, mode, uid, hasOtherSignal, s.cfg)
	} else if canSuppress && !isHashedOversize {
		// Suppressed files are downgraded to INFO and recorded (counted in CoverageStats.Suppressed, listed with --verbose)
		if rawELF := CheckELFInTempOrDev(virtPath, hashRes.Header, mode, uid, false, s.cfg); rawELF != nil {
			if skippedSuppressed != nil {
				skippedSuppressed.Add(1)
			}
			suppressedFinding := report.NewFinding(
				"filesystem",
				report.SeverityInfo,
				virtPath,
				fmt.Sprintf("Suppressed benign ELF file (%s)", benignReason),
				"Benign_Suppressed_File",
			)
			suppressedFinding.Hashes["MD5"] = hashRes.Hashes.MD5
			suppressedFinding.Hashes["SHA1"] = hashRes.Hashes.SHA1
			suppressedFinding.Hashes["SHA256"] = hashRes.Hashes.SHA256
			suppressedFinding.Metadata["suppressed"] = true
			suppressedFinding.Metadata["suppress_reason"] = benignReason
			suppressedFinding.Metadata["score"] = 0
			s.accumulator.Add(virtPath, "Benign_Suppressed_File", suppressedFinding.Reason, report.SeverityInfo, 0, suppressedFinding)
		}
		s.logger.Debug("suppressing ELF-in-temp heuristic for known benign path",
			slog.String("path", virtPath),
			slog.String("reason", benignReason),
		)
	}

	inspectData := hashRes.Header
	if len(fileData) > 0 {
		inspectData = fileData
	}

	hHidden := CheckHiddenExecutableInSystemDirs(virtPath, mode, s.cfg)
	hSUID := CheckSuspiciousSUID(virtPath, mode, s.cfg)
	hWorldWritable := CheckWorldWritableInEtc(virtPath, mode, s.cfg)
	hKey := CheckSuspiciousPrivateKeyMaterial(virtPath, inspectData, s.pkgDB, s.cfg)
	hScript := CheckSuspiciousScriptContent(virtPath, inspectData, s.pkgDB, s.cfg)
	hEntropyELF := CheckHighEntropyELF(virtPath, inspectData, s.cfg)
	hEntropyScript := CheckHighEntropyScript(virtPath, inspectData, s.cfg)
	hDecode, decodeLayers, decodeYaraMatches := DecodeAndRescanWithYARA(ctx, virtPath, inspectData, s.pkgDB, s.cfg, s.memoryBudget, yScanner)
	hTrojanPkg := CheckTrojanedPackageBinary(virtPath, hashRes.Hashes.MD5, s.pkgDB, s.cfg)

	if hELF != nil || hHidden != nil || hSUID != nil || hWorldWritable != nil || hKey != nil || hScript != nil || hEntropyELF != nil || hEntropyScript != nil || hDecode != nil || hTrojanPkg != nil || len(decodeYaraMatches) > 0 {
		hasOtherSignal = true
	}

	// 5. Known-good allowlist check:
	isAllowlisted, _ := s.iocEngine.IsAllowlisted(hashRes.Hashes.SHA256)
	if isAllowlisted || isHashedOversize {
		hELF = nil
		hHidden = nil
		hSUID = nil
		hWorldWritable = nil
		hKey = nil
		hScript = nil
		hEntropyELF = nil
		hEntropyScript = nil
		hDecode = nil
		hTrojanPkg = nil
		decodeYaraMatches = nil
		pathMatch = nil // Suppress path heuristics if known-good hash matches or oversize
	}

	statSize := desc.Stat.Size
	// 6. YARA scanning from buffer
	var yaraMatches []yara.RuleMatch
	if s.yaraEngine != nil && s.yaraEngine.Enabled() && yScanner != nil && statSize <= s.cfg.Scan.YaraMaxFileSize && !isHashedOversize {
		if len(fileData) > 0 || statSize == 0 {
			target := yara.ScanTarget{
				Path:      virtPath,
				Filename:  base,
				Extension: filepath.Ext(virtPath),
				FileType:  "",
				Owner:     fmt.Sprint(uid),
				Data:      fileData,
			}
			matches, yErr := yScanner.Scan(target)
			if yErr == nil && len(matches) > 0 {
				yaraMatches = matches
			}
		}
	}

	if len(decodeYaraMatches) > 0 && !isAllowlisted && !isHashedOversize {
		for i := range decodeYaraMatches {
			if decodeYaraMatches[i].Metadata == nil {
				decodeYaraMatches[i].Metadata = make(map[string]interface{})
			}
			decodeYaraMatches[i].Metadata["obfuscation_layers"] = strings.Join(decodeLayers, " -> ")
			decodeYaraMatches[i].Metadata["deobfuscated"] = true
		}
		yaraMatches = append(yaraMatches, decodeYaraMatches...)
	}

	// 7. Check if this file qualifies as a YARA rule file
	if s.yaraEngine != nil && s.yaraEngine.Enabled() && len(yaraMatches) > 0 && looksLikeYaraRuleFile(virtPath, fileData, hasOtherSignal, statSize) {
		if yEngine, ok := s.yaraEngine.(interface{ RecordRuleFileSeen() }); ok {
			yEngine.RecordRuleFileSeen()
		}
		ruleFinding := report.NewFinding(
			"filesystem",
			report.SeverityInfo,
			virtPath,
			"looks like a YARA rule file",
			"YARA_Rule_File",
		)
		ruleFinding.Hashes["MD5"] = hashRes.Hashes.MD5
		ruleFinding.Hashes["SHA1"] = hashRes.Hashes.SHA1
		ruleFinding.Hashes["SHA256"] = hashRes.Hashes.SHA256
		ruleFinding.Metadata["score"] = 0
		ruleFinding.Metadata["is_rule_file"] = true
		ruleFinding.Metadata["yara_rule"] = yaraMatches[0].RuleName
		s.accumulator.Add(virtPath, "YARA_Rule_File", ruleFinding.Reason, report.SeverityInfo, 0, ruleFinding)
		yaraMatches = nil
	}

	// 8. Consolidate into findings
	var matchedReasons []string
	var matchedRules []string
	totalScore := 0
	highestSeverity := report.SeverityInfo
	var hasConfidenceHigh bool

	updateSeverity := func(sev report.Severity) {
		switch sev {
		case report.SeverityAlert:
			highestSeverity = report.SeverityAlert
		case report.SeverityWarning:
			if highestSeverity != report.SeverityAlert {
				highestSeverity = report.SeverityWarning
			}
		case report.SeverityNotice:
			if highestSeverity != report.SeverityAlert && highestSeverity != report.SeverityWarning {
				highestSeverity = report.SeverityNotice
			}
		}
	}

	ruleSeverities := make(map[string]string)

	if hashMatch != nil {
		matchedReasons = append(matchedReasons, hashMatch.Reason)
		matchedRules = append(matchedRules, hashMatch.RuleName)
		ruleSeverities[hashMatch.RuleName] = hashMatch.Severity.String()
		totalScore += hashMatch.Score
		updateSeverity(hashMatch.Severity)
	}

	if pathMatch != nil {
		matchedReasons = append(matchedReasons, pathMatch.Reason)
		matchedRules = append(matchedRules, pathMatch.RuleName)
		ruleSeverities[pathMatch.RuleName] = pathMatch.Severity.String()
		totalScore += pathMatch.Score
		updateSeverity(pathMatch.Severity)
	}

	for _, hm := range []*HeuristicMatch{hELF, hHidden, hSUID, hWorldWritable, hKey, hScript, hEntropyELF, hEntropyScript, hDecode, hTrojanPkg} {
		if hm != nil {
			matchedReasons = append(matchedReasons, hm.Reason)
			matchedRules = append(matchedRules, hm.Name)
			ruleSeverities[hm.Name] = hm.Severity.String()
			totalScore += hm.Score
			updateSeverity(hm.Severity)
		}
	}

	var yaraRuleNames []string
	var yaraNamespaces []string
	var yaraTags []string
	var yaraMatchedStrings []string

	var isPkgOwned bool
	var pkgName string
	if s.pkgDB != nil && s.pkgDB.IsAvailable() {
		pkgName, isPkgOwned = s.pkgDB.Owner(virtPath)
	}
	isPentestPath := isKnownPentestToolPath(virtPath)

	var hasPentestDowngrade bool
	var hasPackageDowngrade bool
	var originalYaraSeverities []string

	for _, ym := range yaraMatches {
		if isAllowlisted && ym.Severity < report.SeverityAlert {
			if skippedSuppressed != nil {
				skippedSuppressed.Add(1)
			}
			suppressedFinding := report.NewFinding(
				"filesystem",
				report.SeverityInfo,
				virtPath,
				fmt.Sprintf("Allowlisted file (YARA match %s suppressed)", ym.RuleName),
				ym.RuleName,
			)
			suppressedFinding.Hashes["MD5"] = hashRes.Hashes.MD5
			suppressedFinding.Hashes["SHA1"] = hashRes.Hashes.SHA1
			suppressedFinding.Hashes["SHA256"] = hashRes.Hashes.SHA256
			suppressedFinding.Metadata["suppressed"] = true
			suppressedFinding.Metadata["suppress_reason"] = "allowlisted"
			suppressedFinding.Metadata["score"] = 0
			suppressedFinding.Metadata["yara_rule"] = ym.RuleName
			suppressedFinding.Metadata["yara_tags"] = ym.Tags
			s.accumulator.Add(virtPath, ym.RuleName, suppressedFinding.Reason, report.SeverityInfo, 0, suppressedFinding)
			continue
		}

		effectiveSev := ym.Severity
		effectiveScore := ym.Score
		isExplicitAlertOrCritical := false
		if ym.Metadata != nil {
			if sVal, ok := ym.Metadata["severity"].(string); ok {
				sUpper := strings.ToUpper(strings.TrimSpace(sVal))
				if sUpper == "ALERT" || sUpper == "CRITICAL" {
					isExplicitAlertOrCritical = true
				}
			}
		}

		isDoc := strings.Contains(virtPath, ".dist-info/") || strings.Contains(virtPath, ".egg-info/") ||
			strings.HasSuffix(virtPath, ".md") || strings.HasSuffix(virtPath, ".rst") || strings.HasSuffix(virtPath, ".txt")
		isTestFixture := (isPkgOwned || strings.Contains(virtPath, "/usr/lib/") || strings.Contains(virtPath, "/usr/share/")) &&
			(strings.Contains(virtPath, "/test/") || strings.Contains(virtPath, "/tests/") || strings.HasPrefix(base, "test_") || strings.Contains(base, "_test."))

		if s.cfg.Scan.TrustInstalledPentestTools && isPentestPath {
			effectiveSev = report.SeverityInfo
			effectiveScore = 0
			hasPentestDowngrade = true
			originalYaraSeverities = append(originalYaraSeverities, ym.Severity.String())
		} else if isDoc {
			effectiveSev = report.SeverityNotice
			if effectiveScore >= config.DefaultScoreYaraWarning {
				effectiveScore = config.DefaultScoreYaraWarning - 1
			}
			hasPackageDowngrade = true
			originalYaraSeverities = append(originalYaraSeverities, ym.Severity.String())
		} else if isTestFixture && isPkgOwned {
			effectiveSev = report.SeverityNotice
			if effectiveScore >= config.DefaultScoreYaraWarning {
				effectiveScore = config.DefaultScoreYaraWarning - 1
			}
			hasPackageDowngrade = true
			originalYaraSeverities = append(originalYaraSeverities, ym.Severity.String())
		} else if isPkgOwned && !isExplicitAlertOrCritical {
			switch ym.Severity {
			case report.SeverityAlert:
				effectiveSev = report.SeverityWarning
				if effectiveScore > config.DefaultScoreYaraStrong {
					effectiveScore = config.DefaultScoreYaraStrong
				}
			case report.SeverityWarning:
				effectiveSev = report.SeverityNotice
				if effectiveScore >= config.DefaultScoreYaraWarning {
					effectiveScore = config.DefaultScoreYaraWarning - 1
				}
			case report.SeverityNotice:
				effectiveSev = report.SeverityNotice
			}
			hasPackageDowngrade = true
			originalYaraSeverities = append(originalYaraSeverities, ym.Severity.String())
		}

		yaraRuleNames = append(yaraRuleNames, ym.RuleName)
		if ym.Namespace != "" {
			yaraNamespaces = append(yaraNamespaces, ym.Namespace)
		}
		yaraTags = append(yaraTags, ym.Tags...)
		yaraMatchedStrings = append(yaraMatchedStrings, ym.MatchedStrings...)

		reasonStr := fmt.Sprintf("YARA match: %s", ym.RuleName)
		if len(ym.MatchedStrings) > 0 {
			reasonStr = fmt.Sprintf("YARA match: %s (%s)", ym.RuleName, strings.Join(ym.MatchedStrings, ", "))
		}
		matchedReasons = append(matchedReasons, reasonStr)
		matchedRules = append(matchedRules, ym.RuleName)
		ruleSeverities[ym.RuleName] = effectiveSev.String()
		totalScore += effectiveScore
		updateSeverity(effectiveSev)
		if strings.EqualFold(ym.Confidence, "high") {
			hasConfidenceHigh = true
		}
	}

	// If any matches occurred, add to accumulator for grouping by (rule, parentDir)
	if len(matchedReasons) > 0 {
		reason := strings.Join(matchedReasons, " | ")
		primaryRule := matchedRules[0]
		var contributing []string
		if len(matchedRules) > 1 {
			contributing = matchedRules[1:]
		}

		f := report.NewFinding("filesystem", highestSeverity, virtPath, reason, primaryRule)
		f.Hashes["MD5"] = hashRes.Hashes.MD5
		f.Hashes["SHA1"] = hashRes.Hashes.SHA1
		f.Hashes["SHA256"] = hashRes.Hashes.SHA256
		// Normalize the additive score to the documented 0-100 band. Severity already
		// derives from the highest rule severity, so this only normalizes display data.
		if totalScore > 100 {
			totalScore = 100
		}
		f.Metadata["score"] = totalScore
		f.Metadata["size"] = hashRes.BytesRead
		f.Metadata["rule_severities"] = ruleSeverities
		if len(decodeLayers) > 0 {
			f.Metadata["decode_layers"] = decodeLayers
		}
		if len(inspectData) >= 512 && highestSeverity >= report.SeverityWarning {
			if ent := ShannonEntropy(inspectData); ent > 7.2 {
				f.Metadata["high_entropy"] = true
				f.Metadata["entropy"] = math.Round(ent*100) / 100
				totalScore += 10
				if totalScore > 100 {
					totalScore = 100
				}
				f.Metadata["score"] = totalScore
			}
		}
		if hasConfidenceHigh {
			f.Metadata["confidence"] = "high"
		}
		if len(yaraRuleNames) > 0 {
			f.Metadata["yara_rules"] = yaraRuleNames
			f.Metadata["yara_rule"] = yaraRuleNames[0]
		}
		if len(yaraNamespaces) > 0 {
			f.Metadata["yara_namespaces"] = yaraNamespaces
		}
		if len(yaraTags) > 0 {
			f.Metadata["yara_tags"] = yaraTags
		}
		if len(yaraMatchedStrings) > 0 {
			f.Metadata["yara_matched_strings"] = yaraMatchedStrings
		}
		if isPkgOwned {
			f.Metadata["known_package_owned"] = true
			f.Metadata["package_name"] = pkgName
		}
		if hasPentestDowngrade {
			f.Metadata["pentest_tool_path"] = true
			if len(originalYaraSeverities) > 0 {
				f.Metadata["original_severity"] = originalYaraSeverities[0]
			}
		} else if hasPackageDowngrade {
			if len(originalYaraSeverities) > 0 {
				f.Metadata["original_severity"] = originalYaraSeverities[0]
			}
		}

		detectorType := "heuristic"
		if len(yaraRuleNames) > 0 {
			detectorType = "yara"
		} else if hashMatch != nil || pathMatch != nil {
			detectorType = "ioc"
		}

		pkgStatus := "unowned"
		if isPkgOwned {
			pkgStatus = "verified_package"
		}

		f.EvidenceRecord = &report.EvidenceRecord{
			DetectorType:          detectorType,
			RuleName:              primaryRule,
			TargetPath:            virtPath,
			SHA256:                hashRes.Hashes.SHA256,
			FileMode:              mode,
			OwnerUID:              uid,
			PackageName:           pkgName,
			PackageStatus:         pkgStatus,
			ContributingDetectors: contributing,
		}

		isDoc := strings.Contains(virtPath, ".dist-info/") || strings.Contains(virtPath, ".egg-info/") ||
			strings.HasSuffix(virtPath, ".md") || strings.HasSuffix(virtPath, ".rst") || strings.HasSuffix(virtPath, ".txt")
		isTestFixture := (isPkgOwned || strings.Contains(virtPath, "/usr/lib/") || strings.Contains(virtPath, "/usr/share/")) &&
			(strings.Contains(virtPath, "/test/") || strings.Contains(virtPath, "/tests/") || strings.HasPrefix(base, "test_") || strings.Contains(base, "_test."))

		if hELF != nil && hELF.Name == "Heuristic_ELF_In_Temp_BuildTree" {
			f.EvidenceRecord.ContextProfile = "build_tree"
		}

		report.DetermineVerdict(&f, s.pkgDB, (mode&0111) != 0, isDoc, isTestFixture, nil)

		// Keep per-rule attribution consistent with the adjudicated finding: when the
		// verdict engine demotes the finding (contextual/package/pentest downgrades),
		// per-rule severities that exceeded the effective severity clamp down with it,
		// so the TopRules summary never advertises a higher level than the finding
		// table shows for the same detection. Lower attributions are preserved.
		if sevs, ok := f.Metadata["rule_severities"].(map[string]string); ok {
			for name, sv := range sevs {
				if rankSeverity(report.Severity(sv)) > rankSeverity(f.Severity) {
					sevs[name] = f.Severity.String()
				}
			}
		}

		s.accumulator.Add(virtPath, primaryRule, reason, f.Severity, totalScore, f)
	}

	return true, isHashedOversize, nil
}

// looksLikeYaraRuleFile determines if a file qualifies as a YARA rule file.
func looksLikeYaraRuleFile(path string, data []byte, hasOtherSignal bool, descSize int64) bool {
	if hasOtherSignal {
		return false
	}
	ext := strings.ToLower(filepath.Ext(path))
	if ext != ".yar" && ext != ".yara" {
		return false
	}
	if descSize > 2*1024*1024 || len(data) == 0 {
		return false
	}
	// Reject files with NUL bytes (binary files)
	if bytes.IndexByte(data, 0) != -1 {
		return false
	}
	// Reject ELF files
	if bytes.HasPrefix(data, []byte("\x7fELF")) {
		return false
	}
	// Reject scripts with shebang
	if bytes.HasPrefix(data, []byte("#!")) {
		return false
	}
	strData := string(data)
	if !strings.Contains(strData, "rule ") || !strings.Contains(strData, "{") || !strings.Contains(strData, "}") {
		return false
	}
	return true
}

var pentestToolPathPrefixes = []string{
	"/usr/share/metasploit-framework",
	"/usr/share/windows-resources",
	"/usr/share/powershell-empire",
	"/usr/share/exploitdb",
	"/usr/share/peass",
	"/usr/lib/python3/dist-packages/pypykatz",
	"/usr/lib/python3/dist-packages/nxc",
}

func isKnownPentestToolPath(path string) bool {
	clean := filepath.Clean(path)
	for _, prefix := range pentestToolPathPrefixes {
		if clean == prefix || strings.HasPrefix(clean, prefix+"/") || strings.HasPrefix(clean, prefix+"-") || strings.HasPrefix(clean, prefix+".") {
			return true
		}
	}
	return false
}
