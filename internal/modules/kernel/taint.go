package kernel

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"aether/internal/report"
)

// TaintFlag defines a documented Linux kernel taint bit.
// Source: Linux Kernel Documentation: Documentation/admin-guide/tainted-kernels.rst (Kernel 6.x / 7.1.5+kali-amd64)
type TaintFlag struct {
	Bit         uint   // Bit position (0..17)
	Value       uint64 // Numerical bitmask value (1 << Bit)
	FlagChar    byte   // Standard single-character flag letter
	Name        string // Kernel identifier
	Description string // Human-readable description
	IsForced    bool   // True if forced load (F) or forced unload (R)
}

// TaintTable contains all 18 documented taint flags from Linux Documentation/admin-guide/tainted-kernels.rst
var TaintTable = []TaintFlag{
	{Bit: 0, Value: 1, FlagChar: 'P', Name: "TAINT_PROPRIETARY_MODULE", Description: "Proprietary module has been loaded"},
	{Bit: 1, Value: 2, FlagChar: 'F', Name: "TAINT_FORCED_MODULE", Description: "Module was force loaded with insmod -f", IsForced: true},
	{Bit: 2, Value: 4, FlagChar: 'S', Name: "TAINT_CPU_OUT_OF_SPEC", Description: "SMP with CPUs not certified for SMP"},
	{Bit: 3, Value: 8, FlagChar: 'R', Name: "TAINT_FORCED_RMMOD", Description: "Module was force unloaded with rmmod -f", IsForced: true},
	{Bit: 4, Value: 16, FlagChar: 'M', Name: "TAINT_MACHINE_CHECK", Description: "Processor machine check exception occurred"},
	{Bit: 5, Value: 32, FlagChar: 'B', Name: "TAINT_BAD_PAGE", Description: "Bad page referenced or unexpected page flags"},
	{Bit: 6, Value: 64, FlagChar: 'U', Name: "TAINT_USER_REQUEST", Description: "User forced taint via sysctl /proc/sys/kernel/tainted"},
	{Bit: 7, Value: 128, FlagChar: 'D', Name: "TAINT_DIE", Description: "Kernel has died (oops or BUG)"},
	{Bit: 8, Value: 256, FlagChar: 'A', Name: "TAINT_OVERRIDDEN_ACPI_TABLE", Description: "ACPI table overridden by user"},
	{Bit: 9, Value: 512, FlagChar: 'W', Name: "TAINT_WARN", Description: "Kernel warning emitted"},
	{Bit: 10, Value: 1024, FlagChar: 'C', Name: "TAINT_CRAP", Description: "Staging driver loaded"},
	{Bit: 11, Value: 2048, FlagChar: 'I', Name: "TAINT_FIRMWARE_WORKAROUND", Description: "Firmware workaround active"},
	{Bit: 12, Value: 4096, FlagChar: 'O', Name: "TAINT_OOT_MODULE", Description: "Out-of-tree module loaded (e.g. DKMS, Nvidia, VirtualBox)"},
	{Bit: 13, Value: 8192, FlagChar: 'E', Name: "TAINT_UNSIGNED_MODULE", Description: "Unsigned module loaded in kernel with module signature checking"},
	{Bit: 14, Value: 16384, FlagChar: 'L', Name: "TAINT_SOFTLOCKUP", Description: "Soft lockup occurred"},
	{Bit: 15, Value: 32768, FlagChar: 'K', Name: "TAINT_LIVEPATCH", Description: "Kernel has been livepatched"},
	{Bit: 16, Value: 65536, FlagChar: 'X', Name: "TAINT_AUX", Description: "Auxiliary taint defined for and used by distros"},
	{Bit: 17, Value: 131072, FlagChar: 'T', Name: "TAINT_STRUCT_RANDOMIZATION", Description: "Kernel was built with GCC struct randomization plugin"},
}

// DecodeTaint converts a taint bitmask integer into active TaintFlags and a flag string.
func DecodeTaint(taintVal uint64) ([]TaintFlag, string) {
	var active []TaintFlag
	var letters []byte

	for _, flag := range TaintTable {
		if (taintVal & flag.Value) != 0 {
			active = append(active, flag)
			letters = append(letters, flag.FlagChar)
		}
	}

	return active, string(letters)
}

// CheckTainted reads and decodes /proc/sys/kernel/tainted.
func CheckTainted(procRoot string, cov *KernelCoverage, logger *slog.Logger) []report.Finding {
	var findings []report.Finding

	taintPath := "/proc/sys/kernel/tainted"
	if procRoot != "" {
		taintPath = filepath.Join(procRoot, "sys/kernel/tainted")
	}

	data, err := os.ReadFile(taintPath)
	if err != nil {
		return findings
	}

	taintValStr := strings.TrimSpace(string(data))
	taintVal, err := strconv.ParseUint(taintValStr, 10, 64)
	if err != nil || taintVal == 0 {
		return findings
	}

	cov.TaintValue = taintVal
	activeFlags, flagChars := DecodeTaint(taintVal)

	var flagNames []string
	hasForced := false
	onlyOOTOrProprietaryOrUnsigned := true

	for _, af := range activeFlags {
		flagNames = append(flagNames, fmt.Sprintf("%c:%s", af.FlagChar, af.Name))
		if af.IsForced {
			hasForced = true
		}
		// Check if outside OOT (O), Proprietary (P), or Unsigned (E)
		if af.FlagChar != 'P' && af.FlagChar != 'O' && af.FlagChar != 'E' {
			onlyOOTOrProprietaryOrUnsigned = false
		}
	}
	cov.TaintFlags = flagNames

	if hasForced {
		cov.TaintSeverity = "NOTICE"
		findings = append(findings, report.Finding{
			Timestamp: time.Now(),
			Module:    "kernel",
			Severity:  report.SeverityNotice,
			Path:      taintPath,
			Reason:    fmt.Sprintf("Kernel is tainted with forced module flag (%s, value %d): %s", flagChars, taintVal, strings.Join(flagNames, ", ")),
			RuleName:  "Kernel_Taint_Forced_Module",
			Count:     1,
			Paths:     []string{taintPath},
			Metadata: map[string]interface{}{
				"taint_value": taintVal,
				"flags":       flagChars,
				"score":       30,
			},
		})
	} else if onlyOOTOrProprietaryOrUnsigned {
		// e.g. Taint 12289 (P + O + E) on host -> INFO only
		cov.TaintSeverity = "INFO"
		findings = append(findings, report.Finding{
			Timestamp: time.Now(),
			Module:    "kernel",
			Severity:  report.SeverityInfo,
			Path:      taintPath,
			Reason:    fmt.Sprintf("Kernel is tainted by out-of-tree / proprietary / unsigned module (%s, value %d): %s", flagChars, taintVal, strings.Join(flagNames, ", ")),
			RuleName:  "Kernel_Taint_OutOfTree",
			Count:     1,
			Paths:     []string{taintPath},
			Metadata: map[string]interface{}{
				"taint_value": taintVal,
				"flags":       flagChars,
				"score":       10,
			},
		})
	} else {
		cov.TaintSeverity = "INFO"
		findings = append(findings, report.Finding{
			Timestamp: time.Now(),
			Module:    "kernel",
			Severity:  report.SeverityInfo,
			Path:      taintPath,
			Reason:    fmt.Sprintf("Kernel taint flags active (%s, value %d): %s", flagChars, taintVal, strings.Join(flagNames, ", ")),
			RuleName:  "Kernel_Taint_Active",
			Count:     1,
			Paths:     []string{taintPath},
			Metadata: map[string]interface{}{
				"taint_value": taintVal,
				"flags":       flagChars,
				"score":       10,
			},
		})
	}

	return findings
}
