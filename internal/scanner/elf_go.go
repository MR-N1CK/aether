package scanner

import (
	"bytes"
	"debug/buildinfo"
	"debug/elf"
	"debug/gosym"
	"sort"
	"strings"
)

// Go static binaries (CGO_ENABLED=0, the default implant build) carry no
// .dynsym imports, so the capability-combo engine sees nothing. Their pclntab
// — required by the Go runtime even in `-ldflags "-s -w"` stripped binaries —
// still names every compiled function, including stdlib networking and
// execution packages. Recovering those names restores behavioral visibility
// into the most common modern Linux implant format.

// goCapabilityMarker maps pclntab function-name substrings to behavioral
// capabilities. Markers are deliberately package-level (not call-site-level):
// pclntab presence proves the program linked the capability, not that a
// hostile path reaches it, so recovered capabilities are treated as weaker
// evidence than dynamic imports and only escalate in combination.
var goCapabilityMarkers = []struct {
	capability string
	markers    []string
}{
	{"go_net_client", []string{"net.Dial", "net.(*Dialer)", "net.(*SyscallConn)"}},
	{"go_net_server", []string{"net.Listen", "net.(*ListenConfig)"}},
	{"go_process_exec", []string{"os/exec."}},
	{"go_fd_dup", []string{"syscall.Dup2", "syscall.Dup3", "unix.Dup3"}},
	{"go_memfd_exec", []string{"MemfdCreate"}},
	{"go_ptrace_inject", []string{"PtraceAttach", "PtraceTraceme", "ProcessVMWritev", "ProcessVMReadv"}},
}

// GoStaticProfile is the recovered intelligence from a static Go binary.
type GoStaticProfile struct {
	IsGo       bool
	GoVersion  string
	ModulePath string
	Caps       []string
}

// RecoverGoStaticProfile extracts build metadata (Go version, module path)
// and behavioral capabilities from a Go ELF binary via buildinfo and the
// pclntab function table. Non-Go binaries return IsGo=false. Failures are
// silent: recovery is best-effort enrichment, never a scan error.
func RecoverGoStaticProfile(data []byte, ef *elf.File) GoStaticProfile {
	var prof GoStaticProfile

	bi, err := buildinfo.Read(bytes.NewReader(data))
	if err != nil || bi == nil {
		return prof
	}
	prof.IsGo = true
	prof.GoVersion = bi.GoVersion
	if bi.Main.Path != "" {
		prof.ModulePath = bi.Main.Path
	}

	// The pclntab section names every compiled function; gosym decodes it.
	var pclntab []byte
	if sec := ef.Section(".gopclntab"); sec != nil {
		if raw, sErr := sec.Data(); sErr == nil {
			pclntab = raw
		}
	}
	if len(pclntab) == 0 {
		return prof
	}

	var textAddr uint64
	if ts := ef.Section(".text"); ts != nil {
		textAddr = ts.Addr
	}

	lineTable := gosym.NewLineTable(pclntab, textAddr)
	tab, err := gosym.NewTable(nil, lineTable)
	if err != nil {
		return prof
	}

	capSet := make(map[string]struct{})
	for _, fn := range tab.Funcs {
		for _, m := range goCapabilityMarkers {
			for _, marker := range m.markers {
				if strings.Contains(fn.Name, marker) {
					capSet[m.capability] = struct{}{}
					break
				}
			}
		}
	}

	prof.Caps = make([]string, 0, len(capSet))
	for c := range capSet {
		prof.Caps = append(prof.Caps, c)
	}
	sort.Strings(prof.Caps)
	return prof
}

// Has reports whether the recovered profile includes the capability.
func (p GoStaticProfile) Has(capability string) bool {
	for _, c := range p.Caps {
		if c == capability {
			return true
		}
	}
	return false
}
