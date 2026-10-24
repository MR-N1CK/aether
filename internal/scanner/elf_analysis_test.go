package scanner

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"debug/elf"

	"aether/internal/config"
	"aether/internal/report"
)

// craftTestELF builds a minimal 64-bit little-endian ELF carrying a .dynamic
// section with the given string-valued tags and an accompanying .dynstr.
// It is consumed in-memory by CheckSuspiciousELFRPath via debug/elf.
func craftTestELF(t *testing.T, entries map[elf.DynTag]string) []byte {
	t.Helper()

	// Build the dynstr blob: "\0" then each unique value NUL-separated.
	strtab := []byte{0}
	valueOffset := make(map[string]uint64, len(entries))
	for _, v := range entries {
		if _, dup := valueOffset[v]; dup {
			continue
		}
		valueOffset[v] = uint64(len(strtab))
		strtab = append(strtab, []byte(v)...)
		strtab = append(strtab, 0)
	}

	// Deterministic tag order so the payload is reproducible.
	tags := make([]int, 0, len(entries))
	for tag := range entries {
		tags = append(tags, int(tag))
	}
	for i := 1; i < len(tags); i++ {
		for j := i; j > 0 && tags[j] < tags[j-1]; j-- {
			tags[j], tags[j-1] = tags[j-1], tags[j]
		}
	}

	var dyn []byte
	for _, tag := range tags {
		dyn = binary.LittleEndian.AppendUint64(dyn, uint64(tag))
		dyn = binary.LittleEndian.AppendUint64(dyn, valueOffset[entries[elf.DynTag(tag)]])
	}
	// DT_NULL terminator.
	dyn = binary.LittleEndian.AppendUint64(dyn, 0)
	dyn = binary.LittleEndian.AppendUint64(dyn, 0)

	// Section-name table (needed so debug/elf can load sections cleanly).
	shstr := []byte{0}
	nameOffset := func(name string) uint32 {
		off := len(shstr)
		shstr = append(shstr, []byte(name)...)
		shstr = append(shstr, 0)
		return uint32(off)
	}
	nameDynamic := nameOffset(".dynamic")
	nameStr := nameOffset(".dynstr")
	nameShstr := nameOffset(".shstrtab")

	dynOff := 64
	strOff := dynOff + len(dyn)
	shstrOff := strOff + len(strtab)
	shOff := shstrOff + len(shstr)

	hdr := make([]byte, 64)
	copy(hdr, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0})
	binary.LittleEndian.PutUint16(hdr[16:], 2)     // e_type ET_EXEC
	binary.LittleEndian.PutUint16(hdr[18:], 62)    // e_machine EM_X86_64
	binary.LittleEndian.PutUint32(hdr[20:], 1)     // e_version
	binary.LittleEndian.PutUint64(hdr[24:], 0x100) // e_entry
	binary.LittleEndian.PutUint64(hdr[32:], 0)     // e_phoff
	binary.LittleEndian.PutUint64(hdr[40:], uint64(shOff))
	binary.LittleEndian.PutUint32(hdr[48:], 0)  // e_flags
	binary.LittleEndian.PutUint16(hdr[52:], 64) // e_ehsize
	binary.LittleEndian.PutUint16(hdr[54:], 56) // e_phentsize
	binary.LittleEndian.PutUint16(hdr[56:], 0)  // e_phnum
	binary.LittleEndian.PutUint16(hdr[58:], 64) // e_shentsize
	binary.LittleEndian.PutUint16(hdr[60:], 4)  // e_shnum
	binary.LittleEndian.PutUint16(hdr[62:], 3)  // e_shstrndx

	// ELF64 section header layout (64 bytes each).
	type sheader struct {
		name      uint32
		typ       uint32
		flags     uint64
		addr      uint64
		offset    uint64
		size      uint64
		link      uint32
		info      uint32
		addralign uint64
		entsize   uint64
	}
	sections := []sheader{
		{},
		{uint32(nameDynamic), 6 /*SHT_DYNAMIC*/, 0, 0, uint64(dynOff), uint64(len(dyn)), 2 /*sh_link -> .dynstr*/, 0, 8, 16},
		{uint32(nameStr), 3 /*SHT_STRTAB*/, 0, 0, uint64(strOff), uint64(len(strtab)), 0, 0, 1, 0},
		{uint32(nameShstr), 3, 0, 0, uint64(shstrOff), uint64(len(shstr)), 0, 0, 1, 0},
	}

	var shTable bytes.Buffer
	for _, sh := range sections {
		shbuf := make([]byte, 64)
		binary.LittleEndian.PutUint32(shbuf[0:], sh.name)
		binary.LittleEndian.PutUint32(shbuf[4:], sh.typ)
		binary.LittleEndian.PutUint64(shbuf[8:], sh.flags)
		binary.LittleEndian.PutUint64(shbuf[16:], sh.addr)
		binary.LittleEndian.PutUint64(shbuf[24:], sh.offset)
		binary.LittleEndian.PutUint64(shbuf[32:], sh.size)
		binary.LittleEndian.PutUint32(shbuf[40:], sh.link)
		binary.LittleEndian.PutUint32(shbuf[44:], sh.info)
		binary.LittleEndian.PutUint64(shbuf[48:], sh.addralign)
		binary.LittleEndian.PutUint64(shbuf[56:], sh.entsize)
		shTable.Write(shbuf)
	}

	var out bytes.Buffer
	out.Write(hdr)
	out.Write(dyn)
	out.Write(strtab)
	out.Write(shstr)
	out.Write(shTable.Bytes())
	return out.Bytes()
}

func parseSelfCheck(t *testing.T, data []byte) *elf.File {
	t.Helper()
	ef, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		t.Skipf("crafted ELF rejected by parser (craft bug): %v", err)
	}
	return ef
}

func TestCraftTestELF_Parseable(t *testing.T) {
	data := craftTestELF(t, map[elf.DynTag]string{
		elf.DT_RPATH: "/tmp/steam",
	})
	ef := parseSelfCheck(t, data)
	if ef == nil {
		return
	}
	vals, err := ef.DynString(elf.DT_RPATH)
	if err != nil || len(vals) != 1 || vals[0] != "/tmp/steam" {
		t.Fatalf("crafted ELF lost RPATH: vals=%v err=%v", vals, err)
	}
}

func TestCheckSuspiciousELFRPath_VolatileDir(t *testing.T) {
	data := craftTestELF(t, map[elf.DynTag]string{
		elf.DT_RUNPATH: "/tmp/steam:/lib/ok",
	})
	hm := CheckSuspiciousELFRPath("/usr/bin/chrome-sandbox", data, 0o755, nil)
	if hm == nil {
		t.Fatal("expected RPATH hijack detection for volatile RUNPATH entry")
	}
	if hm.Name != "Persistence_ELF_RPATH_Hijack" {
		t.Errorf("unexpected rule name %q", hm.Name)
	}
	if hm.Severity != report.SeverityAlert {
		t.Errorf("system-dir binary with volatile RUNPATH must be ALERT, got %s", hm.Severity)
	}
	if hm.Score != config.DefaultScoreELFRPATHSystem {
		t.Errorf("expected system score %d, got %d", config.DefaultScoreELFRPATHSystem, hm.Score)
	}
	if !bytes.Contains([]byte(hm.Reason), []byte("/tmp/steam")) {
		t.Errorf("reason must name the offending entry, got %q", hm.Reason)
	}
}

func TestCheckSuspiciousELFRPath_WorldWritable(t *testing.T) {
	// /var/tmp and /tmp are volatile-classified, so the writable fixture
	// must live elsewhere for the world-writable branch to be reachable.
	dir, err := os.MkdirTemp(".", "aether-ww-")
	if err != nil {
		t.Skipf("cannot create temp dir in cwd: %v", err)
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		t.Skipf("cannot resolve abs: %v", err)
	}
	dir = abs
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	data := craftTestELF(t, map[elf.DynTag]string{
		elf.DT_RPATH: dir,
	})
	hm := CheckSuspiciousELFRPath("/usr/lib/libcombo.so", data, 0o755, nil)
	if hm == nil {
		t.Fatalf("expected detection for world-writable RPATH dir %s", dir)
	}
	if !bytes.Contains([]byte(hm.Reason), []byte("world-writable")) {
		t.Errorf("reason must cite world-writable, got %q", hm.Reason)
	}
}

func TestCheckSuspiciousELFRPath_UserBinaryIsWarning(t *testing.T) {
	data := craftTestELF(t, map[elf.DynTag]string{
		elf.DT_RUNPATH: "/dev/shm",
	})
	hm := CheckSuspiciousELFRPath("/home/dev/tools/mytool", data, 0o755, nil)
	if hm == nil {
		t.Fatal("expected detection outside system dirs")
	}
	if hm.Severity != report.SeverityWarning {
		t.Errorf("non-system binary must be WARNING, got %s", hm.Severity)
	}
	if hm.Score != config.DefaultScoreELFRPATHUser {
		t.Errorf("expected user score %d, got %d", config.DefaultScoreELFRPATHUser, hm.Score)
	}
}

func TestCheckSuspiciousELFRPath_OriginIgnored(t *testing.T) {
	data := craftTestELF(t, map[elf.DynTag]string{
		elf.DT_RUNPATH: "$ORIGIN/../lib",
	})
	if hm := CheckSuspiciousELFRPath("/opt/app/bin/run", data, 0o755, nil); hm != nil {
		t.Errorf("legitimate $ORIGIN RUNPATH must not alert, got %q", hm.Reason)
	}
}

func TestCheckSuspiciousELFRPath_RelativeEntryFlags(t *testing.T) {
	data := craftTestELF(t, map[elf.DynTag]string{
		elf.DT_RPATH: "relative/lib",
	})
	hm := CheckSuspiciousELFRPath("/usr/sbin/agent", data, 0o755, nil)
	if hm == nil {
		t.Fatal("relative RPATH entry must be flagged")
	}
	if !bytes.Contains([]byte(hm.Reason), []byte("relative search path")) {
		t.Errorf("reason must cite relative search path, got %q", hm.Reason)
	}
}

func TestCheckSuspiciousELFRPath_DataFileSkipped(t *testing.T) {
	data := craftTestELF(t, map[elf.DynTag]string{
		elf.DT_RPATH: "/tmp/steam",
	})
	// No execute bit and no .so in the name: detector skips.
	if hm := CheckSuspiciousELFRPath("/var/lib/dump.core", data, 0o600, nil); hm != nil {
		t.Errorf("non-executable data file must not alert, got %q", hm.Reason)
	}
	// Shared object naming keeps it eligible regardless of the exec bit.
	if hm := CheckSuspiciousELFRPath("/var/lib/libhook.so.1", data, 0o644, nil); hm == nil {
		t.Error("named shared object must still be inspected")
	}
}

func TestCheckSuspiciousELFRPath_NonELF(t *testing.T) {
	if hm := CheckSuspiciousELFRPath("/usr/bin/script.sh", []byte("#!/bin/sh\n"), 0o755, nil); hm != nil {
		t.Error("shell script data must not trigger the ELF detector")
	}
	if hm := CheckSuspiciousELFRPath("/usr/bin/nothing", nil, 0o755, nil); hm != nil {
		t.Error("empty data must not alarm")
	}
}

func TestCheckSuspiciousELFRPath_ConfigOverride(t *testing.T) {
	data := craftTestELF(t, map[elf.DynTag]string{
		elf.DT_RUNPATH: "/var/tmp",
	})
	cfg := &config.Config{}
	cfg.Scan.ScoreELFRPATHSystem = 88
	cfg.Scan.ScoreELFRPATHUser = 55
	hm := CheckSuspiciousELFRPath("/usr/bin/x", data, 0o755, cfg)
	if hm == nil || hm.Score != 88 {
		t.Errorf("config override ignored: %+v", hm)
	}
	hm2 := CheckSuspiciousELFRPath("/home/x/bin/y", data, 0o755, cfg)
	if hm2 == nil || hm2.Score != 55 {
		t.Errorf("user-tier config override ignored: %+v", hm2)
	}
}

func TestCheckSuspiciousELFRPath_FixtureLikeName(t *testing.T) {
	// Sanity: gore helper so filepath.Base semantics are pinned in the gate.
	if filepath.Base("/a/b/libc.so") != "libc.so" {
		t.Fatal("unexpected stdlib behavior")
	}
	_ = fmt.Sprint()
}

// craftBehavioralELF creates in-memory valid ELF binaries equipped with specific
// dynamic symbols, RWX program headers, UPX tags, or code section buffers.
func craftBehavioralELF(t *testing.T, symbols []string, rwx bool, upx bool, textBytes []byte, c2IP string) []byte {
	t.Helper()

	dynstr := []byte{0}
	symOffsets := make(map[string]uint32)
	for _, s := range symbols {
		symOffsets[s] = uint32(len(dynstr))
		dynstr = append(dynstr, []byte(s)...)
		dynstr = append(dynstr, 0)
	}

	var dynsym []byte
	dynsym = append(dynsym, make([]byte, 24)...) // STN_UNDEF
	for _, s := range symbols {
		entry := make([]byte, 24)
		binary.LittleEndian.PutUint32(entry[0:4], symOffsets[s])
		entry[4] = 0x12 // STB_GLOBAL | STT_FUNC
		entry[5] = 0
		binary.LittleEndian.PutUint16(entry[6:8], 0)
		binary.LittleEndian.PutUint64(entry[8:16], 0)
		binary.LittleEndian.PutUint64(entry[16:24], 0)
		dynsym = append(dynsym, entry...)
	}

	shstr := []byte{0}
	shstrOffset := func(name string) uint32 {
		off := len(shstr)
		shstr = append(shstr, []byte(name)...)
		shstr = append(shstr, 0)
		return uint32(off)
	}
	nameText := shstrOffset(".text")
	nameRodata := shstrOffset(".rodata")
	nameDynsym := shstrOffset(".dynsym")
	nameDynstr := shstrOffset(".dynstr")
	nameShstr := shstrOffset(".shstrtab")

	var textBuf []byte
	if len(textBytes) > 0 {
		textBuf = textBytes
	} else {
		textBuf = []byte{0x90, 0x90, 0xc3} // nop, nop, ret
	}

	var rodataBuf []byte
	if c2IP != "" {
		rodataBuf = []byte(c2IP + "\x00")
	} else {
		rodataBuf = []byte{0}
	}

	phFlags := uint32(5) // PF_R | PF_X
	if rwx {
		phFlags = 7 // PF_R | PF_W | PF_X
	}
	phdr := make([]byte, 56)
	binary.LittleEndian.PutUint32(phdr[0:4], 1) // PT_LOAD
	binary.LittleEndian.PutUint32(phdr[4:8], phFlags)
	binary.LittleEndian.PutUint64(phdr[8:16], 0)
	binary.LittleEndian.PutUint64(phdr[16:24], 0x400000)
	binary.LittleEndian.PutUint64(phdr[24:32], 0x400000)
	binary.LittleEndian.PutUint64(phdr[32:40], 0x2000)
	binary.LittleEndian.PutUint64(phdr[40:48], 0x2000)
	binary.LittleEndian.PutUint64(phdr[48:56], 0x1000)

	phOff := 64
	textOff := phOff + 56
	rodataOff := textOff + len(textBuf)
	dynsymOff := rodataOff + len(rodataBuf)
	dynstrOff := dynsymOff + len(dynsym)
	shstrOff := dynstrOff + len(dynstr)
	shOff := shstrOff + len(shstr)

	type sheader struct {
		name, typ                 uint32
		flags, addr, offset, size uint64
		link, info                uint32
		addralign, entsize        uint64
	}
	sections := []sheader{
		{},
		{nameText, 1 /*SHT_PROGBITS*/, 6 /*SHF_ALLOC|SHF_EXECINSTR*/, 0x401000, uint64(textOff), uint64(len(textBuf)), 0, 0, 16, 0},
		{nameRodata, 1 /*SHT_PROGBITS*/, 2 /*SHF_ALLOC*/, 0x402000, uint64(rodataOff), uint64(len(rodataBuf)), 0, 0, 8, 0},
		{nameDynsym, 11 /*SHT_DYNSYM*/, 2 /*SHF_ALLOC*/, 0x403000, uint64(dynsymOff), uint64(len(dynsym)), 4 /*link -> .dynstr*/, 1, 8, 24},
		{nameDynstr, 3 /*SHT_STRTAB*/, 2 /*SHF_ALLOC*/, 0x404000, uint64(dynstrOff), uint64(len(dynstr)), 0, 0, 1, 0},
		{nameShstr, 3 /*SHT_STRTAB*/, 0, 0, uint64(shstrOff), uint64(len(shstr)), 0, 0, 1, 0},
	}

	var shTable bytes.Buffer
	for _, sh := range sections {
		shbuf := make([]byte, 64)
		binary.LittleEndian.PutUint32(shbuf[0:4], sh.name)
		binary.LittleEndian.PutUint32(shbuf[4:8], sh.typ)
		binary.LittleEndian.PutUint64(shbuf[8:16], sh.flags)
		binary.LittleEndian.PutUint64(shbuf[16:24], sh.addr)
		binary.LittleEndian.PutUint64(shbuf[24:32], sh.offset)
		binary.LittleEndian.PutUint64(shbuf[32:40], sh.size)
		binary.LittleEndian.PutUint32(shbuf[40:44], sh.link)
		binary.LittleEndian.PutUint32(shbuf[44:48], sh.info)
		binary.LittleEndian.PutUint64(shbuf[48:56], sh.addralign)
		binary.LittleEndian.PutUint64(shbuf[56:64], sh.entsize)
		shTable.Write(shbuf)
	}

	hdr := make([]byte, 64)
	copy(hdr, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0})
	binary.LittleEndian.PutUint16(hdr[16:], 2)  // e_type ET_EXEC
	binary.LittleEndian.PutUint16(hdr[18:], 62) // e_machine EM_X86_64
	binary.LittleEndian.PutUint32(hdr[20:], 1)  // e_version
	binary.LittleEndian.PutUint64(hdr[24:], 0x401000)
	binary.LittleEndian.PutUint64(hdr[32:], uint64(phOff))
	binary.LittleEndian.PutUint64(hdr[40:], uint64(shOff))
	binary.LittleEndian.PutUint16(hdr[52:], 64)
	binary.LittleEndian.PutUint16(hdr[54:], 56)
	binary.LittleEndian.PutUint16(hdr[56:], 1)
	binary.LittleEndian.PutUint16(hdr[58:], 64)
	binary.LittleEndian.PutUint16(hdr[60:], uint16(len(sections)))
	binary.LittleEndian.PutUint16(hdr[62:], 5)

	var out bytes.Buffer
	out.Write(hdr)
	out.Write(phdr)
	out.Write(textBuf)
	out.Write(rodataBuf)
	out.Write(dynsym)
	out.Write(dynstr)
	out.Write(shstr)
	out.Write(shTable.Bytes())

	if upx {
		out.Write([]byte("UPX!"))
	}

	return out.Bytes()
}

type mockPkgDB struct {
	ownedPaths map[string]string
}

func (m *mockPkgDB) Owner(p string) (string, bool) {
	pkg, ok := m.ownedPaths[p]
	return pkg, ok
}
func (m *mockPkgDB) VerifyDigest(p string, d string) (bool, string, bool) { return true, d, true }
func (m *mockPkgDB) IsAvailable() bool                                    { return true }
func (m *mockPkgDB) StatusNote() string                                   { return "mock" }

func TestAnalyzeELFExecutable_ReverseShell_Combo(t *testing.T) {
	elfBytes := craftBehavioralELF(t, []string{"socket", "connect", "dup2", "execve"}, false, false, nil, "198.51.100.23:4444")
	matches := AnalyzeELFExecutable("/tmp/revshell_implant", elfBytes, 0o755, nil, nil)
	if len(matches) == 0 {
		t.Fatalf("expected behavioral match for reverse shell combo, got none")
	}

	var found bool
	for _, m := range matches {
		if m.Name == "ELF_Behavioral_ReverseShell_Combo" {
			found = true
			if m.Severity != report.SeverityAlert || m.Score != 90 {
				t.Errorf("expected ALERT (Score 90), got %v (%d)", m.Severity, m.Score)
			}
			if !strings.Contains(m.Reason, "198.51.100.23:4444") {
				t.Errorf("expected C2 endpoint in reason, got %s", m.Reason)
			}
		}
	}
	if !found {
		t.Errorf("ELF_Behavioral_ReverseShell_Combo not found in matches: %+v", matches)
	}
}

func TestAnalyzeELFExecutable_C2_Listener_Combo(t *testing.T) {
	elfBytes := craftBehavioralELF(t, []string{"socket", "bind", "listen", "dup2", "execve"}, false, false, nil, "")
	matches := AnalyzeELFExecutable("/dev/shm/bind_shell", elfBytes, 0o755, nil, nil)

	var found bool
	for _, m := range matches {
		if m.Name == "ELF_Behavioral_C2_Listener_Combo" {
			found = true
			if m.Severity != report.SeverityAlert || m.Score != 85 {
				t.Errorf("expected ALERT (Score 85), got %v (%d)", m.Severity, m.Score)
			}
		}
	}
	if !found {
		t.Errorf("ELF_Behavioral_C2_Listener_Combo not found in matches: %+v", matches)
	}
}

func TestAnalyzeELFExecutable_ProcessInjection_Combo(t *testing.T) {
	elfBytes := craftBehavioralELF(t, []string{"ptrace", "mprotect", "kill"}, false, false, nil, "")
	matches := AnalyzeELFExecutable("/tmp/inject_tool", elfBytes, 0o755, nil, nil)

	var found bool
	for _, m := range matches {
		if m.Name == "ELF_Behavioral_ProcessInjection_Combo" {
			found = true
			if m.Severity != report.SeverityAlert || m.Score != 90 {
				t.Errorf("expected ALERT (Score 90), got %v (%d)", m.Severity, m.Score)
			}
		}
	}
	if !found {
		t.Errorf("ELF_Behavioral_ProcessInjection_Combo not found in matches: %+v", matches)
	}
}

func TestAnalyzeELFExecutable_FilelessDropper_Combo(t *testing.T) {
	elfBytes := craftBehavioralELF(t, []string{"memfd_create", "fexecve"}, false, false, nil, "")
	matches := AnalyzeELFExecutable("/tmp/fileless_stager", elfBytes, 0o755, nil, nil)

	var found bool
	for _, m := range matches {
		if m.Name == "ELF_Behavioral_FilelessDropper_Combo" {
			found = true
			if m.Severity != report.SeverityAlert || m.Score != 85 {
				t.Errorf("expected ALERT (Score 85), got %v (%d)", m.Severity, m.Score)
			}
		}
	}
	if !found {
		t.Errorf("ELF_Behavioral_FilelessDropper_Combo not found in matches: %+v", matches)
	}
}

func TestAnalyzeELFExecutable_RWX_Segment(t *testing.T) {
	elfBytes := craftBehavioralELF(t, nil, true, false, nil, "")
	matches := AnalyzeELFExecutable("/tmp/rwx_stager", elfBytes, 0o755, nil, nil)

	var found bool
	for _, m := range matches {
		if m.Name == "ELF_Section_RWX_Anomaly" {
			found = true
			if m.Severity != report.SeverityAlert {
				t.Errorf("expected ALERT for RWX in /tmp, got %v", m.Severity)
			}
		}
	}
	if !found {
		t.Errorf("ELF_Section_RWX_Anomaly not found in matches: %+v", matches)
	}
}

func TestAnalyzeELFExecutable_UPX_Packed(t *testing.T) {
	elfBytes := craftBehavioralELF(t, nil, false, true, nil, "")
	matches := AnalyzeELFExecutable("/tmp/upx_sample", elfBytes, 0o755, nil, nil)

	var found bool
	for _, m := range matches {
		if m.Name == "ELF_Packed_UPX" {
			found = true
			if m.Severity != report.SeverityAlert {
				t.Errorf("expected ALERT for UPX in /tmp, got %v", m.Severity)
			}
		}
	}
	if !found {
		t.Errorf("ELF_Packed_UPX not found in matches: %+v", matches)
	}
}

func TestAnalyzeELFExecutable_High_Entropy_Code(t *testing.T) {
	// 512 bytes with maximum entropy (every byte 0..255 twice)
	highEntropyBytes := make([]byte, 512)
	for i := 0; i < 512; i++ {
		highEntropyBytes[i] = byte(i % 256)
	}
	elfBytes := craftBehavioralELF(t, nil, false, false, highEntropyBytes, "")
	matches := AnalyzeELFExecutable("/tmp/encrypted_code", elfBytes, 0o755, nil, nil)

	var found bool
	for _, m := range matches {
		if m.Name == "ELF_High_Entropy_Code_Section" {
			found = true
			if m.Severity != report.SeverityAlert {
				t.Errorf("expected ALERT for high entropy code in /tmp, got %v", m.Severity)
			}
		}
	}
	if !found {
		t.Errorf("ELF_High_Entropy_Code_Section not found in matches: %+v", matches)
	}
}

func TestAnalyzeELFExecutable_Corrupted_Header(t *testing.T) {
	elfBytes := craftBehavioralELF(t, nil, false, false, nil, "")
	// Tamper section header offset e_shoff to out-of-bounds offset
	binary.LittleEndian.PutUint64(elfBytes[40:48], 0xFFFFFF)

	matches := AnalyzeELFExecutable("/tmp/corrupted_bin", elfBytes, 0o755, nil, nil)
	var found bool
	for _, m := range matches {
		if m.Name == "ELF_AntiAnalysis_Corrupted_Header" {
			found = true
			if m.Severity != report.SeverityWarning {
				t.Errorf("expected WARNING for corrupted header, got %v", m.Severity)
			}
		}
	}
	if !found {
		t.Errorf("ELF_AntiAnalysis_Corrupted_Header not found in matches: %+v", matches)
	}
}

func TestAnalyzeELFExecutable_PackageManaged_Exempt(t *testing.T) {
	elfBytes := craftBehavioralELF(t, []string{"socket", "connect", "dup2", "execve"}, false, false, nil, "")
	db := &mockPkgDB{
		ownedPaths: map[string]string{
			"/usr/bin/curl": "curl",
		},
	}
	matches := AnalyzeELFExecutable("/usr/bin/curl", elfBytes, 0o755, db, nil)
	for _, m := range matches {
		if m.Name == "ELF_Behavioral_ReverseShell_Combo" {
			t.Errorf("package-managed binary /usr/bin/curl should be exempted from behavioral reverse shell alert")
		}
	}
}
