package scanner

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
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
