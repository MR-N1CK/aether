package users_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"aether/internal/config"
	"aether/internal/modules/users"
	"aether/internal/report"
)

type memoryReporter struct {
	findings []report.Finding
}

func (r *memoryReporter) Report(f report.Finding) {
	r.findings = append(r.findings, f)
}
func (r *memoryReporter) Findings() []report.Finding      { return r.findings }
func (r *memoryReporter) Summary() (int, int, int, int, int) { return 0, 0, 0, 0, 0 }
func (r *memoryReporter) Close() error                     { return nil }

func setupCleanEtc(t *testing.T) string {
	root := t.TempDir()
	etc := filepath.Join(root, "etc")
	_ = os.MkdirAll(etc, 0755)

	passwdContent := `root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
alice:x:1000:1000:Alice,,,:/home/alice:/bin/bash
bob:x:1001:1001:Bob,,,:/home/bob:/bin/zsh
`
	_ = os.WriteFile(filepath.Join(etc, "passwd"), []byte(passwdContent), 0644)

	shadowContent := `root:$6$rounds=4096$xyz$abc123hash:19000:0:99999:7:::
daemon:*:19000:0:99999:7:::
bin:*:19000:0:99999:7:::
sys:*:19000:0:99999:7:::
sync:*:19000:0:99999:7:::
games:*:19000:0:99999:7:::
nobody:*:19000:0:99999:7:::
alice:$6$rounds=4096$xyz$alicehash:19000:0:99999:7:::
bob:!$6$rounds=4096$xyz$boblocked:19000:0:99999:7:::
`
	_ = os.WriteFile(filepath.Join(etc, "shadow"), []byte(shadowContent), 0640)

	groupContent := `root:x:0:
daemon:x:1:
bin:x:2:
sys:x:3:
adm:x:4:alice
tty:x:5:
disk:x:6:
sudo:x:27:alice
docker:x:998:
alice:x:1000:
bob:x:1001:
`
	_ = os.WriteFile(filepath.Join(etc, "group"), []byte(groupContent), 0644)

	shellsContent := `/bin/sh
/bin/bash
/usr/bin/bash
/bin/zsh
/usr/bin/zsh
`
	_ = os.WriteFile(filepath.Join(etc, "shells"), []byte(shellsContent), 0644)

	return root
}

func TestUsers_CleanBaseline(t *testing.T) {
	root := setupCleanEtc(t)
	cfg := config.NewDefaultConfig()
	rep := &memoryReporter{}
	mod := users.NewModuleWithRoot(root, nil, nil, nil)

	err := mod.Run(context.Background(), cfg, rep)
	if err != nil {
		t.Fatalf("unexpected error running users module: %v", err)
	}

	for _, f := range rep.findings {
		if f.Severity == report.SeverityAlert || f.Severity == report.SeverityWarning {
			t.Errorf("unexpected WARNING or ALERT in clean baseline: %s (%s)", f.RuleName, f.Reason)
		}
	}

	cov := mod.Coverage()
	if cov.AccountsInspected != 9 {
		t.Errorf("expected 9 accounts inspected, got %d", cov.AccountsInspected)
	}
	if !cov.ShadowReadable {
		t.Errorf("expected ShadowReadable == true in test rootFS")
	}
}

func TestUsers_ExtraUID0_WarningAlone(t *testing.T) {
	root := setupCleanEtc(t)
	etc := filepath.Join(root, "etc")

	// Add extra UID 0 account 'backdoor' with a locked password and no authorized_keys
	passwdContent := `root:x:0:0:root:/root:/bin/bash
backdoor:x:0:0:Backdoor Admin:/home/backdoor:/bin/bash
alice:x:1000:1000:Alice:/home/alice:/bin/bash
`
	_ = os.WriteFile(filepath.Join(etc, "passwd"), []byte(passwdContent), 0644)

	shadowContent := `root:$6$rounds=4096$xyz$abc:19000:0:99999:7:::
backdoor:*:19000:0:99999:7:::
alice:$6$rounds=4096$xyz$alice:19000:0:99999:7:::
`
	_ = os.WriteFile(filepath.Join(etc, "shadow"), []byte(shadowContent), 0640)

	cfg := config.NewDefaultConfig()
	rep := &memoryReporter{}
	mod := users.NewModuleWithRoot(root, nil, nil, nil)

	err := mod.Run(context.Background(), cfg, rep)
	if err != nil {
		t.Fatalf("unexpected error running users module: %v", err)
	}

	var foundExtraUID0 bool
	for _, f := range rep.findings {
		if f.RuleName == "Users_Extra_UID0_Account" {
			foundExtraUID0 = true
			if f.Severity != report.SeverityWarning {
				t.Errorf("expected WARNING alone for extra UID 0, got %s", f.Severity)
			}
		}
	}
	if !foundExtraUID0 {
		t.Errorf("expected Users_Extra_UID0_Account finding for backdoor user")
	}
}

func TestUsers_ExtraUID0_AlertWithEmptyPassword(t *testing.T) {
	root := setupCleanEtc(t)
	etc := filepath.Join(root, "etc")

	passwdContent := `root:x:0:0:root:/root:/bin/bash
backdoor:x:0:0:Backdoor Admin:/home/backdoor:/bin/bash
alice:x:1000:1000:Alice:/home/alice:/bin/bash
`
	_ = os.WriteFile(filepath.Join(etc, "passwd"), []byte(passwdContent), 0644)

	// backdoor has empty password in /etc/shadow
	shadowContent := `root:$6$rounds=4096$xyz$abc:19000:0:99999:7:::
backdoor::19000:0:99999:7:::
alice:$6$rounds=4096$xyz$alice:19000:0:99999:7:::
`
	_ = os.WriteFile(filepath.Join(etc, "shadow"), []byte(shadowContent), 0640)

	cfg := config.NewDefaultConfig()
	rep := &memoryReporter{}
	mod := users.NewModuleWithRoot(root, nil, nil, nil)

	err := mod.Run(context.Background(), cfg, rep)
	if err != nil {
		t.Fatalf("unexpected error running users module: %v", err)
	}

	var foundAlert bool
	for _, f := range rep.findings {
		if f.RuleName == "Users_Extra_UID0_Account" {
			if f.Severity == report.SeverityAlert {
				foundAlert = true
			}
		}
	}
	if !foundAlert {
		t.Errorf("expected ALERT for extra UID 0 with empty shadow password")
	}
}

func TestUsers_ExtraUID0_RootHasAuthKeys_ExtraAccountDoesNot(t *testing.T) {
	root := setupCleanEtc(t)
	etc := filepath.Join(root, "etc")

	passwdContent := `root:x:0:0:root:/root:/bin/bash
backdoor:x:0:0:Backdoor Admin:/home/backdoor:/bin/bash
alice:x:1000:1000:Alice:/home/alice:/bin/bash
`
	_ = os.WriteFile(filepath.Join(etc, "passwd"), []byte(passwdContent), 0644)

	// Root has authorized_keys, but backdoor does NOT
	_ = os.MkdirAll(filepath.Join(root, "root/.ssh"), 0700)
	_ = os.WriteFile(filepath.Join(root, "root/.ssh/authorized_keys"), []byte("ssh-rsa AAAA... root@example\n"), 0600)

	shadowContent := `root:$6$rounds=4096$xyz$abc:19000:0:99999:7:::
backdoor:*:19000:0:99999:7:::
alice:$6$rounds=4096$xyz$alice:19000:0:99999:7:::
`
	_ = os.WriteFile(filepath.Join(etc, "shadow"), []byte(shadowContent), 0640)

	cfg := config.NewDefaultConfig()
	rep := &memoryReporter{}
	mod := users.NewModuleWithRoot(root, nil, nil, nil)

	err := mod.Run(context.Background(), cfg, rep)
	if err != nil {
		t.Fatalf("unexpected error running users module: %v", err)
	}

	for _, f := range rep.findings {
		if f.RuleName == "Users_Extra_UID0_Account" {
			if f.Severity != report.SeverityWarning {
				t.Errorf("expected WARNING (not ALERT) when root has authorized_keys but backdoor does not, got: %s", f.Severity)
			}
		}
	}
}

func TestUsers_ExtraUID0_AlertWithAccountAuthKeys(t *testing.T) {
	root := setupCleanEtc(t)
	etc := filepath.Join(root, "etc")

	passwdContent := `root:x:0:0:root:/root:/bin/bash
backdoor:x:0:0:Backdoor Admin:/home/backdoor:/bin/bash
alice:x:1000:1000:Alice:/home/alice:/bin/bash
`
	_ = os.WriteFile(filepath.Join(etc, "passwd"), []byte(passwdContent), 0644)

	// Backdoor has authorized_keys
	_ = os.MkdirAll(filepath.Join(root, "home/backdoor/.ssh"), 0700)
	_ = os.WriteFile(filepath.Join(root, "home/backdoor/.ssh/authorized_keys"), []byte("ssh-ed25519 AAAA... backdoor@key\n"), 0600)

	shadowContent := `root:$6$rounds=4096$xyz$abc:19000:0:99999:7:::
backdoor:*:19000:0:99999:7:::
alice:$6$rounds=4096$xyz$alice:19000:0:99999:7:::
`
	_ = os.WriteFile(filepath.Join(etc, "shadow"), []byte(shadowContent), 0640)

	cfg := config.NewDefaultConfig()
	rep := &memoryReporter{}
	mod := users.NewModuleWithRoot(root, nil, nil, nil)

	err := mod.Run(context.Background(), cfg, rep)
	if err != nil {
		t.Fatalf("unexpected error running users module: %v", err)
	}

	var foundAlert bool
	for _, f := range rep.findings {
		if f.RuleName == "Users_Extra_UID0_Account" && f.Severity == report.SeverityAlert {
			foundAlert = true
		}
	}
	if !foundAlert {
		t.Errorf("expected ALERT for extra UID 0 with its own authorized_keys")
	}
}

func TestUsers_Shadow_EmptyPasswordAndLockedAccounts(t *testing.T) {
	root := setupCleanEtc(t)
	etc := filepath.Join(root, "etc")

	shadowContent := `root:$6$rounds=4096$xyz$abc:19000:0:99999:7:::
daemon:*:19000:0:99999:7:::
bin:!:19000:0:99999:7:::
sys:!!:19000:0:99999:7:::
games:!$6$rounds=4096$xyz$lockedhash:19000:0:99999:7:::
alice::19000:0:99999:7:::
bob:$1$salt$legacyMD5Hash:19000:0:99999:7:::
`
	_ = os.WriteFile(filepath.Join(etc, "shadow"), []byte(shadowContent), 0640)

	cfg := config.NewDefaultConfig()
	rep := &memoryReporter{}
	mod := users.NewModuleWithRoot(root, nil, nil, nil)

	err := mod.Run(context.Background(), cfg, rep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var foundEmptyAlice, foundLegacyBob, foundLockedWarning bool
	for _, f := range rep.findings {
		if f.RuleName == "Users_Shadow_Empty_Password" && strings.Contains(f.Reason, "alice") {
			foundEmptyAlice = true
		}
		if f.RuleName == "Users_Shadow_Legacy_Hash_Format" && strings.Contains(f.Reason, "bob") {
			foundLegacyBob = true
		}
		if strings.Contains(f.Reason, "daemon") || strings.Contains(f.Reason, "bin") || strings.Contains(f.Reason, "sys") || strings.Contains(f.Reason, "games") {
			foundLockedWarning = true
		}
	}

	if !foundEmptyAlice {
		t.Errorf("expected Users_Shadow_Empty_Password for alice")
	}
	if !foundLegacyBob {
		t.Errorf("expected Users_Shadow_Legacy_Hash_Format for bob (MD5)")
	}
	if foundLockedWarning {
		t.Errorf("locked accounts (!, *, !!, !$) must never produce shadow findings")
	}
}

func TestUsers_SystemAccount_InteractiveShellWithTempHome(t *testing.T) {
	root := setupCleanEtc(t)
	etc := filepath.Join(root, "etc")

	// System account (UID 105) with /bin/bash and home in /tmp
	passwdContent := `root:x:0:0:root:/root:/bin/bash
systemd-coredump:x:105:105:Coredump:/tmp/coredump:/bin/bash
alice:x:1000:1000:Alice:/home/alice:/bin/bash
`
	_ = os.WriteFile(filepath.Join(etc, "passwd"), []byte(passwdContent), 0644)

	cfg := config.NewDefaultConfig()
	rep := &memoryReporter{}
	mod := users.NewModuleWithRoot(root, nil, nil, nil)

	err := mod.Run(context.Background(), cfg, rep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var foundNotice bool
	for _, f := range rep.findings {
		if f.RuleName == "Users_System_Account_Interactive_Shell" {
			foundNotice = true
			if f.Severity != report.SeverityNotice {
				t.Errorf("expected NOTICE for system account + bash + temp home, got %s", f.Severity)
			}
		}
	}
	if !foundNotice {
		t.Errorf("expected Users_System_Account_Interactive_Shell finding")
	}
}

func TestUsers_Permissions_WorldReadableShadow_And_GroupWritablePasswd(t *testing.T) {
	root := setupCleanEtc(t)
	etc := filepath.Join(root, "etc")

	// Make shadow world-readable (0644)
	_ = os.Chmod(filepath.Join(etc, "shadow"), 0644)
	// Make passwd group-writable (0664)
	_ = os.Chmod(filepath.Join(etc, "passwd"), 0664)

	cfg := config.NewDefaultConfig()
	rep := &memoryReporter{}
	mod := users.NewModuleWithRoot(root, nil, nil, nil)

	err := mod.Run(context.Background(), cfg, rep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var foundWorldShadow, foundGroupPasswd bool
	for _, f := range rep.findings {
		if f.RuleName == "Users_Shadow_Insecure_Permissions" {
			foundWorldShadow = true
			if f.Severity != report.SeverityWarning {
				t.Errorf("expected WARNING for world-readable shadow, got %s", f.Severity)
			}
		}
		if f.RuleName == "Users_Passwd_Group_Writable" {
			foundGroupPasswd = true
			if f.Severity != report.SeverityNotice {
				t.Errorf("expected NOTICE for group-writable passwd, got %s", f.Severity)
			}
		}
	}

	if !foundWorldShadow {
		t.Errorf("expected Users_Shadow_Insecure_Permissions finding")
	}
	if !foundGroupPasswd {
		t.Errorf("expected Users_Passwd_Group_Writable finding")
	}
}

func TestUsers_Groups_DockerAllowlist(t *testing.T) {
	root := setupCleanEtc(t)
	etc := filepath.Join(root, "etc")

	groupContent := `root:x:0:
sudo:x:27:alice
docker:x:998:alice,charlie
lxd:x:999:charlie
`
	_ = os.WriteFile(filepath.Join(etc, "group"), []byte(groupContent), 0644)

	// Allowlist alice for docker
	cfg := config.NewDefaultConfig()
	cfg.Scan.DockerLXDAllowlist = []string{"alice"}

	rep := &memoryReporter{}
	mod := users.NewModuleWithRoot(root, nil, nil, nil)

	err := mod.Run(context.Background(), cfg, rep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var flaggedUsers []string
	for _, f := range rep.findings {
		if f.RuleName == "Users_Container_Group_Membership" {
			u, _ := f.Metadata["username"].(string)
			flaggedUsers = append(flaggedUsers, u)
		}
	}

	// charlie should be flagged (for docker and lxd), alice should be suppressed
	foundCharlie := false
	for _, u := range flaggedUsers {
		if u == "alice" {
			t.Errorf("alice is in DockerLXDAllowlist and must not be flagged")
		}
		if u == "charlie" {
			foundCharlie = true
		}
	}
	if !foundCharlie {
		t.Errorf("expected charlie to be flagged for docker/lxd membership")
	}
}

func TestUsers_NonRoot_ShadowGapNote(t *testing.T) {
	root := setupCleanEtc(t)
	etc := filepath.Join(root, "etc")
	// Make shadow unreadable (0000) simulating non-root lack of access
	_ = os.Chmod(filepath.Join(etc, "shadow"), 0000)

	cfg := config.NewDefaultConfig()
	rep := &memoryReporter{}
	mod := users.NewModuleWithRoot(root, nil, nil, nil)

	err := mod.Run(context.Background(), cfg, rep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cov := mod.Coverage()
	if cov.ShadowReadable {
		t.Errorf("expected ShadowReadable == false for unreadable shadow")
	}
	if !cov.ShadowGapNonRoot {
		t.Errorf("expected ShadowGapNonRoot == true for unreadable shadow")
	}
}
