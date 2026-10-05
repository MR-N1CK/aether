package persistence

import (
	"testing"
)

func TestExtractExecTargets_RedirectionsAndPipes(t *testing.T) {
	tests := []struct {
		name            string
		cmd             string
		wantExecTargets []string
		wantSourced     []string
	}{
		{
			name:            "tput with stdout/stderr redirection",
			cmd:             `if [ -x /usr/bin/tput ] && tput setaf 1 >&/dev/null; then`,
			wantExecTargets: []string{"tput"},
			wantSourced:     nil,
		},
		{
			name:            "redirection to dev null with space",
			cmd:             `foo > /dev/null 2>&1`,
			wantExecTargets: []string{"foo"},
			wantSourced:     nil,
		},
		{
			name:            "redirection to temporary file output",
			cmd:             `echo test > /tmp/output.txt`,
			wantExecTargets: nil, // echo is built-in
			wantSourced:     nil,
		},
		{
			name:            "python script with args and redirection",
			cmd:             `python3 /usr/local/bin/agent.py --config /etc/agent.conf > /dev/null 2>&1 &`,
			wantExecTargets: []string{"python3", "/usr/local/bin/agent.py"},
			wantSourced:     nil,
		},
		{
			name:            "sourced shell script with parameters",
			cmd:             `. "${XDG_CONFIG_HOME:-$HOME/.config}/bash_completion"`,
			wantExecTargets: nil,
			wantSourced:     []string{`${XDG_CONFIG_HOME:-$HOME/.config}/bash_completion`},
		},
		{
			name:            "chained commands with pipes",
			cmd:             `cat /etc/passwd | grep -v nologin | /usr/bin/awk -F: '{print $1}'`,
			wantExecTargets: []string{"cat", "grep", "/usr/bin/awk"},
			wantSourced:     nil,
		},
		{
			name:            "input and append redirection",
			cmd:             `/usr/bin/scanner < /dev/zero >> /var/log/audit.log 2>/dev/null`,
			wantExecTargets: []string{"/usr/bin/scanner"},
			wantSourced:     nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			execs, sourced := ExtractExecTargets(tt.cmd)
			if len(execs) != len(tt.wantExecTargets) {
				t.Fatalf("ExtractExecTargets(%q) execs = %v, want %v", tt.cmd, execs, tt.wantExecTargets)
			}
			for i, e := range execs {
				if e != tt.wantExecTargets[i] {
					t.Errorf("execs[%d] = %q, want %q", i, e, tt.wantExecTargets[i])
				}
			}

			if len(sourced) != len(tt.wantSourced) {
				t.Fatalf("ExtractExecTargets(%q) sourced = %v, want %v", tt.cmd, sourced, tt.wantSourced)
			}
			for i, s := range sourced {
				if s != tt.wantSourced[i] {
					t.Errorf("sourced[%d] = %q, want %q", i, s, tt.wantSourced[i])
				}
			}
		})
	}
}
