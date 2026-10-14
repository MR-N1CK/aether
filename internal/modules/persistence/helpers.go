package persistence

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"aether/internal/config"
	"aether/internal/pkgdb"
	"aether/internal/report"
	"aether/internal/safeopen"
)

var (
	ErrSymlinkEscapesRoot = errors.New("symlink target escapes root filesystem boundary")
)

// SignalClass categorizes persistence anomaly indicators.
type SignalClass string

const (
	ClassExecFromTemp       SignalClass = "exec-from-temp"
	ClassDownloadAndExecute SignalClass = "download-and-execute"
	ClassReverseShell       SignalClass = "reverse-shell"
	ClassObfuscation        SignalClass = "obfuscation"
	ClassUnowned            SignalClass = "unowned"
	ClassRecentMod          SignalClass = "recent-mod"
	ClassMissingTarget      SignalClass = "missing-target"
	ClassSymlinkHijack      SignalClass = "symlink-hijack"
	ClassPrivilegeAbuse     SignalClass = "privilege-abuse"
	ClassConfigDeviation    SignalClass = "config-deviation"
)

// PersistenceSignal represents an individual heuristic detection.
type PersistenceSignal struct {
	Class                   SignalClass
	RuleName                string
	Reason                  string
	Score                   int
	Severity                report.Severity
	IsStrong                bool
	IsReverseShellPrimitive bool
	IsIOCMatch              bool
	LineNumber              int
	Snippet                 string
}

// Regular expressions for credential and key redaction
var (
	reUserPass   = regexp.MustCompile(`//[^:\s/]+:[^@\s/]+@`)
	rePassword   = regexp.MustCompile(`(?i)(password|passwd|pwd)\s*=\s*[^\s;&]+`)
	reToken      = regexp.MustCompile(`(?i)(token|bearer)\s*=\s*[^\s;&]+`)
	reSecret     = regexp.MustCompile(`(?i)(secret|api_key|apikey)\s*=\s*[^\s;&]+`)
	reCurlAuth   = regexp.MustCompile(`(?i)(curl|wget)[^;\n]*\s+-u\s+([^\s;&]+)`)
	reSSHKey     = regexp.MustCompile(`(?i)(^|\s)(-i\s+)[^\s;&]+`)
	reSSHCommand = regexp.MustCompile(`(?i)\b(ssh|scp|sftp|rsync|autossh)\b`)
)

// RedactSnippet truncates snippet to 200 characters and redacts credentials and key paths.
func RedactSnippet(s string) string {
	s = strings.TrimSpace(s)
	// Apply redactions
	s = reUserPass.ReplaceAllString(s, "//[REDACTED_AUTH]@")
	s = rePassword.ReplaceAllString(s, "$1=[REDACTED]")
	s = reToken.ReplaceAllString(s, "$1=[REDACTED]")
	s = reSecret.ReplaceAllString(s, "$1=[REDACTED]")
	s = reCurlAuth.ReplaceAllString(s, "$1 ... -u [REDACTED]")
	if reSSHCommand.MatchString(s) {
		s = reSSHKey.ReplaceAllString(s, "$1$2[REDACTED_KEY]")
	}

	// Truncate to 200 characters
	if len(s) > 200 {
		return s[:197] + "..."
	}
	return s
}

// Regex patterns for suspicious commands
var (
	// Reverse shell primitives (high-confidence, ALERT)
	reRevShellInteractive = regexp.MustCompile(`(?i)(?:bash|sh|zsh)\s+-i\s+(?:>&|>\s*&\s*|\d*>&|\d*<&\s*\d*)|(?:bash|sh|zsh)\s+.*(?:>&|>\s*&\s*)\s*/dev/tcp/|/dev/tcp/[^\s;]+\s+(?:0>&1|1>&0)|(?:\d*<>\s*/dev/tcp/[^\s;]+).*(?:0>&1|1>&0|\b(?:ba)?sh\s+-i\b)`)
	reNetcatExec          = regexp.MustCompile(`(?i)(?:nc|ncat|netcat)(?:\.traditional|\.openbsd)?\s+.*-e\s+[^\s;&]+`)
	rePythonSocketRev     = regexp.MustCompile(`(?i)python(?:\d+)?\s+-c\s+.*(?:import\s+socket|socket\.socket).*(?:dup2|subprocess|pty\.spawn|/bin/sh|/bin/bash)`)
	rePerlSocketRev       = regexp.MustCompile(`(?i)perl\s+-e\s+.*(?:use\s+Socket|IO::Socket).*(?:open|exec|/bin/sh|/bin/bash)`)

	// Bare /dev/tcp reference (e.g. wait-for-it.sh, WARNING at most, weak)
	reBareDevTCP = regexp.MustCompile(`/dev/tcp/[^\s;]+`)

	// Download and execute patterns
	reDownloadExec = regexp.MustCompile(`(?:curl|wget)\s+.*\|\s*(?:ba)?sh`)

	// Piped decode patterns
	rePipedDecode = regexp.MustCompile(`(?i)(?:base64\s+(?:-d|--decode)|xxd\s+(?:-r|-revert)|openssl\s+enc\s+(?:-d|-decode))\s*\|\s*(?:ba)?sh`)

	// Standard benign eval patterns (never flag as obfuscation)
	reBenignEval = regexp.MustCompile(`(?i)eval\s+["']?\$\((?:dircolors|pyenv\s+init|ssh-agent|starship\s+init|apt-config\s+shell|/usr/libexec/|/usr/lib/)`)

	// Obfuscation decode primitives
	reDecodePrimitives = regexp.MustCompile(`(?i)(?:base64\s+(?:-d|--decode)|xxd\s+(?:-r|-revert)|openssl\s+enc\s+(?:-d|-decode)|python(?:\d+)?\s+-c\s+.*(?:b64decode|decode)|curl\s+|wget\s+)`)

	// Tunnel and SSH rules
	reAutostartTunnelTools = regexp.MustCompile(`(?i)\b(autossh|ngrok|cloudflared|frpc|chisel)\b`)
	reSSHTunnelArgs        = regexp.MustCompile(`(?i)\bssh\b.*(?:\s-[RLDw]|\s-o\s*(?:RemoteForward|LocalForward|DynamicForward))`)
	reSocatTunnel          = regexp.MustCompile(`(?i)\bsocat\b.*(?:TCP-LISTEN|LISTEN|EXEC|SYSTEM)`)
	reInsecureSSHArgs      = regexp.MustCompile(`(?i)(?:StrictHostKeyChecking=(?:no|off)|UserKnownHostsFile=/dev/null|ExitOnForwardFailure=(?:yes|true))`)
	reSSHBaseCmd           = regexp.MustCompile(`(?i)\b(ssh|scp|sftp|autossh)\b`)
)

func tokenizeShellCommand(s string) []string {
	var tokens []string
	var cur strings.Builder
	inSingle := false
	inDouble := false
	escaped := false

	for i := 0; i < len(s); i++ {
		ch := s[i]
		if escaped {
			cur.WriteByte(ch)
			escaped = false
			continue
		}
		if ch == '\\' && !inSingle {
			escaped = true
			continue
		}
		if ch == '\'' && !inDouble {
			inSingle = !inSingle
			continue
		}
		if ch == '"' && !inSingle {
			inDouble = !inDouble
			continue
		}
		if (ch == ' ' || ch == '\t') && !inSingle && !inDouble {
			if cur.Len() > 0 {
				tokens = append(tokens, cur.String())
				cur.Reset()
			}
			continue
		}
		cur.WriteByte(ch)
	}
	if cur.Len() > 0 {
		tokens = append(tokens, cur.String())
	}
	return tokens
}

func isPseudoFile(p string) bool {
	clean := filepath.Clean(strings.TrimSpace(p))
	if clean == "/dev/null" || clean == "/dev/zero" || clean == "/dev/tty" ||
		clean == "/dev/stdin" || clean == "/dev/stdout" || clean == "/dev/stderr" ||
		clean == "/dev/random" || clean == "/dev/urandom" {
		return true
	}
	if strings.HasPrefix(clean, "/dev/fd/") || strings.HasPrefix(clean, "/dev/pts/") ||
		strings.HasPrefix(clean, "/dev/tcp/") || strings.HasPrefix(clean, "/dev/udp/") ||
		strings.HasPrefix(clean, "/proc/") || strings.HasPrefix(clean, "/sys/") {
		return true
	}
	return false
}

func isRedirectionOperator(tok string) bool {
	switch tok {
	case ">", ">>", "<", "<<", "<<<",
		"1>", "1>>", "2>", "2>>", "0<", "0<<", "0<<<",
		"&>", "&>>", ">&", "<&":
		return true
	}
	if len(tok) >= 2 && tok[0] >= '0' && tok[0] <= '9' {
		sub := tok[1:]
		if sub == ">" || sub == ">>" || sub == "<" || sub == "<<" || sub == "<<<" || sub == ">&" || sub == "<&" {
			return true
		}
	}
	return false
}

func isAttachedRedirection(tok string) bool {
	if isRedirectionOperator(tok) {
		return false
	}
	if strings.HasPrefix(tok, ">&") || strings.HasPrefix(tok, "&>") || strings.HasPrefix(tok, "&>>") || strings.HasPrefix(tok, "<&") {
		return true
	}
	if strings.HasPrefix(tok, ">") || strings.HasPrefix(tok, ">>") ||
		strings.HasPrefix(tok, "<") || strings.HasPrefix(tok, "<<") || strings.HasPrefix(tok, "<<<") {
		return true
	}
	if len(tok) >= 2 && tok[0] >= '0' && tok[0] <= '9' {
		sub := tok[1:]
		if strings.HasPrefix(sub, ">") || strings.HasPrefix(sub, "<") {
			return true
		}
	}
	return false
}

func stripRedirections(tokens []string) []string {
	var clean []string
	for i := 0; i < len(tokens); i++ {
		tok := tokens[i]
		if isRedirectionOperator(tok) {
			if i+1 < len(tokens) {
				i++
			}
			continue
		}
		if isAttachedRedirection(tok) {
			continue
		}
		clean = append(clean, tok)
	}
	return clean
}

func splitCommandOperators(s string) (commands []string, subshells []string) {
	var cur strings.Builder
	inSingle := false
	inDouble := false
	escaped := false

	for i := 0; i < len(s); i++ {
		ch := s[i]
		if escaped {
			cur.WriteByte(ch)
			escaped = false
			continue
		}
		if ch == '\\' && !inSingle {
			escaped = true
			continue
		}
		if ch == '\'' && !inDouble {
			inSingle = !inSingle
			cur.WriteByte(ch)
			continue
		}
		if ch == '"' && !inSingle {
			inDouble = !inDouble
			cur.WriteByte(ch)
			continue
		}

		// Subshells $(...) or `...`
		if !inSingle && ch == '$' && i+1 < len(s) && s[i+1] == '(' {
			depth := 1
			j := i + 2
			for j < len(s) && depth > 0 {
				if s[j] == '(' {
					depth++
				} else if s[j] == ')' {
					depth--
				}
				j++
			}
			if j-1 <= len(s) && j-1 > i+2 {
				subshells = append(subshells, s[i+2:j-1])
			}
			i = j - 1
			continue
		}
		if !inSingle && ch == '`' {
			j := i + 1
			for j < len(s) && s[j] != '`' {
				j++
			}
			if j < len(s) {
				subshells = append(subshells, s[i+1:j])
				i = j
				continue
			}
		}

		if !inSingle && !inDouble {
			if ch == ';' || ch == '\n' {
				if strings.TrimSpace(cur.String()) != "" {
					commands = append(commands, cur.String())
					cur.Reset()
				}
				continue
			}
			if ch == '|' {
				if i+1 < len(s) && (s[i+1] == '|' || s[i+1] == '&') {
					i++
				}
				if strings.TrimSpace(cur.String()) != "" {
					commands = append(commands, cur.String())
					cur.Reset()
				}
				continue
			}
			if ch == '&' {
				if i+1 < len(s) && s[i+1] == '&' {
					i++
					if strings.TrimSpace(cur.String()) != "" {
						commands = append(commands, cur.String())
						cur.Reset()
					}
					continue
				}
				// Do not split if part of &> or &>>
				if i+1 < len(s) && s[i+1] == '>' {
					cur.WriteByte(ch)
					continue
				}
				// Do not split if preceded by > or < (e.g. >&, <&, 2>&1)
				curStr := cur.String()
				if len(curStr) > 0 && (curStr[len(curStr)-1] == '>' || curStr[len(curStr)-1] == '<') {
					cur.WriteByte(ch)
					continue
				}
				// Standalone background &
				if strings.TrimSpace(cur.String()) != "" {
					commands = append(commands, cur.String())
					cur.Reset()
				}
				continue
			}
		}
		cur.WriteByte(ch)
	}
	if strings.TrimSpace(cur.String()) != "" {
		commands = append(commands, cur.String())
	}
	return commands, subshells
}

// ExtractExecTargets parses a shell command or script line and extracts
// the executable binaries/scripts (execTargets) and explicitly sourced files (sourcedFiles).
// Only the command and, for interpreters (python*, bash, sh, zsh, dash, perl, node, ruby),
// the first non-option script argument count as exec targets.
// Option values and file arguments (ssh -i/-F, --config, -o x=y, redirections) are never exec targets.
func ExtractExecTargets(cmd string) (execTargets []string, sourcedFiles []string) {
	seenExec := make(map[string]bool)
	seenSource := make(map[string]bool)

	addExec := func(p string) {
		p = strings.TrimSpace(p)
		if p != "" && !isPseudoFile(p) && !seenExec[p] {
			seenExec[p] = true
			execTargets = append(execTargets, p)
		}
	}
	addSource := func(p string) {
		p = strings.TrimSpace(p)
		if p != "" && !isPseudoFile(p) && !seenSource[p] {
			seenSource[p] = true
			sourcedFiles = append(sourcedFiles, p)
		}
	}

	var parseSegment func(seg string)
	parseSegment = func(seg string) {
		commands, subshells := splitCommandOperators(seg)
		for _, sub := range subshells {
			parseSegment(sub)
		}

		for _, cStr := range commands {
			rawTokens := tokenizeShellCommand(cStr)
			tokens := stripRedirections(rawTokens)
			if len(tokens) == 0 {
				continue
			}

			// Filter leading variable assignments
			for len(tokens) > 0 && strings.Contains(tokens[0], "=") && !strings.HasPrefix(tokens[0], "-") && !strings.HasPrefix(tokens[0], "/") && !strings.HasPrefix(tokens[0], ".") {
				tokens = tokens[1:]
			}
			if len(tokens) == 0 {
				continue
			}

			// Filter "export"
			if tokens[0] == "export" {
				tokens = tokens[1:]
				for len(tokens) > 0 && strings.Contains(tokens[0], "=") {
					tokens = tokens[1:]
				}
				if len(tokens) == 0 {
					continue
				}
			}

			// Filter shell keywords and compound command markers
			for len(tokens) > 0 {
				tok := tokens[0]
				if tok == "if" || tok == "then" || tok == "else" || tok == "elif" ||
					tok == "fi" || tok == "do" || tok == "done" || tok == "{" ||
					tok == "}" || tok == "!" || tok == "time" {
					tokens = tokens[1:]
					continue
				}
				break
			}
			if len(tokens) == 0 {
				continue
			}

			// Unwrap wrappers
			for len(tokens) > 0 {
				w := tokens[0]
				if w == "nohup" || w == "exec" || w == "builtin" {
					tokens = tokens[1:]
					continue
				}
				if w == "setsid" {
					tokens = tokens[1:]
					for len(tokens) > 0 && strings.HasPrefix(tokens[0], "-") {
						tokens = tokens[1:]
					}
					continue
				}
				if w == "env" {
					tokens = tokens[1:]
					for len(tokens) > 0 {
						t := tokens[0]
						if t == "-i" {
							tokens = tokens[1:]
						} else if t == "-u" || t == "-C" {
							if len(tokens) >= 2 {
								tokens = tokens[2:]
							} else {
								tokens = tokens[1:]
							}
						} else if strings.Contains(t, "=") && !strings.HasPrefix(t, "/") && !strings.HasPrefix(t, ".") {
							tokens = tokens[1:]
						} else if strings.HasPrefix(t, "-") {
							tokens = tokens[1:]
						} else {
							break
						}
					}
					continue
				}
				if w == "sudo" {
					tokens = tokens[1:]
					for len(tokens) > 0 && strings.HasPrefix(tokens[0], "-") {
						t := tokens[0]
						if t == "-u" || t == "-g" || t == "-h" || t == "-p" || t == "-C" {
							if len(tokens) >= 2 {
								tokens = tokens[2:]
							} else {
								tokens = tokens[1:]
							}
						} else {
							tokens = tokens[1:]
						}
					}
					continue
				}
				if w == "timeout" {
					tokens = tokens[1:]
					for len(tokens) > 0 && strings.HasPrefix(tokens[0], "-") {
						t := tokens[0]
						if t == "-k" || t == "-s" || t == "--kill-after" || t == "--signal" {
							if len(tokens) >= 2 {
								tokens = tokens[2:]
							} else {
								tokens = tokens[1:]
							}
						} else {
							tokens = tokens[1:]
						}
					}
					if len(tokens) > 0 && len(tokens[0]) > 0 && tokens[0][0] >= '0' && tokens[0][0] <= '9' {
						tokens = tokens[1:]
					}
					continue
				}
				if w == "xargs" {
					tokens = tokens[1:]
					for len(tokens) > 0 && strings.HasPrefix(tokens[0], "-") {
						tokens = tokens[1:]
					}
					continue
				}
				break
			}

			if len(tokens) == 0 {
				continue
			}

			// Sourcing
			if tokens[0] == "source" || tokens[0] == "." {
				if len(tokens) >= 2 {
					sf := strings.Trim(tokens[1], `"'`)
					if sf != "" && !strings.HasPrefix(sf, "-") {
						addSource(sf)
					}
				}
				continue
			}

			cmdName := tokens[0]
			if cmdName == "[" || cmdName == "test" || cmdName == "echo" || cmdName == "printf" || cmdName == "eval" {
				continue
			}

			addExec(cmdName)

			base := filepath.Base(cmdName)
			isInterpreter := isInterpreterOrShell(base)
			isShell := false
			switch base {
			case "sh", "bash", "zsh", "dash", "ksh", "csh", "tcsh":
				isShell = true
			}

			if isInterpreter && len(tokens) > 1 {
				for i := 1; i < len(tokens); i++ {
					arg := tokens[i]
					if arg == "-c" || arg == "-e" {
						if isShell && i+1 < len(tokens) {
							parseSegment(tokens[i+1])
						}
						break
					}
					if arg == "-m" {
						break
					}
					if strings.HasPrefix(arg, "-") {
						continue
					}
					if isRedirectionOperator(arg) || isAttachedRedirection(arg) {
						continue
					}
					// First non-option script argument
					addExec(arg)
					break
				}
			}
		}
	}

	parseSegment(cmd)
	return execTargets, sourcedFiles
}

func isInterpreterOrShell(name string) bool {
	base := filepath.Base(name)
	switch base {
	case "sh", "bash", "zsh", "dash", "ksh", "csh", "tcsh",
		"perl", "perl5", "node", "nodejs", "ruby", "env":
		return true
	}
	if strings.HasPrefix(base, "python") {
		return true
	}
	return false
}

var reShellParamDefault = regexp.MustCompile(`\$\{([a-zA-Z_][a-zA-Z0-9_]*):-([^}]+)\}`)

func normalizeShellPath(target string) string {
	target = strings.Trim(target, `"'`)
	// Replace ${VAR:-DEFAULT} with DEFAULT
	target = reShellParamDefault.ReplaceAllString(target, "$2")
	// Replace known XDG and home variables
	target = strings.ReplaceAll(target, "$XDG_CONFIG_HOME", "$HOME/.config")
	target = strings.ReplaceAll(target, "${XDG_CONFIG_HOME}", "$HOME/.config")
	target = strings.ReplaceAll(target, "$XDG_CACHE_HOME", "$HOME/.cache")
	target = strings.ReplaceAll(target, "${XDG_CACHE_HOME}", "$HOME/.cache")
	target = strings.ReplaceAll(target, "$XDG_DATA_HOME", "$HOME/.local/share")
	target = strings.ReplaceAll(target, "${XDG_DATA_HOME}", "$HOME/.local/share")
	return target
}

func analyzeHiddenPath(target string, wellKnownHidden []string) (hasUnknownHiddenDir bool, hasHiddenNoExtBinary bool, isCacheOnly bool, cleanPath string) {
	norm := normalizeShellPath(target)
	clean := filepath.Clean(norm)
	base := filepath.Base(clean)
	dir := filepath.Dir(clean)

	// Standard exempt dotfiles
	switch base {
	case ".bashrc", ".profile", ".zshrc", ".bash_profile", ".bash_logout", ".bash_aliases", ".dircolors", ".bash_completion", ".gitconfig", ".vimrc":
		return false, false, false, clean
	}

	// Check base filename: dot-prefixed with no extension is suspicious
	if strings.HasPrefix(base, ".") && base != "." && base != ".." {
		if filepath.Ext(base) == "" {
			hasHiddenNoExtBinary = true
		}
	}

	// Check directory segments
	parts := strings.Split(dir, "/")
	hasCache := false
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			continue
		}
		if strings.HasPrefix(part, ".") {
			isWk := false
			for _, wk := range wellKnownHidden {
				if part == wk {
					isWk = true
					if part == ".cache" || part == ".npm" {
						hasCache = true
					}
					break
				}
			}
			if !isWk {
				hasUnknownHiddenDir = true
			}
		}
	}

	if hasCache && !hasUnknownHiddenDir && !hasHiddenNoExtBinary {
		isCacheOnly = true
	}

	return hasUnknownHiddenDir, hasHiddenNoExtBinary, isCacheOnly, clean
}

func extractHomeDotDir(target string) string {
	clean := filepath.Clean(normalizeShellPath(target))
	if strings.HasPrefix(clean, "$HOME/") {
		parts := strings.Split(strings.TrimPrefix(clean, "$HOME/"), "/")
		if len(parts) > 0 && strings.HasPrefix(parts[0], ".") {
			return parts[0]
		}
	} else if strings.HasPrefix(clean, "${HOME}/") {
		parts := strings.Split(strings.TrimPrefix(clean, "${HOME}/"), "/")
		if len(parts) > 0 && strings.HasPrefix(parts[0], ".") {
			return parts[0]
		}
	} else if strings.HasPrefix(clean, "~/") {
		parts := strings.Split(strings.TrimPrefix(clean, "~/"), "/")
		if len(parts) > 0 && strings.HasPrefix(parts[0], ".") {
			return parts[0]
		}
	} else if strings.HasPrefix(clean, "/root/") {
		parts := strings.Split(strings.TrimPrefix(clean, "/root/"), "/")
		if len(parts) > 0 && strings.HasPrefix(parts[0], ".") {
			return parts[0]
		}
	} else if strings.HasPrefix(clean, "/home/") {
		parts := strings.Split(strings.TrimPrefix(clean, "/home/"), "/")
		if len(parts) >= 2 && strings.HasPrefix(parts[1], ".") {
			return parts[1]
		}
	}
	return ""
}

var (
	reGuardBracket  = regexp.MustCompile(`\[{1,2}\s+-[xfe]\s+["']?([^"'\s\]]+)["']?`)
	reGuardTest     = regexp.MustCompile(`\btest\s+-[xfe]\s+["']?([^"'\s;&|)]+)["']?`)
	reGuardCommandV = regexp.MustCompile(`\bcommand\s+-v\s+["']?([^"'\s;&|)]+)["']?`)
	reGuardType     = regexp.MustCompile(`\btype\s+(?:-P\s+|-[a-zA-Z]*P[a-zA-Z]*\s+)?["']?([^"'\s;&|)]+)["']?`)
	reGuardWhich    = regexp.MustCompile(`\bwhich\s+["']?([^"'\s;&|)]+)["']?`)
)

// ExtractGuardedPaths inspects a script or file content and extracts paths tested in conditional guards.
func ExtractGuardedPaths(content string) map[string]bool {
	guards := make(map[string]bool)
	add := func(p string) {
		p = strings.TrimSpace(p)
		p = strings.Trim(p, `"'`)
		if p != "" && !strings.HasPrefix(p, "$") {
			guards[p] = true
			clean := filepath.Clean(p)
			guards[clean] = true
			base := filepath.Base(clean)
			if base != "" && base != "." && base != "/" {
				guards[base] = true
			}
		}
	}

	for _, m := range reGuardBracket.FindAllStringSubmatch(content, -1) {
		if len(m) > 1 {
			add(m[1])
		}
	}
	for _, m := range reGuardTest.FindAllStringSubmatch(content, -1) {
		if len(m) > 1 {
			add(m[1])
		}
	}
	for _, m := range reGuardCommandV.FindAllStringSubmatch(content, -1) {
		if len(m) > 1 {
			add(m[1])
		}
	}
	for _, m := range reGuardType.FindAllStringSubmatch(content, -1) {
		if len(m) > 1 {
			add(m[1])
		}
	}
	for _, m := range reGuardWhich.FindAllStringSubmatch(content, -1) {
		if len(m) > 1 {
			add(m[1])
		}
	}

	return guards
}

func isPathInGuards(target string, guards map[string]bool) bool {
	if len(guards) == 0 {
		return false
	}
	cleanTarget := filepath.Clean(target)
	baseTarget := filepath.Base(cleanTarget)
	return guards[target] || guards[cleanTarget] || guards[baseTarget]
}

func isTargetSuspiciousLocation(target string) bool {
	if strings.Contains(target, "/.") || strings.HasPrefix(filepath.Base(target), ".") {
		return true
	}
	if strings.HasPrefix(target, "/tmp/") || strings.HasPrefix(target, "/var/tmp/") || strings.HasPrefix(target, "/dev/shm/") {
		return true
	}
	return false
}

// isTargetGuarded checks if target is guarded by test -x/-f/-e, [ -x/-f/-e ... ], or command -v.
// The guard must name the exact target path (or basename for command -v).
func isTargetGuarded(line, target string) bool {
	cleanTarget := filepath.Clean(target)
	baseTarget := filepath.Base(cleanTarget)

	escapedClean := regexp.QuoteMeta(cleanTarget)
	escapedRaw := regexp.QuoteMeta(strings.TrimSpace(target))
	escapedBase := regexp.QuoteMeta(baseTarget)

	var targetPattern string
	if escapedClean == escapedRaw {
		targetPattern = escapedClean
	} else {
		targetPattern = fmt.Sprintf("(?:%s|%s)", escapedClean, escapedRaw)
	}

	// 1. test -[xfe] <target>
	// e.g. test -x /path/to/target or test -x "/path/to/target"
	reTest := regexp.MustCompile(fmt.Sprintf(`\btest\s+-[xfe]\s+["']?%s["']?(?:\s|[;&|)]|$)`, targetPattern))
	if reTest.MatchString(line) {
		return true
	}

	// 2. [ -[xfe] <target> ] or [[ -[xfe] <target> ]]
	// Allow optional extra test operators inside brackets, e.g. [ -x /path -a ... ]
	reBracket := regexp.MustCompile(fmt.Sprintf(`\[{1,2}\s+-[xfe]\s+["']?%s["']?[^\]]*\]{1,2}`, targetPattern))
	if reBracket.MatchString(line) {
		return true
	}

	// 3. command -v <target> or command -v <baseTarget>
	// e.g. command -v foo or command -v /usr/bin/foo
	reCommandV := regexp.MustCompile(fmt.Sprintf(`\bcommand\s+-v\s+["']?(?:%s|%s)["']?(?:\s|[;&|)]|$)`, targetPattern, escapedBase))
	if reCommandV.MatchString(line) {
		return true
	}

	// 4. type -P / type <target>
	reType := regexp.MustCompile(fmt.Sprintf(`\btype\s+(?:-P\s+|-[a-zA-Z]*P[a-zA-Z]*\s+)?["']?(?:%s|%s)["']?(?:\s|[;&|)]|$)`, targetPattern, escapedBase))
	if reType.MatchString(line) {
		return true
	}

	// 5. which <target>
	reWhich := regexp.MustCompile(fmt.Sprintf(`\bwhich\s+["']?(?:%s|%s)["']?(?:\s|[;&|)]|$)`, targetPattern, escapedBase))
	if reWhich.MatchString(line) {
		return true
	}

	return false
}

// dedupeSlice removes duplicate and empty entries from a slice of strings.
func dedupeSlice(slice []string) []string {
	if len(slice) == 0 {
		return slice
	}
	seen := make(map[string]bool, len(slice))
	var res []string
	for _, s := range slice {
		s = strings.TrimSpace(s)
		if s != "" && !seen[s] {
			seen[s] = true
			res = append(res, s)
		}
	}
	return res
}

// CheckSuspiciousCommand inspects a shell command string for threat primitives.
func CheckSuspiciousCommand(line string, lineNum int, cfg *config.Config, rootFS string, isSystemContext bool, pkgDB pkgdb.PackageDB, fileGuardsOpt ...map[string]bool) []*PersistenceSignal {
	var fileGuards map[string]bool
	if len(fileGuardsOpt) > 0 {
		fileGuards = fileGuardsOpt[0]
	}
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return nil
	}

	var signals []*PersistenceSignal
	redacted := RedactSnippet(trimmed)

	// 1. Reverse shell primitives (can ALERT alone)
	if reRevShellInteractive.MatchString(trimmed) {
		signals = append(signals, &PersistenceSignal{
			Class:                   ClassReverseShell,
			RuleName:                "Persistence_Reverse_Shell_Primitive",
			Reason:                  "Interactive shell socket redirection (reverse shell)",
			Score:                   85,
			Severity:                report.SeverityAlert,
			IsStrong:                true,
			IsReverseShellPrimitive: true,
			LineNumber:              lineNum,
			Snippet:                 redacted,
		})
	} else if reNetcatExec.MatchString(trimmed) {
		signals = append(signals, &PersistenceSignal{
			Class:                   ClassReverseShell,
			RuleName:                "Persistence_Reverse_Shell_Primitive",
			Reason:                  "Netcat execution hook (-e) invoked",
			Score:                   85,
			Severity:                report.SeverityAlert,
			IsStrong:                true,
			IsReverseShellPrimitive: true,
			LineNumber:              lineNum,
			Snippet:                 redacted,
		})
	} else if rePythonSocketRev.MatchString(trimmed) {
		signals = append(signals, &PersistenceSignal{
			Class:                   ClassReverseShell,
			RuleName:                "Persistence_Reverse_Shell_Primitive",
			Reason:                  "Inline Python reverse shell socket with redirection",
			Score:                   85,
			Severity:                report.SeverityAlert,
			IsStrong:                true,
			IsReverseShellPrimitive: true,
			LineNumber:              lineNum,
			Snippet:                 redacted,
		})
	} else if rePerlSocketRev.MatchString(trimmed) {
		signals = append(signals, &PersistenceSignal{
			Class:                   ClassReverseShell,
			RuleName:                "Persistence_Reverse_Shell_Primitive",
			Reason:                  "Inline Perl reverse shell socket with redirection",
			Score:                   85,
			Severity:                report.SeverityAlert,
			IsStrong:                true,
			IsReverseShellPrimitive: true,
			LineNumber:              lineNum,
			Snippet:                 redacted,
		})
	} else if reBareDevTCP.MatchString(trimmed) {
		// Bare /dev/tcp reference (e.g. wait-for-it.sh): WARNING at most, weak signal
		signals = append(signals, &PersistenceSignal{
			Class:                   ClassReverseShell,
			RuleName:                "Persistence_Dev_TCP_Reference",
			Reason:                  "Reference to /dev/tcp network socket (non-interactive)",
			Score:                   55,
			Severity:                report.SeverityWarning,
			IsStrong:                false,
			IsReverseShellPrimitive: false,
			LineNumber:              lineNum,
			Snippet:                 redacted,
		})
	}

	// 2. Download and execute patterns (WARNING, strong)
	if reDownloadExec.MatchString(trimmed) {
		score := cfg.Scan.ScorePersistCronSuspiciousCmd
		if score == 0 {
			score = config.DefaultScorePersistCronSuspiciousCmd
		}
		signals = append(signals, &PersistenceSignal{
			Class:      ClassDownloadAndExecute,
			RuleName:   "Persistence_Download_And_Execute",
			Reason:     "Download piped directly into shell execution (curl/wget | sh)",
			Score:      score,
			Severity:   report.SeverityWarning,
			IsStrong:   true,
			LineNumber: lineNum,
			Snippet:    redacted,
		})
	}

	// 3. Obfuscation & Eval
	if rePipedDecode.MatchString(trimmed) {
		signals = append(signals, &PersistenceSignal{
			Class:      ClassObfuscation,
			RuleName:   "Persistence_Piped_Decode_Execute",
			Reason:     "Decoded payload piped directly into shell execution",
			Score:      75,
			Severity:   report.SeverityWarning,
			IsStrong:   true,
			LineNumber: lineNum,
			Snippet:    redacted,
		})
	} else if strings.Contains(trimmed, "eval") {
		if !reBenignEval.MatchString(trimmed) && reDecodePrimitives.MatchString(trimmed) {
			signals = append(signals, &PersistenceSignal{
				Class:      ClassObfuscation,
				RuleName:   "Persistence_Eval_Decode_Obfuscation",
				Reason:     "eval executed with decoded or downloaded payload",
				Score:      75,
				Severity:   report.SeverityWarning,
				IsStrong:   true,
				LineNumber: lineNum,
				Snippet:    redacted,
			})
		}
	}

	// 4. Tunnel & SSH Rules
	isTunnel := reAutostartTunnelTools.MatchString(trimmed) || reSSHTunnelArgs.MatchString(trimmed) || reSocatTunnel.MatchString(trimmed)
	hasInsecureSSH := reInsecureSSHArgs.MatchString(trimmed)

	if isTunnel {
		tunnelScore := cfg.Scan.ScorePersistRemoteTunnel
		if tunnelScore <= 0 {
			tunnelScore = config.DefaultScorePersistRemoteTunnel
		}
		if hasInsecureSSH {
			boost := cfg.Scan.ScorePersistRemoteTunnelBoost
			if boost <= 0 {
				boost = config.DefaultScorePersistRemoteTunnelBoost
			}
			tunnelScore += boost
		}
		if tunnelScore >= 85 {
			tunnelScore = 80 // Never ALERT alone
		}
		signals = append(signals, &PersistenceSignal{
			Class:      ClassPrivilegeAbuse,
			RuleName:   "Persistence_Autostart_Tunnel",
			Reason:     "Autostart tunnel or port forward configured",
			Score:      tunnelScore,
			Severity:   report.SeverityWarning,
			IsStrong:   true,
			LineNumber: lineNum,
			Snippet:    redacted,
		})
	} else if reSSHBaseCmd.MatchString(trimmed) && hasInsecureSSH {
		insecureScore := cfg.Scan.ScorePersistInsecureSSH
		if insecureScore <= 0 {
			insecureScore = config.DefaultScorePersistInsecureSSH
		}
		signals = append(signals, &PersistenceSignal{
			Class:      ClassConfigDeviation,
			RuleName:   "Persistence_Insecure_SSH_Options",
			Reason:     "SSH command disables host key verification (StrictHostKeyChecking=no or UserKnownHostsFile=/dev/null)",
			Score:      insecureScore,
			Severity:   report.SeverityNotice,
			IsStrong:   false,
			LineNumber: lineNum,
			Snippet:    redacted,
		})
	}

	// 5. Extract Exec Targets & Sourced Files
	execTargets, sourcedFiles := ExtractExecTargets(trimmed)

	// 6. Exec from temporary directories
	tempPrefixes := []string{"/tmp/", "/var/tmp/", "/dev/shm/"}
	hasTempExec := false

	// Check extracted exec targets first
	for _, target := range execTargets {
		for _, pfx := range tempPrefixes {
			if strings.HasPrefix(target, pfx) {
				score := cfg.Scan.ScorePersistSystemdTempExec
				if score == 0 {
					score = config.DefaultScorePersistSystemdTempExec
				}
				signals = append(signals, &PersistenceSignal{
					Class:      ClassExecFromTemp,
					RuleName:   "Persistence_Exec_From_Temp",
					Reason:     fmt.Sprintf("Executes binary or script from volatile directory (%s)", target),
					Score:      score,
					Severity:   report.SeverityWarning,
					IsStrong:   true,
					LineNumber: lineNum,
					Snippet:    redacted,
				})
				hasTempExec = true
				break
			}
		}
		if hasTempExec {
			break
		}
	}

	// Also check raw words in command line for wrapper cases
	if !hasTempExec {
		words := strings.Fields(trimmed)
		for i, word := range words {
			if strings.HasPrefix(word, ">") || strings.HasPrefix(word, "<") || strings.Contains(word, ">/") {
				continue
			}
			w := strings.Trim(word, `"'();|&`)
			if w == "" {
				continue
			}
			ext := strings.ToLower(filepath.Ext(w))
			if ext == ".log" || ext == ".pid" || ext == ".sock" || ext == ".lock" ||
				ext == ".ipc" || ext == ".tmp" || ext == ".txt" || ext == ".json" ||
				ext == ".yaml" || ext == ".yml" || ext == ".csv" || ext == ".md" ||
				ext == ".dat" || ext == ".conf" || ext == ".cfg" || ext == ".ini" ||
				strings.Contains(w, "XXXX") || strings.HasSuffix(w, "-ipc") {
				continue
			}
			if i > 0 {
				prev := strings.Trim(words[i-1], `"'()[]$`)
				if prev == "test" || prev == "[" || prev == "[[" || prev == "cat" || prev == "ls" ||
					prev == "touch" || prev == "rm" || prev == "mkdir" || prev == "echo" || prev == "grep" ||
					prev == "mktemp" || strings.Contains(prev, "mktemp") || prev == "in" || prev == "cp" ||
					prev == "mv" || prev == "chmod" || prev == "chown" || prev == "find" || prev == ">" ||
					prev == ">>" || prev == "<" || strings.HasSuffix(prev, ">") || strings.HasSuffix(prev, "<") ||
					prev == "-d" || prev == "-f" || prev == "-e" || prev == "-s" || prev == "-r" ||
					prev == "-w" || prev == "-x" || prev == "-h" || prev == "-L" || prev == "-z" || prev == "-n" {
					continue
				}
			}
			for _, pfx := range tempPrefixes {
				if strings.HasPrefix(w, pfx) {
					score := cfg.Scan.ScorePersistSystemdTempExec
					if score == 0 {
						score = config.DefaultScorePersistSystemdTempExec
					}
					signals = append(signals, &PersistenceSignal{
						Class:      ClassExecFromTemp,
						RuleName:   "Persistence_Exec_From_Temp",
						Reason:     fmt.Sprintf("Executes binary or script from volatile directory (%s)", w),
						Score:      score,
						Severity:   report.SeverityWarning,
						IsStrong:   true,
						LineNumber: lineNum,
						Snippet:    redacted,
					})
					hasTempExec = true
					break
				}
			}
			if hasTempExec {
				break
			}
		}
	}

	// 7. Hidden path execution: only for extracted exec targets and sourced files
	allTargets := append([]string{}, execTargets...)
	allTargets = append(allTargets, sourcedFiles...)

	wellKnownHidden := cfg.Scan.HomeWellKnownHiddenDirs
	if len(wellKnownHidden) == 0 {
		wellKnownHidden = config.DefaultHomeWellKnownHiddenDirs
	}

	for _, rawTarget := range allTargets {
		normTarget := normalizeShellPath(rawTarget)
		if strings.Contains(normTarget, "/.") && !strings.Contains(normTarget, "/..") {
			hasUnknownHiddenDir, hasHiddenNoExtBinary, isCacheOnly, clean := analyzeHiddenPath(normTarget, wellKnownHidden)

			if !hasUnknownHiddenDir && !hasHiddenNoExtBinary {
				if isCacheOnly {
					signals = append(signals, &PersistenceSignal{
						Class:      ClassExecFromTemp,
						RuleName:   "Persistence_Exec_From_Home_Cache_Path",
						Reason:     fmt.Sprintf("Executes script or binary from user cache directory (%s)", rawTarget),
						Score:      10,
						Severity:   report.SeverityInfo,
						IsStrong:   false,
						LineNumber: lineNum,
						Snippet:    redacted,
					})
				}
				continue
			}

			base := filepath.Base(clean)
			isHome := strings.HasPrefix(clean, "/home/") || strings.HasPrefix(clean, "/root/") || strings.HasPrefix(clean, "~/") || strings.HasPrefix(clean, "$HOME/") || strings.HasPrefix(clean, "${HOME}/")

			if isHome {
				if isSystemContext {
					signals = append(signals, &PersistenceSignal{
						Class:      ClassExecFromTemp,
						RuleName:   "Persistence_System_Exec_User_Hidden_Path",
						Reason:     fmt.Sprintf("System file executes or sources user hidden home path (%s)", rawTarget),
						Score:      70,
						Severity:   report.SeverityWarning,
						IsStrong:   true,
						LineNumber: lineNum,
						Snippet:    redacted,
					})
				} else {
					signals = append(signals, &PersistenceSignal{
						Class:      ClassExecFromTemp,
						RuleName:   "Persistence_Exec_From_Home_Hidden_Path",
						Reason:     fmt.Sprintf("Executes script or tool from hidden directory in user home (%s)", rawTarget),
						Score:      25,
						Severity:   report.SeverityNotice,
						IsStrong:   false,
						LineNumber: lineNum,
						Snippet:    redacted,
					})
				}
			} else {
				// System path outside home (/usr, /lib, /etc, /var, /opt, /dev, /run, /srv, etc.)
				isSystemHiddenTree := strings.HasPrefix(clean, "/usr/") || strings.HasPrefix(clean, "/lib") || strings.HasPrefix(clean, "/etc/")
				if !isSystemHiddenTree && strings.Contains(clean, "/.venv/") {
					// Check benign virtualenv under /opt or /srv
					hostTarget := clean
					if rootFS != "" && strings.HasPrefix(clean, "/") {
						hostTarget = filepath.Join(rootFS, strings.TrimPrefix(clean, "/"))
					}
					if st, err := os.Stat(hostTarget); err == nil {
						if (st.Mode()&0002) == 0 && !strings.HasPrefix(base, ".") {
							continue
						}
					}
				}

				signals = append(signals, &PersistenceSignal{
					Class:      ClassExecFromTemp,
					RuleName:   "Persistence_Exec_From_Hidden_Path",
					Reason:     fmt.Sprintf("Executes binary or script from hidden path (%s)", rawTarget),
					Score:      70,
					Severity:   report.SeverityWarning,
					IsStrong:   true,
					LineNumber: lineNum,
					Snippet:    redacted,
				})
			}
		}
	}

	// 8. Missing target executable check: only for exec targets and sourced files
	for _, target := range allTargets {
		if strings.HasPrefix(target, "/") {
			if strings.ContainsAny(target, "*?[]|()$<>&;") {
				continue
			}
			if isPseudoFile(target) {
				continue
			}
			ext := strings.ToLower(filepath.Ext(target))
			if ext == ".pid" || ext == ".conf" || ext == ".cfg" || ext == ".txt" ||
				ext == ".log" || ext == ".lock" || ext == ".sock" || ext == ".ipc" ||
				ext == ".json" || ext == ".yaml" || ext == ".yml" {
				continue
			}
			cleanTarget := filepath.Clean(target)
			if strings.HasPrefix(cleanTarget, "/usr/bin/env") {
				continue
			}

			// Skip package-owned files
			if pkgDB != nil && pkgDB.IsAvailable() {
				if _, ok := pkgDB.Owner(cleanTarget); ok {
					continue
				}
			}

			hostTarget := cleanTarget
			if rootFS != "" {
				hostTarget = filepath.Join(rootFS, strings.TrimPrefix(cleanTarget, "/"))
			}
			if _, err := os.Stat(hostTarget); errors.Is(err, os.ErrNotExist) {
				guarded := isTargetGuarded(trimmed, cleanTarget) || isPathInGuards(cleanTarget, fileGuards)
				if guarded && !isTargetSuspiciousLocation(cleanTarget) {
					continue
				}
				signals = append(signals, &PersistenceSignal{
					Class:      ClassMissingTarget,
					RuleName:   "Persistence_Missing_Target_File",
					Reason:     fmt.Sprintf("References non-existent executable target %s", cleanTarget),
					Score:      config.DefaultScorePersistCronMissingTarget,
					Severity:   report.SeverityNotice,
					IsStrong:   false,
					LineNumber: lineNum,
					Snippet:    redacted,
				})
			}
		}
	}

	return signals
}

// SafeResolveSymlink evaluates symlinks for virtualPath within rootFS, ensuring
// SafeResolveSymlink evaluates symlinks for virtualPath within rootFS, ensuring
// the target does not escape rootFS.
func SafeResolveSymlink(rootFS, virtualPath string) (string, bool, error) {
	_, virtPath, isSym, err := safeopen.ResolveUnderRoot(rootFS, virtualPath)
	if err != nil {
		if errors.Is(err, safeopen.ErrSymlinkEscapesRoot) {
			return virtPath, true, ErrSymlinkEscapesRoot
		}
		return virtPath, isSym, err
	}
	return virtPath, isSym, nil
}

// ResolveVirtualPath resolves symlinks in the directory hierarchy of virtPath within rootFS
// (e.g. resolving /lib/systemd/system to /usr/lib/systemd/system on merged-/usr systems)
// while preserving the base filename.
func ResolveVirtualPath(rootFS, virtPath string) string {
	cleanVirt := filepath.Clean(virtPath)
	dir := filepath.Dir(cleanVirt)
	base := filepath.Base(cleanVirt)

	resolvedHostDir, _, _, err := safeopen.ResolveUnderRoot(rootFS, dir)
	if err != nil {
		return cleanVirt
	}

	if rootFS != "" {
		cleanRoot := filepath.Clean(rootFS)
		if resolvedHostDir == cleanRoot {
			return "/" + base
		}
		if strings.HasPrefix(resolvedHostDir, cleanRoot+string(filepath.Separator)) {
			rel, err := filepath.Rel(cleanRoot, resolvedHostDir)
			if err == nil {
				return filepath.Clean("/" + strings.TrimPrefix(rel, "/") + "/" + base)
			}
		}
	} else {
		return filepath.Clean(filepath.Join(resolvedHostDir, base))
	}
	return cleanVirt
}

// SafeReadRegularFile reads a persistence file using safeopen.OpenRegularReadOnly.
// If the path is a symlink, it returns isSymlink = true.
func SafeReadRegularFile(rootFS, virtualPath string, maxBytes int64) ([]byte, bool, error) {
	cleanVirt := filepath.Clean(virtualPath)
	hostPath, _, isSymlink, err := safeopen.ResolveUnderRoot(rootFS, cleanVirt)
	if err != nil {
		if errors.Is(err, safeopen.ErrSymlinkLoop) {
			return nil, true, err
		}
		if errors.Is(err, safeopen.ErrSymlinkEscapesRoot) {
			return nil, true, ErrSymlinkEscapesRoot
		}
		return nil, isSymlink, err
	}

	lstat, err := os.Lstat(hostPath)
	if err != nil {
		return nil, isSymlink, err
	}

	if (lstat.Mode() & os.ModeSymlink) != 0 {
		return nil, true, nil
	}

	f, err := safeopen.OpenRegularReadOnly(hostPath, maxBytes)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		return nil, false, err
	}
	return data, false, nil
}

// AssessSymlink inspects a symlink for hijack risks, cross-boundary pointing, or vendor targets.
// In production (rootFS == ""), absolute targets are normal and never treated as escapes.
// User-controlled files (authorized_keys, user profiles, per-user cron/units): strong signal
// if target is outside owner's home or not owned by that user; target contents are never read.
// A symlink pointing to a package-owned file is never flagged.
// System symlinks pointing into /opt or /usr owned by root are INFO at most.
// System symlinks pointing into temp/home, world-writable, or non-root owned are WARNING (strong).
func AssessSymlink(rootFS, virtPath string, pkgDB pkgdb.PackageDB, isUserControlled bool, userHome string, fileUID uint32) *PersistenceSignal {
	cleanVirt := filepath.Clean(virtPath)
	hostDir, _, _, dErr := safeopen.ResolveUnderRoot(rootFS, filepath.Dir(cleanVirt))
	var hostPath string
	if dErr == nil {
		hostPath = filepath.Join(hostDir, filepath.Base(cleanVirt))
	} else {
		if rootFS != "" {
			hostPath = filepath.Join(rootFS, strings.TrimPrefix(cleanVirt, "/"))
		} else {
			hostPath = cleanVirt
		}
	}

	lst, err := os.Lstat(hostPath)
	if err != nil {
		return nil
	}
	if (lst.Mode() & os.ModeSymlink) == 0 {
		return nil // Not a symlink
	}

	target, err := os.Readlink(hostPath)
	if err != nil {
		return nil
	}

	if target == "/dev/null" || filepath.Clean(target) == "/dev/null" {
		return nil
	}

	var targetVirt string
	var targetHost string
	if filepath.IsAbs(target) {
		targetVirt = filepath.Clean(target)
		if rootFS != "" {
			targetHost = filepath.Join(rootFS, strings.TrimPrefix(targetVirt, "/"))
		} else {
			targetHost = targetVirt
		}
	} else {
		targetVirt = filepath.Clean(filepath.Join(filepath.Dir(cleanVirt), target))
		targetHost = filepath.Clean(filepath.Join(filepath.Dir(hostPath), target))
	}

	// 1. Boundary escape check: ONLY applies when rootFS != "" (test / fake root trees)
	if rootFS != "" {
		cleanRoot := filepath.Clean(rootFS)
		cleanedHost := filepath.Clean(targetHost)
		if cleanedHost != cleanRoot && !strings.HasPrefix(cleanedHost, cleanRoot+string(filepath.Separator)) {
			rule := "Persistence_Symlink_Escape"
			if strings.Contains(virtPath, "systemd") {
				rule = "Persistence_Systemd_Symlink_Escape"
			}
			return &PersistenceSignal{
				Class:    ClassSymlinkHijack,
				RuleName: rule,
				Reason:   fmt.Sprintf("Symlink target escapes root filesystem boundary (%s -> %s)", virtPath, target),
				Score:    85,
				Severity: report.SeverityAlert,
				IsStrong: true,
				Snippet:  target,
			}
		}
	}

	// 2. Package ownership check: package-owned target or symlink is completely benign
	if pkgDB != nil && pkgDB.IsAvailable() {
		if _, ok := pkgDB.Owner(targetVirt); ok {
			return nil
		}
		if _, ok := pkgDB.Owner(virtPath); ok {
			return nil
		}
	}

	// 3. User-controlled files (authorized_keys, user profile, user unit)
	if isUserControlled {
		cleanHome := ""
		if userHome != "" {
			cleanHome = filepath.Clean(userHome)
		} else {
			if strings.HasPrefix(virtPath, "/home/") {
				parts := strings.Split(virtPath, "/")
				if len(parts) >= 3 {
					cleanHome = "/" + parts[1] + "/" + parts[2]
				}
			} else if strings.HasPrefix(virtPath, "/root/") {
				cleanHome = "/root"
			}
		}

		if fileUID == 0 {
			if statSys, ok := lst.Sys().(*syscall.Stat_t); ok {
				fileUID = statSys.Uid
			}
		}

		if cleanHome != "" {
			isOutsideHome := !strings.HasPrefix(targetVirt, cleanHome+"/") && targetVirt != cleanHome

			if isOutsideHome {
				isSensitive := strings.HasPrefix(targetVirt, "/etc") || strings.HasPrefix(targetVirt, "/root")
				score := 75
				sev := report.SeverityWarning
				rule := "Persistence_User_Symlink_Cross_Boundary"
				if strings.Contains(virtPath, ".ssh") {
					rule = "Persistence_SSH_Symlink_Key"
				}
				if isSensitive {
					score = 85
					sev = report.SeverityAlert
				}
				return &PersistenceSignal{
					Class:    ClassSymlinkHijack,
					RuleName: rule,
					Reason:   fmt.Sprintf("User persistence file is a symlink pointing outside owner's home directory to %s", targetVirt),
					Score:    score,
					Severity: sev,
					IsStrong: true,
					Snippet:  targetVirt,
				}
			}
		}

		// Check owner of target if within home
		tStat, tErr := os.Stat(targetHost)
		if tErr == nil {
			if statSys, ok := tStat.Sys().(*syscall.Stat_t); ok {
				if statSys.Uid != fileUID && fileUID != 0 {
					return &PersistenceSignal{
						Class:    ClassSymlinkHijack,
						RuleName: "Persistence_User_Symlink_Foreign_Owner",
						Reason:   fmt.Sprintf("User symlink points to file owned by different UID %d (%s)", statSys.Uid, targetVirt),
						Score:    75,
						Severity: report.SeverityWarning,
						IsStrong: true,
						Snippet:  targetVirt,
					}
				}
			}
		}
		return nil
	}

	// 4. System symlinks (cron, systemd, /etc/profile.d, PAM, hooks)
	tStat, tErr := os.Stat(targetHost)
	if tErr != nil {
		if os.IsNotExist(tErr) {
			return &PersistenceSignal{
				Class:    ClassMissingTarget,
				RuleName: "Persistence_System_Broken_Symlink",
				Reason:   fmt.Sprintf("System symlink points to non-existent target (%s -> %s)", virtPath, targetVirt),
				Score:    25,
				Severity: report.SeverityNotice,
				IsStrong: false,
				Snippet:  targetVirt,
			}
		}
		return nil
	}

	var targetUID uint32
	if statSys, ok := tStat.Sys().(*syscall.Stat_t); ok {
		targetUID = statSys.Uid
	}
	isRootOwned := targetUID == 0 || (rootFS != "" && targetUID == uint32(os.Geteuid()))
	isWorldWritable := (tStat.Mode() & 0002) != 0
	isVolatileOrHome := strings.HasPrefix(targetVirt, "/tmp") ||
		strings.HasPrefix(targetVirt, "/var/tmp") ||
		strings.HasPrefix(targetVirt, "/dev/shm") ||
		strings.HasPrefix(targetVirt, "/home")

	if isVolatileOrHome || isWorldWritable || !isRootOwned {
		return &PersistenceSignal{
			Class:    ClassSymlinkHijack,
			RuleName: "Persistence_System_Suspicious_Symlink",
			Reason:   fmt.Sprintf("System symlink points to volatile, world-writable, or non-root owned target (%s -> %s)", virtPath, targetVirt),
			Score:    75,
			Severity: report.SeverityWarning,
			IsStrong: true,
			Snippet:  targetVirt,
		}
	}

	// Root-owned target under /opt or /usr is normal vendor behavior
	if strings.HasPrefix(targetVirt, "/opt") || strings.HasPrefix(targetVirt, "/usr") {
		return &PersistenceSignal{
			Class:    ClassSymlinkHijack,
			RuleName: "Persistence_System_Vendor_Symlink",
			Reason:   fmt.Sprintf("System symlink points to root-owned vendor location (%s -> %s)", virtPath, targetVirt),
			Score:    10,
			Severity: report.SeverityInfo,
			IsStrong: false,
			Snippet:  targetVirt,
		}
	}

	return nil
}

// ConsolidateSignals consolidates signals for an artifact into one finding.
// Enforces accuracy rules:
// - Same-class hits count once.
// - ALERT requires strong+strong (2+ distinct strong classes), an IOC hit, or a high-confidence primitive.
// - Strong + weak = WARNING (raised score, capped below ALERT).
// - Weak only = WARNING or NOTICE (capped below 75).
func ConsolidateSignals(signals []*PersistenceSignal, virtualPath string, extraMeta map[string]any) *report.Finding {
	if len(signals) == 0 {
		return nil
	}

	// 1. Group signals by class, picking highest score per class, while tracking if class has any strong signal
	type classInfo struct {
		sig      *PersistenceSignal
		isStrong bool
	}
	byClass := make(map[SignalClass]*classInfo)
	hasRevShellPrimitive := false
	hasIOCMatch := false
	hasSymlinkEscape := false

	for _, s := range signals {
		if s.IsIOCMatch {
			hasIOCMatch = true
		}
		if s.IsReverseShellPrimitive {
			hasRevShellPrimitive = true
		}
		if s.Class == ClassSymlinkHijack && s.Score >= 85 {
			hasSymlinkEscape = true
		}

		ci, exists := byClass[s.Class]
		if !exists {
			byClass[s.Class] = &classInfo{sig: s, isStrong: s.IsStrong}
		} else {
			if s.Score > ci.sig.Score {
				ci.sig = s
			}
			if s.IsStrong {
				ci.isStrong = true
			}
		}
	}

	strongClasses := 0
	weakClasses := 0
	var reasons []string
	var ruleNames []string
	totalScore := 0

	ruleSeverities := make(map[string]string)
	for _, ci := range byClass {
		s := ci.sig
		if ci.isStrong {
			strongClasses++
		} else {
			weakClasses++
		}
		ruleNames = append(ruleNames, s.RuleName)
		ruleSeverities[s.RuleName] = s.Severity.String()
		if s.Snippet != "" {
			if s.LineNumber > 0 {
				reasons = append(reasons, fmt.Sprintf("%s (line %d: %s)", s.Reason, s.LineNumber, s.Snippet))
			} else {
				reasons = append(reasons, fmt.Sprintf("%s (%s)", s.Reason, s.Snippet))
			}
		} else {
			if s.LineNumber > 0 {
				reasons = append(reasons, fmt.Sprintf("%s (line %d)", s.Reason, s.LineNumber))
			} else {
				reasons = append(reasons, s.Reason)
			}
		}
		totalScore += s.Score
	}

	// 3. Determine final severity
	// ALERT rule: weak signals never count as corroboration.
	// A finding may be ALERT only with strong+strong, an IOC hit, or a high-confidence primitive.
	// Strong + weak = WARNING (raised score, capped below ALERT).
	var finalSeverity report.Severity
	isHighConfidence := false

	if hasIOCMatch || hasRevShellPrimitive || hasSymlinkEscape || strongClasses >= 2 {
		finalSeverity = report.SeverityAlert
		isHighConfidence = true
		if totalScore < 85 {
			totalScore = 85
		}
	} else if strongClasses >= 1 {
		finalSeverity = report.SeverityWarning
		if totalScore > 80 {
			totalScore = 80 // capped below ALERT
		}
		if totalScore < 50 {
			totalScore = 50
		}
	} else {
		// Only weak classes: never ALERT, score capped at 70
		if totalScore > 70 {
			totalScore = 70
		}
		if totalScore >= 50 {
			finalSeverity = report.SeverityWarning
		} else if totalScore >= 20 {
			finalSeverity = report.SeverityNotice
		} else {
			finalSeverity = report.SeverityInfo
		}
	}

	if totalScore > 100 {
		totalScore = 100
	}

	primaryRule := ruleNames[0]
	if len(ruleNames) > 1 {
		primaryRule = strings.Join(ruleNames, ", ")
	}

	f := report.NewFinding("persistence", finalSeverity, virtualPath, strings.Join(reasons, " | "), primaryRule)
	f.Metadata["score"] = totalScore
	f.Metadata["classes_count"] = len(byClass)
	f.Metadata["distinct_strong_classes"] = strongClasses
	f.Metadata["high_confidence"] = isHighConfidence
	f.Metadata["is_ioc_match"] = hasIOCMatch
	f.Metadata["rule_severities"] = ruleSeverities

	for k, v := range extraMeta {
		f.Metadata[k] = v
	}

	return &f
}

// ClassifyUnreadableReason returns a standardized diagnostic string for unreadable file errors.
func ClassifyUnreadableReason(err error) string {
	if err == nil {
		return ""
	}
	if os.IsNotExist(err) || errors.Is(err, safeopen.ErrVanished) || errors.Is(err, os.ErrNotExist) {
		return "does not exist"
	}
	if errors.Is(err, safeopen.ErrPermission) || os.IsPermission(err) {
		return "permission denied"
	}
	if errors.Is(err, safeopen.ErrFileTooLarge) {
		return "size cap"
	}
	if errors.Is(err, safeopen.ErrNotRegularFile) {
		return "not regular"
	}
	if errors.Is(err, ErrSymlinkEscapesRoot) || errors.Is(err, safeopen.ErrSymlinkEscapesRoot) {
		return "symlink target refused"
	}
	if errors.Is(err, safeopen.ErrSymlinkLoop) {
		return "symlink loop"
	}
	errStr := strings.ToLower(err.Error())
	if strings.Contains(errStr, "no such file") || strings.Contains(errStr, "not exist") {
		return "does not exist"
	}
	if strings.Contains(errStr, "permission denied") || strings.Contains(errStr, "access denied") {
		return "permission denied"
	}
	if strings.Contains(errStr, "not regular") {
		return "not regular"
	}
	if strings.Contains(errStr, "size") || strings.Contains(errStr, "too large") {
		return "size cap"
	}
	if strings.Contains(errStr, "symlink") {
		return "symlink target refused"
	}
	return "permission denied"
}
