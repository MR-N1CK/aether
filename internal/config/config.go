package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	ToolName                 = "aether"
	DefaultMaxFileSize       = 50 * 1024 * 1024 // 50MB
	DefaultNice              = 0
	DefaultMaxReportFindings = 5000
	DefaultFileTimeout       = 30 * time.Second
	DefaultHashOversizeMax   = 2 * 1024 * 1024 * 1024 // 2GB

	// Default heuristic score thresholds
	DefaultScoreELFInTemp             = 55 // WARNING
	DefaultScoreELFInTempEscalated    = 85 // ALERT
	DefaultScoreELFInTempNonExec      = 25 // NOTICE (owned by non-root invoking user & non-executable)
	DefaultScoreELFInDev              = 85 // ALERT
	DefaultScoreHiddenExe             = 65 // WARNING
	DefaultScoreSuspiciousSUID        = 85 // ALERT
	DefaultScoreWorldWritableEtc      = 60 // WARNING
	DefaultScoreSuspiciousPrivateKey  = 70 // WARNING
	DefaultScoreTrojanedPackageBinary = 95 // ALERT

	// ELF dynamic-section hijack thresholds
	DefaultScoreELFRPATHSystem = 90 // ALERT (RPATH/RUNPATH to volatile or world-writable dir on a system binary)
	DefaultScoreELFRPATHUser   = 65 // WARNING (same hijack pattern on a non-system binary)

	// Default process hunting score thresholds
	DefaultScoreProcDeletedExePkg    = 25 // NOTICE (package upgrade restart needed)
	DefaultScoreProcDeletedExeSusp   = 85 // ALERT (deleted from /tmp, /dev/shm, /home, etc.)
	DefaultScoreProcDeletedExeOther  = 55 // WARNING
	DefaultScoreProcExeInTemp        = 55 // WARNING
	DefaultScoreProcFilelessLow      = 15 // NOTICE
	DefaultScoreProcFilelessELF      = 55 // WARNING
	DefaultScoreProcMasquerade       = 60 // WARNING
	DefaultScoreProcRootWritable     = 70 // WARNING
	DefaultScoreProcRootNonRootOwner = 20 // NOTICE
	DefaultScoreProcHiddenPID        = 85 // ALERT
	DefaultContainerScoreReduction   = 20 // Score reduction for container processes

	// Default persistence hunting score thresholds
	DefaultScorePersistCronSuspiciousCmd = 65 // WARNING
	DefaultScorePersistCronMissingTarget = 25 // NOTICE
	DefaultScorePersistSystemdTempExec   = 70 // WARNING
	DefaultScorePersistSystemdUnowned    = 20 // NOTICE
	DefaultScorePersistRecentMtimeDays   = 3  // days
	DefaultScorePersistSSHForcedCmd      = 60 // WARNING
	DefaultScorePersistSSHNoCommentPriv  = 25 // NOTICE
	DefaultScorePersistSSHSystemNologin  = 75 // WARNING
	DefaultScorePersistSSHPerms          = 55 // WARNING
	DefaultScorePersistSSHConfig         = 25 // NOTICE
	DefaultScorePersistProfileSuspicious = 65 // WARNING
	DefaultScorePersistProfileTemp       = 70 // WARNING
	DefaultScorePersistProfileAlias      = 60 // WARNING
	DefaultScorePersistLoaderPreload     = 60 // WARNING
	DefaultScorePersistLoaderPreloadSusp = 85 // ALERT
	DefaultScorePersistPAMExec           = 75 // WARNING
	DefaultScorePersistPAMUnownedSO      = 25 // NOTICE
	DefaultScorePersistHooksSuspicious   = 65 // WARNING
	DefaultScorePersistRemoteTunnel      = 65 // WARNING
	DefaultScorePersistRemoteTunnelBoost = 10 // Boost within WARNING
	DefaultScorePersistInsecureSSH       = 25 // NOTICE
	DefaultVerdictNoticesThreshold       = 3  // 3 or more notices escalates verdict to SUSPICIOUS

	// Default YARA configuration
	DefaultYaraMaxFileSize  = 20 * 1024 * 1024  // 20MB
	DefaultYaraTimeoutMs    = 5000              // 5 seconds
	DefaultScoreYaraWarning = 40                // WARNING (weak) threshold
	DefaultScoreYaraStrong  = 75                // STRONG signal threshold
	DefaultScoreYaraAlert   = 90                // Single-match ALERT threshold
	DefaultMemoryBudget     = 256 * 1024 * 1024 // 256MB buffer memory budget
)

// DefaultHomeWellKnownHiddenDirs contains common tool caches and development directories in user home.
var DefaultHomeWellKnownHiddenDirs = []string{
	".config",
	".local",
	".cache",
	".ssh",
	".gnupg",
	".cargo",
	".rustup",
	".nvm",
	".pyenv",
	".rbenv",
	".sdkman",
	".bun",
	".deno",
	".volta",
	".asdf",
	".oh-my-zsh",
	".npm",
	".pnpm",
}

// DefaultBuildMarkers contains build file markers indicating a development source tree.
var DefaultBuildMarkers = []string{
	"Cargo.toml",
	"CMakeCache.txt",
	"go.mod",
}

// DefaultBuildOutputDirs contains directory names where build artifacts reside below a marker.
var DefaultBuildOutputDirs = []string{
	"target",
	"build",
	"deps",
	"out",
	"dist",
}

// DefaultListenerAllowlist contains standard daemon process names expected to bind network listeners.
var DefaultListenerAllowlist = []string{
	"postgres",
	"redis-server",
	"openvpn",
	"ollama",
	"tor",
	"sshd",
	"nginx",
	"apache2",
	"cupsd",
	"rpcbind",
	"dnsmasq",
	"named",
	"systemd-resolved",
}

// DefaultWeakRules returns the default list of rules considered weak for verdict escalation.
func DefaultWeakRules() []string {
	return []string{
		"Persistence_Missing_Target_File",
		"Persistence_Systemd_Unowned_Unit",
		"Persistence_InitD_Unowned_Script",
		"Persistence_RCD_Unowned_Script",
		"Persistence_Cron_Unowned_Drop",
		"Persistence_Cron_Unowned_File",
		"Persistence_Update_MOTD_Unowned_Script",
		"Persistence_Udev_Unowned_Rule",
	}
}

// ValidModules defines the recognized hunting modules for --modules flag.
var ValidModules = []string{
	"filesystem",
	"process",
	"persistence",
	"users",
	"network",
	"kernel",
}

// ValidateModules validates that all specified module names are valid.
func ValidateModules(mods []string) error {
	validMap := make(map[string]bool)
	for _, v := range ValidModules {
		validMap[v] = true
	}
	for _, m := range mods {
		m = strings.TrimSpace(m)
		if m == "" {
			continue
		}
		if !validMap[m] {
			return fmt.Errorf("unknown module %q; valid modules are: %s", m, strings.Join(ValidModules, ", "))
		}
	}
	return nil
}

// Config represents the top-level configuration for the scanner.
type Config struct {
	Scan    ScanConfig    `yaml:"scan"`
	Logging LoggingConfig `yaml:"logging"`
}

// ScanConfig holds scan targets, exclusions, and resource governance limits.
type ScanConfig struct {
	Paths              []string `yaml:"paths"`
	Root               string   `yaml:"root"`
	ExplicitPaths      bool     `yaml:"-"` // Set to true when --path is explicitly provided by the user
	Modules            []string `yaml:"modules"`
	Excludes           []string `yaml:"excludes"`
	Quick              bool     `yaml:"quick"`
	Full               bool     `yaml:"full"`
	MaxFileSize        int64    `yaml:"max_filesize"`
	Threads            int      `yaml:"threads"`
	Nice               int      `yaml:"nice"`
	JSONOut            string   `yaml:"json_out"`
	HTMLOut            string   `yaml:"html_out"`
	RedactHosts        bool     `yaml:"redact_hosts"`
	MaxReportFindings  int      `yaml:"max_report_findings"`
	IOCDir             string   `yaml:"ioc_dir"`
	IOCFile            string   `yaml:"ioc_file"`
	AllowlistPath      string   `yaml:"allowlist"`
	OneFileSystem      bool     `yaml:"one_file_system"`
	DockerLXDAllowlist []string `yaml:"docker_lxd_allowlist"`
	ListenerAllowlist  []string `yaml:"listener_allowlist"`

	// Configurable heuristic detection scores
	ScoreELFInTemp             int `yaml:"score_elf_in_temp"`
	ScoreELFInTempEscalated    int `yaml:"score_elf_in_temp_escalated"`
	ScoreELFInTempNonExec      int `yaml:"score_elf_in_temp_non_exec"`
	ScoreELFInDev              int `yaml:"score_elf_in_dev"`
	ScoreHiddenExe             int `yaml:"score_hidden_exe"`
	ScoreSuspiciousSUID        int `yaml:"score_suspicious_suid"`
	ScoreWorldWritableEtc      int `yaml:"score_world_writable_etc"`
	ScoreTrojanedPackageBinary int `yaml:"score_trojaned_package_binary"`

	// ELF dynamic-section hijack scores
	ScoreELFRPATHSystem int `yaml:"score_elf_rpath_system"`
	ScoreELFRPATHUser   int `yaml:"score_elf_rpath_user"`

	// Process hunting detection scores
	ScoreProcDeletedExePkg    int `yaml:"score_proc_deleted_exe_pkg"`
	ScoreProcDeletedExeSusp   int `yaml:"score_proc_deleted_exe_susp"`
	ScoreProcDeletedExeOther  int `yaml:"score_proc_deleted_exe_other"`
	ScoreProcExeInTemp        int `yaml:"score_proc_exe_in_temp"`
	ScoreProcFilelessLow      int `yaml:"score_proc_fileless_low"`
	ScoreProcFilelessELF      int `yaml:"score_proc_fileless_elf"`
	ScoreProcMasquerade       int `yaml:"score_proc_masquerade"`
	ScoreProcRootWritable     int `yaml:"score_proc_root_writable"`
	ScoreProcRootNonRootOwner int `yaml:"score_proc_root_non_root_owner"`
	ScoreProcHiddenPID        int `yaml:"score_proc_hidden_pid"`
	ContainerScoreReduction   int `yaml:"container_score_reduction"`

	// Persistence hunting detection scores
	ScorePersistCronSuspiciousCmd int      `yaml:"score_persist_cron_suspicious_cmd"`
	ScorePersistCronMissingTarget int      `yaml:"score_persist_cron_missing_target"`
	ScorePersistSystemdTempExec   int      `yaml:"score_persist_systemd_temp_exec"`
	ScorePersistSystemdUnowned    int      `yaml:"score_persist_systemd_unowned"`
	ScorePersistRecentMtimeDays   int      `yaml:"score_persist_recent_mtime_days"`
	ScorePersistSSHForcedCmd      int      `yaml:"score_persist_ssh_forced_cmd"`
	ScorePersistSSHNoCommentPriv  int      `yaml:"score_persist_ssh_no_comment_priv"`
	ScorePersistSSHSystemNologin  int      `yaml:"score_persist_ssh_system_nologin"`
	ScorePersistSSHPerms          int      `yaml:"score_persist_ssh_perms"`
	ScorePersistSSHConfig         int      `yaml:"score_persist_ssh_config"`
	ScorePersistProfileSuspicious int      `yaml:"score_persist_profile_suspicious"`
	ScorePersistProfileTemp       int      `yaml:"score_persist_profile_temp"`
	ScorePersistProfileAlias      int      `yaml:"score_persist_profile_alias"`
	ScorePersistLoaderPreload     int      `yaml:"score_persist_loader_preload"`
	ScorePersistLoaderPreloadSusp int      `yaml:"score_persist_loader_preload_susp"`
	ScorePersistPAMExec           int      `yaml:"score_persist_pam_exec"`
	ScorePersistPAMUnownedSO      int      `yaml:"score_persist_pam_unowned_so"`
	ScorePersistHooksSuspicious   int      `yaml:"score_persist_hooks_suspicious"`
	ScoreSuspiciousPrivateKey     int      `yaml:"score_suspicious_private_key"`
	VerdictNoticesThreshold       int      `yaml:"verdict_notices_threshold"`
	HomeWellKnownHiddenDirs       []string `yaml:"home_well_known_hidden_dirs"`
	ScorePersistRemoteTunnel      int      `yaml:"score_persist_remote_tunnel"`
	ScorePersistRemoteTunnelBoost int      `yaml:"score_persist_remote_tunnel_boost"`
	ScorePersistInsecureSSH       int      `yaml:"score_persist_insecure_ssh"`
	AcknowledgedPath              string   `yaml:"acknowledged_path"`
	TempDirs                      []string `yaml:"temp_dirs"`
	HomeDirs                      []string `yaml:"home_dirs"`
	BuildMarkers                  []string `yaml:"build_markers"`
	BuildOutputDirs               []string `yaml:"build_output_dirs"`

	// YARA Configuration
	DemoRules                  bool          `yaml:"demo_rules"`
	RulesDir                   string        `yaml:"rules_dir"`
	TrustRulesDir              bool          `yaml:"trust_rules_dir"`
	TrustInstalledPentestTools bool          `yaml:"trust_installed_pentest_tools"`
	YaraMaxFileSize            int64         `yaml:"yara_max_filesize"`
	YaraTimeoutMs              int           `yaml:"yara_timeout_ms"`
	YaraWarningScore           int           `yaml:"yara_warning_score"`
	YaraStrongScore            int           `yaml:"yara_strong_score"`
	YaraAlertScore             int           `yaml:"yara_alert_score"`
	DisabledRules              []string      `yaml:"disabled_rules"`
	DisabledTags               []string      `yaml:"disabled_tags"`
	MemoryBudgetBytes          int64         `yaml:"memory_budget_bytes"`
	FileTimeout                time.Duration `yaml:"file_timeout"`
	HashOversizeMax            int64         `yaml:"hash_oversize_max"`
	WeakRules                  []string      `yaml:"weak_rules"`
}

// LoggingConfig holds structured logging parameters.
type LoggingConfig struct {
	Level  string `yaml:"level"`  // "debug", "info", "warn", "error"
	Format string `yaml:"format"` // "text" or "json"
}

// DefaultScanPaths returns the standard fallback target paths for a default scan.
func DefaultScanPaths() []string {
	return []string{
		"/bin",
		"/sbin",
		"/usr/bin",
		"/usr/sbin",
		"/usr/local/bin",
		"/tmp",
		"/dev/shm",
		"/var/tmp",
	}
}

// QuickScanTargets returns the high-risk paths inspected during a --quick scan.
func QuickScanTargets() []string {
	return []string{
		"/tmp",
		"/var/tmp",
		"/dev/shm",
		"/etc",
		"/root",
		"/home/*/.ssh",
		"/usr/local/bin",
		"/var/www",
		"/etc/cron*",
		"/var/spool/cron",
		"/etc/systemd/system",
		"/lib/systemd/system",
	}
}

// NewDefaultConfig generates a production-ready configuration with sane Linux threat hunting defaults.
func NewDefaultConfig() *Config {
	cpus := runtime.NumCPU()
	if cpus < 1 {
		cpus = 1
	}

	return &Config{
		Scan: ScanConfig{
			Paths:         DefaultScanPaths(),
			Root:          "/",
			ExplicitPaths: false,
			Excludes: []string{
				"/proc",
				"/sys",
				"/dev/pts",
				"/run/user",
			},
			Quick:                         false,
			Full:                          false,
			MaxFileSize:                   DefaultMaxFileSize,
			Threads:                       cpus,
			Nice:                          DefaultNice,
			JSONOut:                       "",
			HTMLOut:                       "",
			RedactHosts:                   false,
			MaxReportFindings:             DefaultMaxReportFindings,
			IOCDir:                        "",
			IOCFile:                       "",
			AllowlistPath:                 "",
			OneFileSystem:                 false, // Enabled by default on --full, configurable
			ScoreELFInTemp:                DefaultScoreELFInTemp,
			ScoreELFInTempEscalated:       DefaultScoreELFInTempEscalated,
			ScoreELFInTempNonExec:         DefaultScoreELFInTempNonExec,
			ScoreELFInDev:                 DefaultScoreELFInDev,
			ScoreHiddenExe:                DefaultScoreHiddenExe,
			ScoreSuspiciousSUID:           DefaultScoreSuspiciousSUID,
			ScoreWorldWritableEtc:         DefaultScoreWorldWritableEtc,
			ScoreTrojanedPackageBinary:    DefaultScoreTrojanedPackageBinary,
			ScoreELFRPATHSystem:           DefaultScoreELFRPATHSystem,
			ScoreELFRPATHUser:             DefaultScoreELFRPATHUser,
			ScoreProcDeletedExePkg:        DefaultScoreProcDeletedExePkg,
			ScoreProcDeletedExeSusp:       DefaultScoreProcDeletedExeSusp,
			ScoreProcDeletedExeOther:      DefaultScoreProcDeletedExeOther,
			ScoreProcExeInTemp:            DefaultScoreProcExeInTemp,
			ScoreProcFilelessLow:          DefaultScoreProcFilelessLow,
			ScoreProcFilelessELF:          DefaultScoreProcFilelessELF,
			ScoreProcMasquerade:           DefaultScoreProcMasquerade,
			ScoreProcRootWritable:         DefaultScoreProcRootWritable,
			ScoreProcRootNonRootOwner:     DefaultScoreProcRootNonRootOwner,
			ScoreProcHiddenPID:            DefaultScoreProcHiddenPID,
			ContainerScoreReduction:       DefaultContainerScoreReduction,
			ScorePersistCronSuspiciousCmd: DefaultScorePersistCronSuspiciousCmd,
			ScorePersistCronMissingTarget: DefaultScorePersistCronMissingTarget,
			ScorePersistSystemdTempExec:   DefaultScorePersistSystemdTempExec,
			ScorePersistSystemdUnowned:    DefaultScorePersistSystemdUnowned,
			ScorePersistRecentMtimeDays:   DefaultScorePersistRecentMtimeDays,
			ScorePersistSSHForcedCmd:      DefaultScorePersistSSHForcedCmd,
			ScorePersistSSHNoCommentPriv:  DefaultScorePersistSSHNoCommentPriv,
			ScorePersistSSHSystemNologin:  DefaultScorePersistSSHSystemNologin,
			ScorePersistSSHPerms:          DefaultScorePersistSSHPerms,
			ScorePersistSSHConfig:         DefaultScorePersistSSHConfig,
			ScorePersistProfileSuspicious: DefaultScorePersistProfileSuspicious,
			ScorePersistProfileTemp:       DefaultScorePersistProfileTemp,
			ScorePersistProfileAlias:      DefaultScorePersistProfileAlias,
			ScorePersistLoaderPreload:     DefaultScorePersistLoaderPreload,
			ScorePersistLoaderPreloadSusp: DefaultScorePersistLoaderPreloadSusp,
			ScorePersistPAMExec:           DefaultScorePersistPAMExec,
			ScorePersistPAMUnownedSO:      DefaultScorePersistPAMUnownedSO,
			ScorePersistHooksSuspicious:   DefaultScorePersistHooksSuspicious,
			ScoreSuspiciousPrivateKey:     DefaultScoreSuspiciousPrivateKey,
			VerdictNoticesThreshold:       DefaultVerdictNoticesThreshold,
			HomeWellKnownHiddenDirs:       append([]string{}, DefaultHomeWellKnownHiddenDirs...),
			ScorePersistRemoteTunnel:      DefaultScorePersistRemoteTunnel,
			ScorePersistRemoteTunnelBoost: DefaultScorePersistRemoteTunnelBoost,
			ScorePersistInsecureSSH:       DefaultScorePersistInsecureSSH,
			AcknowledgedPath:              "",
			TempDirs:                      []string{"/tmp", "/var/tmp", "/dev/shm"},
			HomeDirs:                      []string{"/home", "/root"},
			BuildMarkers:                  append([]string{}, DefaultBuildMarkers...),
			BuildOutputDirs:               append([]string{}, DefaultBuildOutputDirs...),
			DockerLXDAllowlist:            []string{},
			ListenerAllowlist:             append([]string{}, DefaultListenerAllowlist...),
			DemoRules:                     false,
			RulesDir:                      "",
			TrustRulesDir:                 false,
			TrustInstalledPentestTools:    false,
			YaraMaxFileSize:               DefaultYaraMaxFileSize,
			YaraTimeoutMs:                 DefaultYaraTimeoutMs,
			YaraWarningScore:              DefaultScoreYaraWarning,
			YaraStrongScore:               DefaultScoreYaraStrong,
			YaraAlertScore:                DefaultScoreYaraAlert,
			DisabledRules:                 nil,
			DisabledTags:                  nil,
			MemoryBudgetBytes:             DefaultMemoryBudget,
			FileTimeout:                   DefaultFileTimeout,
			HashOversizeMax:               DefaultHashOversizeMax,
			WeakRules:                     append([]string{}, DefaultWeakRules()...),
		},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "text",
		},
	}
}

// ConfiguredRulesDirs returns all configured rules directories (custom --rules-dir if set + defaults).
func (c *ScanConfig) ConfiguredRulesDirs() []string {
	var dirs []string
	if c.RulesDir != "" {
		dirs = append(dirs, c.RulesDir)
	}
	dirs = append(dirs, DefaultRulesDirs()...)
	return dirs
}

// DefaultRulesDirs returns standard directories searched for YARA rule files:
// 1. ~/.config/aether/rules/
// 2. /etc/aether/rules/
func DefaultRulesDirs() []string {
	var dirs []string
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		dirs = append(dirs, filepath.Join(home, ".config", ToolName, "rules"))
	}
	dirs = append(dirs, filepath.Join("/etc", ToolName, "rules"))
	return dirs
}

// DefaultConfigPaths returns standard config file locations:
// 1. ~/.config/aether/config.yaml
// 2. /etc/aether/config.yaml
func DefaultConfigPaths() []string {
	var paths []string
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		paths = append(paths, filepath.Join(home, ".config", ToolName, "config.yaml"))
	}
	paths = append(paths, filepath.Join("/etc", ToolName, "config.yaml"))
	return paths
}

// DefaultIOCDirs returns standard directories searched for IOC rule files:
// 1. ~/.config/aether/iocs/
// 2. /etc/aether/iocs/
func DefaultIOCDirs() []string {
	var dirs []string
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		dirs = append(dirs, filepath.Join(home, ".config", ToolName, "iocs"))
	}
	dirs = append(dirs, filepath.Join("/etc", ToolName, "iocs"))
	return dirs
}

// LoadConfig loads the configuration hierarchy.
func LoadConfig(customPath string) (*Config, string, error) {
	cfg := NewDefaultConfig()

	if customPath != "" {
		data, err := os.ReadFile(customPath)
		if err != nil {
			return nil, "", fmt.Errorf("failed to read specified config %q: %w", customPath, err)
		}
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, "", fmt.Errorf("failed to parse yaml config %q: %w", customPath, err)
		}
		return cfg, customPath, nil
	}

	for _, p := range DefaultConfigPaths() {
		if _, err := os.Stat(p); err == nil {
			data, err := os.ReadFile(p)
			if err != nil {
				return nil, "", fmt.Errorf("failed to read config %q: %w", p, err)
			}
			if err := yaml.Unmarshal(data, cfg); err != nil {
				return nil, "", fmt.Errorf("failed to parse yaml config %q: %w", p, err)
			}
			return cfg, p, nil
		}
	}

	return cfg, "", nil
}

// ParseYAML decodes raw YAML content into a new default Config.
func ParseYAML(data []byte) (*Config, error) {
	cfg := NewDefaultConfig()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal yaml: %w", err)
	}
	return cfg, nil
}
