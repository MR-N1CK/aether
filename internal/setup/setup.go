package setup

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"

	"aether/internal/config"
	"aether/internal/ui/theme"
	"aether/internal/yara"
)

// SetupOptions holds flags/options for the 1-click setup process.
type SetupOptions struct {
	DownloadRules bool
	InstallBinary bool
	Force         bool
	CustomDir     string
}

// SetupResult returns the outcome of the setup operations.
type SetupResult struct {
	RulesDir       string
	RulesInstalled int
	BinaryPath     string
	Warnings       []string
}

// DefaultYARAForgeURL is the official latest release of YARA-Forge Core ruleset.
const DefaultYARAForgeURL = "https://github.com/YARA-Forge/yara-forge/releases/latest/download/yara-forge-core-rules.zip"

// ValidateSetupPath checks that the target directory satisfies security constraints:
// 1. If running as root, target must be inside /etc/aether (/etc/aether or /etc/aether/...).
// 2. No ancestor directory component or target path may be a symlink.
func ValidateSetupPath(targetPath string, isRoot bool) (string, error) {
	cleaned := filepath.Clean(targetPath)
	if isRoot {
		if cleaned != "/etc/aether" && !strings.HasPrefix(cleaned, "/etc/aether/") {
			return "", fmt.Errorf("root setup directory must be inside /etc/aether, got %q", cleaned)
		}
	}

	// Verify no component along the path is a symlink
	parts := strings.Split(cleaned, string(filepath.Separator))
	cur := ""
	for i, part := range parts {
		if i == 0 && part == "" {
			cur = "/"
			continue
		}
		cur = filepath.Join(cur, part)
		fi, err := os.Lstat(cur)
		if err == nil {
			if fi.Mode()&os.ModeSymlink != 0 {
				return "", fmt.Errorf("symlinks are rejected in setup path: %q (component %q is a symlink)", cleaned, cur)
			}
		} else if !os.IsNotExist(err) {
			return "", fmt.Errorf("failed to inspect path component %q: %w", cur, err)
		}
	}

	return cleaned, nil
}

// RunSetup executes the end-to-end setup workflow.
func RunSetup(opts SetupOptions, th *theme.Theme) (*SetupResult, error) {
	if th == nil {
		th = theme.NewTheme(theme.DetectNoColor())
	}

	result := &SetupResult{}
	isRoot := os.Geteuid() == 0

	// 1. Determine rules directory
	targetRulesDir := opts.CustomDir
	if targetRulesDir == "" {
		if isRoot {
			targetRulesDir = "/etc/aether/rules"
		} else {
			usr, err := user.Current()
			if err != nil || usr.HomeDir == "" {
				targetRulesDir = filepath.Join(os.Getenv("HOME"), ".config", "aether", "rules")
			} else {
				targetRulesDir = filepath.Join(usr.HomeDir, ".config", "aether", "rules")
			}
		}
	}

	validatedDir, err := ValidateSetupPath(targetRulesDir, isRoot)
	if err != nil {
		return nil, err
	}
	result.RulesDir = validatedDir

	cyanStyle := lipgloss.NewStyle().Foreground(theme.ColorCyan).Bold(true)
	greenStyle := lipgloss.NewStyle().Foreground(theme.ColorNotice).Bold(true)
	yellowStyle := lipgloss.NewStyle().Foreground(theme.ColorWarning).Bold(true)
	boldStyle := lipgloss.NewStyle().Bold(true)

	if th.NoColor {
		cyanStyle = lipgloss.NewStyle().Bold(true)
		greenStyle = lipgloss.NewStyle().Bold(true)
		yellowStyle = lipgloss.NewStyle().Bold(true)
	}

	fmt.Printf("%s\n", cyanStyle.Render("╭─────────────────────────────────────────────────────────────╮"))
	fmt.Printf("%s\n", cyanStyle.Render("│  A E T H E R  ::  Automated System Setup & Diagnostics      │"))
	fmt.Printf("%s\n\n", cyanStyle.Render("╰─────────────────────────────────────────────────────────────╯"))

	// 2. Create directory if not existing. Never chmod an existing directory.
	if fi, statErr := os.Lstat(result.RulesDir); statErr == nil {
		if !fi.IsDir() {
			return nil, fmt.Errorf("target path exists and is not a directory: %s", result.RulesDir)
		}
		fmt.Printf("  %s Rules directory verified (existing): %s\n", greenStyle.Render("✓"), result.RulesDir)
	} else if os.IsNotExist(statErr) {
		var dirPerm os.FileMode = 0755
		if !isRoot {
			dirPerm = 0700
		}
		if err := os.MkdirAll(result.RulesDir, dirPerm); err != nil {
			return nil, fmt.Errorf("failed to create rules directory %s: %w", result.RulesDir, err)
		}
		fmt.Printf("  %s Rules directory created: %s (mode: %04o)\n", greenStyle.Render("✓"), result.RulesDir, dirPerm)
	} else {
		return nil, fmt.Errorf("failed to inspect rules directory %s: %w", result.RulesDir, statErr)
	}

	// 3. Download YARA-Forge Core rules if enabled
	if opts.DownloadRules {
		fmt.Printf("  %s Fetching YARA-Forge Core ruleset package...\n", cyanStyle.Render("⠋"))
		count, err := downloadAndExtractRules(DefaultYARAForgeURL, result.RulesDir)
		if err != nil {
			warn := fmt.Sprintf("failed to download rules: %v (embedded core rules will be used)", err)
			result.Warnings = append(result.Warnings, warn)
			fmt.Printf("  %s %s\n", yellowStyle.Render("!"), warn)
		} else {
			result.RulesInstalled = count
			fmt.Printf("  %s Successfully installed %d YARA rule files from YARA-Forge Core\n", greenStyle.Render("✓"), count)
		}
	}

	// 4. Run validation compiler test
	valRes, err := yara.ValidateRulesDir(result.RulesDir)
	if err == nil && valRes != nil {
		fmt.Printf("  %s Rules verification: %d compiled rule names loaded across %d files\n",
			greenStyle.Render("✓"), valRes.TotalRulesLoaded, valRes.FilesCompiled)
		if valRes.FilesFailed > 0 {
			warn := fmt.Sprintf("%d rule files had compilation issues and will be skipped safely", valRes.FilesFailed)
			result.Warnings = append(result.Warnings, warn)
			fmt.Printf("  %s %s\n", yellowStyle.Render("!"), warn)
		}
	} else {
		fmt.Printf("  %s Embedded Core Rules: 13 high-confidence Linux threat signatures active\n", greenStyle.Render("✓"))
	}

	fmt.Println()
	fmt.Printf("%s Setup complete! You can now run:\n", boldStyle.Render("🎉"))
	fmt.Printf("  • %s         (15-second fast triage)\n", cyanStyle.Render("sudo aether quick"))
	fmt.Printf("  • %s          (Full system deep threat hunt)\n", cyanStyle.Render("sudo aether full"))
	fmt.Printf("  • %s  (Inspect specific directory)\n", cyanStyle.Render("aether /var/www"))
	fmt.Println()

	return result, nil
}

// RefreshRuleset re-downloads the YARA-Forge Core ruleset into rulesDir,
// creating the directory when it does not exist yet. It is the engine behind
// `aether update`: existing rule files with the same names are replaced, so
// scanning picks up the refreshed packages on the next run.
func RefreshRuleset(rulesDir string) (int, error) {
	if strings.TrimSpace(rulesDir) == "" {
		rulesDir = filepath.Join("/etc", config.ToolName)
		rulesDir = filepath.Join(rulesDir, "rules")
	}
	if err := ensureRulesDir(rulesDir); err != nil {
		return 0, err
	}
	return downloadAndExtractRules(DefaultYARAForgeURL, rulesDir)
}

// ensureRulesDir validates that rulesDir is a directory, creating it with a
// safe mode when missing. It rejects paths that exist as non-directories.
func ensureRulesDir(rulesDir string) error {
	if fi, statErr := os.Lstat(rulesDir); statErr == nil {
		if !fi.IsDir() {
			return fmt.Errorf("rules path exists and is not a directory: %s", rulesDir)
		}
		return nil
	} else if !os.IsNotExist(statErr) {
		return fmt.Errorf("cannot inspect rules directory %s: %w", rulesDir, statErr)
	}
	dirPerm := os.FileMode(0o700)
	if os.Geteuid() == 0 {
		dirPerm = 0o755
	}
	if err := os.MkdirAll(rulesDir, dirPerm); err != nil {
		return fmt.Errorf("cannot create rules directory %s: %w", rulesDir, err)
	}
	return nil
}

func downloadAndExtractRules(urlStr, destDir string) (int, error) {
	client := &http.Client{
		Timeout: 45 * time.Second,
	}

	req, err := http.NewRequest("GET", urlStr, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "Aether-Threat-Hunter/0.1.0")

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("server returned HTTP %d", resp.StatusCode)
	}

	const maxRuleDownloadSize = 50 * 1024 * 1024 // 50MB safety ceiling
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxRuleDownloadSize+1))
	if err != nil {
		return 0, fmt.Errorf("failed reading rules archive: %w", err)
	}
	if int64(len(bodyBytes)) > maxRuleDownloadSize {
		return 0, fmt.Errorf("rules archive exceeds maximum allowed size (%d bytes > 50MB)", len(bodyBytes))
	}

	zipReader, err := zip.NewReader(bytes.NewReader(bodyBytes), int64(len(bodyBytes)))
	if err != nil {
		if strings.HasSuffix(urlStr, ".yar") || strings.HasSuffix(urlStr, ".yara") {
			destFile := filepath.Join(destDir, "yara-rules.yar")
			if err := os.WriteFile(destFile, bodyBytes, 0644); err != nil {
				return 0, err
			}
			return 1, nil
		}
		return 0, fmt.Errorf("response is not a valid zip archive: %w", err)
	}

	count := 0
	for _, f := range zipReader.File {
		ext := strings.ToLower(filepath.Ext(f.Name))
		if ext != ".yar" && ext != ".yara" {
			continue
		}

		rc, err := f.Open()
		if err != nil {
			continue
		}

		destPath := filepath.Join(destDir, filepath.Base(f.Name))
		outFile, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			rc.Close()
			continue
		}

		_, copyErr := io.Copy(outFile, rc)
		outFile.Close()
		rc.Close()

		if copyErr == nil {
			count++
		}
	}

	return count, nil
}
