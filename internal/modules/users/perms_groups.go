package users

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strings"
	"time"

	"aether/internal/config"
	"aether/internal/report"
	"aether/internal/safeopen"
)

// CheckPermissions inspects filesystem permissions of /etc/passwd and /etc/shadow.
func CheckPermissions(rootFS string, cfg *config.Config, cov *UsersCoverage) []report.Finding {
	var findings []report.Finding

	// Check /etc/passwd
	passwdPath := "/etc/passwd"
	if hostPasswd, _, _, err := safeopen.ResolveUnderRoot(rootFS, passwdPath); err == nil {
		if fi, err := os.Stat(hostPasswd); err == nil {
			mode := fi.Mode().Perm()
			if (mode & 0002) != 0 {
				// World-writable
				findings = append(findings, report.Finding{
					Timestamp: time.Now(),
					Module:    "users",
					Severity:  report.SeverityWarning,
					Path:      passwdPath,
					Reason:    fmt.Sprintf("/etc/passwd is world-writable (permissions: 0%o)", mode),
					RuleName:  "Users_Passwd_World_Writable",
					Count:     1,
					Paths:     []string{passwdPath},
					Metadata: map[string]interface{}{
						"permissions": fmt.Sprintf("0%o", mode),
						"score":       85,
					},
				})
			} else if (mode & 0020) != 0 {
				// Group-writable
				findings = append(findings, report.Finding{
					Timestamp: time.Now(),
					Module:    "users",
					Severity:  report.SeverityNotice,
					Path:      passwdPath,
					Reason:    fmt.Sprintf("/etc/passwd is group-writable (permissions: 0%o)", mode),
					RuleName:  "Users_Passwd_Group_Writable",
					Count:     1,
					Paths:     []string{passwdPath},
					Metadata: map[string]interface{}{
						"permissions": fmt.Sprintf("0%o", mode),
						"score":       30,
					},
				})
			}
		}
	}

	// Check /etc/shadow
	shadowPath := "/etc/shadow"
	if hostShadow, _, _, err := safeopen.ResolveUnderRoot(rootFS, shadowPath); err == nil {
		if fi, err := os.Stat(hostShadow); err == nil {
			mode := fi.Mode().Perm()
			// 0640 (u=rw,g=r,o=) is standard and clean on Debian/Ubuntu/RHEL (root:shadow).
			if (mode & 0002) != 0 {
				findings = append(findings, report.Finding{
					Timestamp: time.Now(),
					Module:    "users",
					Severity:  report.SeverityWarning,
					Path:      shadowPath,
					Reason:    fmt.Sprintf("/etc/shadow is world-writable (permissions: 0%o)", mode),
					RuleName:  "Users_Shadow_World_Writable",
					Count:     1,
					Paths:     []string{shadowPath},
					Metadata: map[string]interface{}{
						"permissions": fmt.Sprintf("0%o", mode),
						"score":       85,
					},
				})
			} else if (mode & 0004) != 0 {
				findings = append(findings, report.Finding{
					Timestamp: time.Now(),
					Module:    "users",
					Severity:  report.SeverityWarning,
					Path:      shadowPath,
					Reason:    fmt.Sprintf("/etc/shadow is world-readable (permissions: 0%o)", mode),
					RuleName:  "Users_Shadow_Insecure_Permissions",
					Count:     1,
					Paths:     []string{shadowPath},
					Metadata: map[string]interface{}{
						"permissions": fmt.Sprintf("0%o", mode),
						"score":       85,
					},
				})
			}
		}
	}

	return findings
}

// CheckGroups inspects /etc/group for privileged group memberships (sudo, wheel, admin, docker, lxd).
func CheckGroups(rootFS string, cfg *config.Config, cov *UsersCoverage) []report.Finding {
	var findings []report.Finding

	groupPath := "/etc/group"
	data, err := safeopen.ReadFileReadOnlyUnderRoot(rootFS, groupPath, 1024*1024)
	if err != nil {
		return findings
	}

	dockerLXDAllowlist := make(map[string]bool)
	if cfg != nil {
		for _, a := range cfg.Scan.DockerLXDAllowlist {
			dockerLXDAllowlist[strings.TrimSpace(a)] = true
		}
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Split(line, ":")
		if len(parts) < 4 {
			continue
		}

		groupName := strings.TrimSpace(parts[0])
		membersStr := strings.TrimSpace(parts[3])
		if membersStr == "" {
			continue
		}

		members := strings.Split(membersStr, ",")
		var cleanMembers []string
		for _, m := range members {
			m = strings.TrimSpace(m)
			if m != "" {
				cleanMembers = append(cleanMembers, m)
			}
		}
		if len(cleanMembers) == 0 {
			continue
		}

		switch groupName {
		case "sudo", "wheel", "admin":
			for _, m := range cleanMembers {
				cov.PrivilegedGroupMembers = append(cov.PrivilegedGroupMembers, fmt.Sprintf("%s (%s)", m, groupName))
			}
			// Privileged group membership is INFO (listed with -v)
			findings = append(findings, report.Finding{
				Timestamp: time.Now(),
				Module:    "users",
				Severity:  report.SeverityInfo,
				Path:      groupPath,
				Reason:    fmt.Sprintf("Privileged group %q contains member(s): %s", groupName, strings.Join(cleanMembers, ", ")),
				RuleName:  "Users_Privileged_Group_Membership",
				Count:     len(cleanMembers),
				Paths:     []string{groupPath},
				Metadata: map[string]interface{}{
					"group":   groupName,
					"members": cleanMembers,
					"score":   10,
				},
			})

		case "docker", "lxd":
			for _, m := range cleanMembers {
				cov.DockerLXDMembers = append(cov.DockerLXDMembers, fmt.Sprintf("%s (%s)", m, groupName))
				if !dockerLXDAllowlist[m] {
					findings = append(findings, report.Finding{
						Timestamp: time.Now(),
						Module:    "users",
						Severity:  report.SeverityNotice,
						Path:      groupPath,
						Reason:    fmt.Sprintf("Account %q is a member of container socket group %q (root-equivalent access)", m, groupName),
						RuleName:  "Users_Container_Group_Membership",
						Count:     1,
						Paths:     []string{groupPath},
						Metadata: map[string]interface{}{
							"group":    groupName,
							"username": m,
							"score":    30,
						},
					})
				}
			}
		}
	}

	return findings
}
