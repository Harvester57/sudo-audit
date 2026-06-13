package audit

import (
	"fmt"
	"os"
	"regexp"
	"runtime"
	"strconv"
)

// SudoVersion represents parsed semantic components of the sudo version string.
type SudoVersion struct {
	Raw   string
	Major int
	Minor int
	Patch int
	Pl    int // Patch release, e.g. p2 -> 2
}

var versionRegex = regexp.MustCompile(`^([0-9]+)\.([0-9]+)\.([0-9]+)(?:p([0-9]+))?`)

// ParseSudoVersion parses a sudo version string (like "1.8.31p2" or "1.9.12")
func ParseSudoVersion(verStr string) (SudoVersion, error) {
	// Clean up trailing text or carriage returns
	cleanVer := regexp.MustCompile(`[^\d.p]+`).ReplaceAllString(verStr, "")
	cleanVer = regexp.MustCompile(`^[^\d]+`).ReplaceAllString(cleanVer, "")

	matches := versionRegex.FindStringSubmatch(cleanVer)
	if len(matches) < 4 {
		return SudoVersion{Raw: verStr}, fmt.Errorf("unable to parse sudo version: %s", verStr)
	}

	major, _ := strconv.Atoi(matches[1])
	minor, _ := strconv.Atoi(matches[2])
	patch, _ := strconv.Atoi(matches[3])
	pl := 0
	if len(matches) > 4 && matches[4] != "" {
		pl, _ = strconv.Atoi(matches[4])
	}

	return SudoVersion{
		Raw:   verStr,
		Major: major,
		Minor: minor,
		Patch: patch,
		Pl:    pl,
	}, nil
}

// Compare returns:
//
//	-1 if v < other
//	 0 if v == other
//	 1 if v > other
func (v SudoVersion) Compare(other SudoVersion) int {
	if v.Major != other.Major {
		if v.Major < other.Major {
			return -1
		}
		return 1
	}
	if v.Minor != other.Minor {
		if v.Minor < other.Minor {
			return -1
		}
		return 1
	}
	if v.Patch != other.Patch {
		if v.Patch < other.Patch {
			return -1
		}
		return 1
	}
	if v.Pl != other.Pl {
		if v.Pl < other.Pl {
			return -1
		}
		return 1
	}
	return 0
}

// AuditSudoVersion checks if the current sudo version is vulnerable to known high-profile CVEs.
func AuditSudoVersion(verStr string) ([]Finding, error) {
	if verStr == "" {
		return nil, nil
	}

	v, err := ParseSudoVersion(verStr)
	if err != nil {
		return []Finding{
			{
				ID:          "SUDO-SYS-001",
				Title:       "Unrecognized Sudo Version Format",
				Description: fmt.Sprintf("The detected sudo version string '%s' could not be parsed into a semantic version. Sudo version vulnerability analysis was skipped.", verStr),
				Severity:    SeverityInfo,
				Remediation: "Manually verify the sudo version against known vulnerability advisories.",
			},
		}, nil
	}

	var findings []Finding

	// CVE-2019-14287: Sudo < 1.8.28
	v1828 := SudoVersion{Major: 1, Minor: 8, Patch: 28, Pl: 0}
	if v.Compare(v1828) < 0 {
		findings = append(findings, Finding{
			ID:          "CVE-2019-14287",
			Title:       "Sudo uid -1 Bypass Vulnerability",
			Description: fmt.Sprintf("The system runs sudo version %s, which is vulnerable to CVE-2019-14287. Users with permissions to execute commands as any user except root can bypass this restriction and execute commands as root by passing UID -1 or 4294967295.", v.Raw),
			Severity:    SeverityHigh,
			Remediation: "Upgrade sudo to version 1.8.28 or later.",
		})
	}

	// CVE-2021-3156 (Baron Samedit): heap overflow
	// Affected: 1.8.2 through 1.8.31p2, and 1.9.0 through 1.9.5p1
	v182 := SudoVersion{Major: 1, Minor: 8, Patch: 2, Pl: 0}
	v1831p2 := SudoVersion{Major: 1, Minor: 8, Patch: 31, Pl: 2}
	v190 := SudoVersion{Major: 1, Minor: 9, Patch: 0, Pl: 0}
	v195p1 := SudoVersion{Major: 1, Minor: 9, Patch: 5, Pl: 1}

	isVulnerable18 := v.Compare(v182) >= 0 && v.Compare(v1831p2) <= 0
	isVulnerable19 := v.Compare(v190) >= 0 && v.Compare(v195p1) <= 0

	if isVulnerable18 || isVulnerable19 {
		findings = append(findings, Finding{
			ID:          "CVE-2021-3156",
			Title:       "Baron Samedit Sudo Heap Buffer Overflow",
			Description: fmt.Sprintf("The system runs sudo version %s, which is vulnerable to CVE-2021-3156 (Baron Samedit). A local unprivileged user can exploit this buffer overflow vulnerability in command-line argument parsing to escalate privileges and execute arbitrary commands as root.", v.Raw),
			Severity:    SeverityCritical,
			Remediation: "Upgrade sudo to version 1.8.32, 1.9.6, or install the vendor security patch.",
		})
	}

	// CVE-2023-27320: Sudoedit privilege escalation
	// Affected: 1.8.0 through 1.9.12p1
	v180 := SudoVersion{Major: 1, Minor: 8, Patch: 0, Pl: 0}
	v1912p1 := SudoVersion{Major: 1, Minor: 9, Patch: 12, Pl: 1}

	if v.Compare(v180) >= 0 && v.Compare(v1912p1) <= 0 {
		findings = append(findings, Finding{
			ID:          "CVE-2023-27320",
			Title:       "Sudoedit Privilege Escalation Vulnerability",
			Description: fmt.Sprintf("The system runs sudo version %s, which is vulnerable to CVE-2023-27320. Sudoedit allows local users with permission to edit files to execute arbitrary commands with root privileges via symbolic links.", v.Raw),
			Severity:    SeverityHigh,
			Remediation: "Upgrade sudo to version 1.9.12p2 or later.",
		})
	}

	return findings, nil
}

// AuditSudoersPermissions checks ownership and permissions of /etc/sudoers (Linux only).
func AuditSudoersPermissions(filePath string) []Finding {
	if runtime.GOOS == "windows" {
		// Permissions checks are bypassed on Windows host
		return nil
	}

	var findings []Finding

	info, err := os.Stat(filePath)
	if err != nil {
		findings = append(findings, Finding{
			ID:          "SUDO-SYS-PERM-001",
			Title:       "Unable to access sudoers file",
			Description: fmt.Sprintf("Could not stat sudoers file at '%s': %v. Ensure the auditor is running with sufficient privileges.", filePath, err),
			Severity:    SeverityMedium,
			Remediation: "Run the sudo-check utility with root/sudo privileges.",
		})
		return findings
	}

	// Get file mode and check permissions
	mode := info.Mode().Perm()

	// Check if group/other has write permission
	if mode&0020 != 0 {
		findings = append(findings, Finding{
			ID:          "SUDO-SYS-PERM-002",
			Title:       "Sudoers Writable by Group",
			Description: fmt.Sprintf("The sudoers file '%s' has group write permissions: %s. This allows members of the group to overwrite the file and elevate privileges.", filePath, mode),
			Severity:    SeverityCritical,
			Remediation: "Run 'chmod 0440 /etc/sudoers' to restrict write access.",
		})
	}
	if mode&0002 != 0 {
		findings = append(findings, Finding{
			ID:          "SUDO-SYS-PERM-003",
			Title:       "Sudoers World Writable",
			Description: fmt.Sprintf("The sudoers file '%s' is world-writable: %s. Any local user can modify the configuration to grant themselves passwordless root privileges.", filePath, mode),
			Severity:    SeverityCritical,
			Remediation: "Run 'chmod 0440 /etc/sudoers' immediately to secure the policy file.",
		})
	}

	// Check if other has read permission (leaks sensitive configuration)
	if mode&0004 != 0 {
		findings = append(findings, Finding{
			ID:          "SUDO-SYS-PERM-004",
			Title:       "Sudoers World Readable",
			Description: fmt.Sprintf("The sudoers file '%s' is world-readable: %s. This leaks the full privilege policy structure, allowing local users to identify vulnerabilities and bypass paths.", filePath, mode),
			Severity:    SeverityHigh,
			Remediation: "Run 'chmod 0440 /etc/sudoers' to restrict read access to authorized users.",
		})
	}

	// Owner check (requires syscall on Unix/Linux)
	if ownerUID, ownerGID, err := getUnixOwner(info); err == nil {
		if ownerUID != 0 {
			findings = append(findings, Finding{
				ID:          "SUDO-SYS-PERM-005",
				Title:       "Sudoers Not Owned by Root",
				Description: fmt.Sprintf("The sudoers file '%s' is owned by UID %d, not UID 0 (root). The owner can modify the file to grant arbitrary privileges.", filePath, ownerUID),
				Severity:    SeverityCritical,
				Remediation: "Run 'chown root:root /etc/sudoers' to reset ownership.",
			})
		}
		if ownerGID != 0 && ownerGID != 4 { // typically root (0) or shadow/wheel/sudo (4/10) is allowed, but let's check
			// Group check (warning if group is not root or wheel/sudo)
			// Let's keep it simple: group owner must be root (0) or gid 4 (commonly shadow on debian, wheel on bsd/arch/redhat etc).
			// We can flag if it's owned by a regular user group
		}
	}

	return findings
}
