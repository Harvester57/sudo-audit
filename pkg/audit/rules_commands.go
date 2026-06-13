package audit

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"sudo-check/pkg/gtfobins"
)

var wildcardRegex = regexp.MustCompile(`[*?\[\]]`)

// AuditCommands runs checks on allowed user commands (User_Specs).
func AuditCommands(policy *SudoersPolicy, gtfoClient *gtfobins.Client) []Finding {
	var findings []Finding

	for _, spec := range policy.UserSpecs {
		// Represent the users list as a string
		var users []string
		for _, u := range spec.UserList {
			users = append(users, u.GetName())
		}
		usersStr := strings.Join(users, ", ")

		// Represent the hosts list as a string
		var hosts []string
		for _, h := range spec.HostList {
			hosts = append(hosts, h.GetName())
		}
		hostsStr := strings.Join(hosts, ", ")

		for _, cs := range spec.CmndSpecs {
			// Extract tags/options for this command spec
			noPasswd := false
			noExec := false
			for _, opt := range cs.Options {
				if val, ok := opt["authenticate"].(bool); ok {
					noPasswd = !val // authenticate: false means NOPASSWD
				}
				if val, ok := opt["noexec"].(bool); ok {
					noExec = val
				}
			}

			// Gather all commands, resolving any aliases if present
			var allCmdMembers []Member
			for _, cmdMember := range cs.Commands {
				allCmdMembers = append(allCmdMembers, resolveCommands(cmdMember, policy)...)
			}

			for _, cmdMember := range allCmdMembers {
				cmdStr := cmdMember.Command
				if cmdStr == "" {
					continue
				}

				// Check 1: Command Negation Bypass (e.g. !/usr/bin/passwd)
				if cmdMember.Negated {
					findings = append(findings, Finding{
						ID:          "SUDO-CMD-001",
						Title:       "Negated Command Policy",
						Description: fmt.Sprintf("The policy contains a negated command '%s' for user(s) [%s]. Sudo command negation is easily bypassed by symlinking the binary, copying it to another location, or executing it with slightly different paths/arguments.", cmdStr, usersStr),
						Severity:    SeverityHigh,
						User:        usersStr,
						Host:        hostsStr,
						Command:     cmdStr,
						Remediation: "Avoid using negated commands (!) to enforce restrictions. Instead, use a strict allowlist of permitted commands.",
					})
					continue
				}

				// Check 2: ALL Commands Allowed
				if cmdStr == "ALL" {
					sev := SeverityHigh
					title := "Full Root Privileges Allowed"
					desc := fmt.Sprintf("The policy allows user(s) [%s] to run any command (ALL) on host(s) [%s]. This grants full administrative control.", usersStr, hostsStr)
					remediation := "Restrict privileges to only the specific commands required for the user's role."
					id := "SUDO-CMD-002"

					if noPasswd {
						sev = SeverityCritical
						title = "Passwordless Full Root Privileges Allowed (NOPASSWD)"
						desc = fmt.Sprintf("The policy allows user(s) [%s] to run any command (ALL) on host(s) [%s] without a password (NOPASSWD). Any compromise of this user account leads to immediate root access.", usersStr, hostsStr)
						id = "SUDO-CMD-003"
					}

					findings = append(findings, Finding{
						ID:          id,
						Title:       title,
						Description: desc,
						Severity:    sev,
						User:        usersStr,
						Host:        hostsStr,
						Command:     cmdStr,
						Remediation: remediation,
					})
					continue
				}

				// Check 3: Wildcards in command spec (e.g., /usr/bin/cat /var/log/*)
				if wildcardRegex.MatchString(cmdStr) {
					findings = append(findings, Finding{
						ID:          "SUDO-CMD-004",
						Title:       "Wildcard in Command Definition",
						Description: fmt.Sprintf("The command '%s' allowed for user(s) [%s] contains wildcards. Arguments matching wildcards in sudoers can often be bypassed using directory traversals (e.g. '/var/log/../../etc/shadow') or injection flags.", cmdStr, usersStr),
						Severity:    SeverityMedium,
						User:        usersStr,
						Host:        hostsStr,
						Command:     cmdStr,
						Remediation: "Avoid wildcards in command paths. Use specific paths or write wrapper scripts that sanitize inputs before executing commands.",
					})
				}

				// Check 4: GTFObins Escalation Match
				// Split command to get the executable path
				parts := strings.Fields(cmdStr)
				if len(parts) == 0 {
					continue
				}
				exePath := parts[0]
				binaryName := filepath.Base(exePath)

				bypasses := gtfoClient.CheckBinary(binaryName)
				if len(bypasses) > 0 {
					// We matched a binary in GTFObins!
					for _, bypass := range bypasses {
						// Evaluate if noexec mitigates this bypass
						mitigated := false
						if noExec && (bypass.Function == "shell" || bypass.Function == "library-load" || bypass.Function == "execute") {
							mitigated = true
						}

						sev := SeverityHigh
						id := "SUDO-GTFO-001"
						title := fmt.Sprintf("Dangerous Sudo Binary allowed: %s (%s)", binaryName, bypass.Function)
						desc := fmt.Sprintf("The user(s) [%s] can run '%s' via sudo, which is known to be bypassable. The binary has a '%s' function in GTFObins which allows escaping restricted environments.", usersStr, cmdStr, bypass.Function)

						if noPasswd {
							sev = SeverityCritical
							id = "SUDO-GTFO-002"
							title = fmt.Sprintf("Passwordless Dangerous Sudo Binary allowed: %s (%s)", binaryName, bypass.Function)
							desc = fmt.Sprintf("The user(s) [%s] can run '%s' via sudo without a password (NOPASSWD) using the '%s' bypass method. This enables instant root privilege escalation.", usersStr, cmdStr, bypass.Function)
						}

						if mitigated {
							sev = SeverityLow
							id = "SUDO-GTFO-003"
							title = fmt.Sprintf("Mitigated Dangerous Sudo Binary: %s (%s)", binaryName, bypass.Function)
							desc = fmt.Sprintf("The user(s) [%s] can run '%s' via sudo, which contains a '%s' bypass. However, the rule enforces 'NOEXEC', which mitigates execution-based escape vectors.", usersStr, cmdStr, bypass.Function)
						}

						commentStr := ""
						if bypass.Comment != "" {
							commentStr = fmt.Sprintf("\nGTFObins Context: %s", bypass.Comment)
						}

						findings = append(findings, Finding{
							ID:          id,
							Title:       title,
							Description: desc + commentStr,
							Severity:    sev,
							User:        usersStr,
							Host:        hostsStr,
							Command:     cmdStr,
							Remediation: fmt.Sprintf("Remove this binary from sudoers or replace it with a wrapper script. Example exploit command:\n%s", bypass.Code),
						})
					}
				} else {
					if noPasswd {
						findings = append(findings, Finding{
							ID:          "SUDO-CMD-005",
							Title:       "Passwordless Specific Command Execution Allowed (NOPASSWD)",
							Description: fmt.Sprintf("The user(s) [%s] are permitted to run the specific command '%s' without entering a password (NOPASSWD). While restricted to this binary, any command running passwordless as root expands the local attack surface if it has undisclosed command injection or argument parsing vulnerabilities.", usersStr, cmdStr),
							Severity:    SeverityLow,
							User:        usersStr,
							Host:        hostsStr,
							Command:     cmdStr,
							Remediation: "Ensure that passwordless privileges are strictly necessary. If possible, require authentication or implement strict input sanitization inside target binary wrapper scripts.",
						})
					}
				}
			}
		}
	}

	return findings
}

// maxResolveDepth limits recursion depth when resolving command aliases to prevent
// stack overflow from circular alias definitions (e.g., ALIAS_A → ALIAS_B → ALIAS_A).
const maxResolveDepth = 10

// resolveCommands recursively resolves command aliases in the sudoers policy structure.
func resolveCommands(member Member, policy *SudoersPolicy) []Member {
	return resolveCommandsDepth(member, policy, 0)
}

func resolveCommandsDepth(member Member, policy *SudoersPolicy, depth int) []Member {
	if depth >= maxResolveDepth {
		return []Member{member}
	}
	if member.CommandAlias != "" {
		aliasName := member.CommandAlias
		if cmds, ok := policy.CommandAliases[aliasName]; ok {
			var resolved []Member
			for _, m := range cmds {
				// Inherit negation if the alias call itself was negated
				if member.Negated {
					m.Negated = !m.Negated
				}
				resolved = append(resolved, resolveCommandsDepth(m, policy, depth+1)...)
			}
			return resolved
		}
	}
	return []Member{member}
}
