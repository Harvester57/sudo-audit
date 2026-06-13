package audit

import (
	"fmt"
	"strings"
)

// AuditDefaults runs checks on global Defaults.
func AuditDefaults(policy *SudoersPolicy) []Finding {
	var findings []Finding

	// We only check global defaults (where Binding is empty)
	var globalOptions []Option
	for _, def := range policy.Defaults {
		if len(def.Binding) == 0 {
			globalOptions = append(globalOptions, def.Options...)
		}
	}

	// Helper to check if a boolean option is explicitly set to true
	isTrue := func(key string) bool {
		for _, opt := range globalOptions {
			if val, ok := opt[key].(bool); ok {
				return val
			}
		}
		return false
	}

	// Helper to check if a boolean option is explicitly set to false
	isFalse := func(key string) bool {
		for _, opt := range globalOptions {
			if val, ok := opt[key].(bool); ok {
				return !val
			}
		}
		return false
	}

	// Helper to check if an option is present at all
	hasOption := func(key string) bool {
		for _, opt := range globalOptions {
			if _, ok := opt[key]; ok {
				if _, hasOp := opt["operation"]; !hasOp {
					return true
				}
			}
		}
		return false
	}

	// Helper to get string option value
	getStringVal := func(key string) string {
		for _, opt := range globalOptions {
			if val, ok := opt[key].(string); ok {
				return val
			}
		}
		return ""
	}

	// Check 1: Missing secure_path
	if !hasOption("secure_path") {
		findings = append(findings, Finding{
			ID:          "SUDO-DEF-001",
			Title:       "Missing secure_path Configuration",
			Description: "The global 'secure_path' default is not defined. Sudo will run commands using the calling user's PATH variable, which can lead to local command hijacking/privilege escalation if the user's PATH contains writable directories.",
			Severity:    SeverityHigh,
			Remediation: "Add 'Defaults secure_path=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"' to the sudoers file.",
		})
	} else {
		securePath := getStringVal("secure_path")
		if securePath == "" {
			findings = append(findings, Finding{
				ID:          "SUDO-DEF-001",
				Title:       "Empty secure_path Configuration",
				Description: "The global 'secure_path' is defined but empty. Sudo will fallback to the user's current PATH environment, raising hijacking risks.",
				Severity:    SeverityHigh,
				Remediation: "Ensure secure_path has a set of safe directories: 'Defaults secure_path=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"'",
			})
		} else {
			// Check for relative paths or current directory '.' or empty elements in PATH
			parts := strings.Split(securePath, ":")
			for _, part := range parts {
				if part == "." || part == "" || !strings.HasPrefix(part, "/") {
					findings = append(findings, Finding{
						ID:          "SUDO-DEF-002",
						Title:       "Dangerous path in secure_path",
						Description: fmt.Sprintf("The 'secure_path' contains a relative or empty directory entry: '%s'. This can allow attackers to hijack commands if they drop a malicious binary in the relative target path.", part),
						Severity:    SeverityHigh,
						Remediation: "Only specify absolute paths in secure_path.",
					})
					break
				}
			}
		}
	}

	// Check 2: Missing use_pty
	// Sudo default for use_pty was false in older versions and might be disabled. Enabling it is highly recommended.
	if !hasOption("use_pty") || isFalse("use_pty") {
		findings = append(findings, Finding{
			ID:          "SUDO-DEF-003",
			Title:       "Missing or Disabled use_pty",
			Description: "The 'use_pty' flag is not enabled globally. Without a pseudo-terminal (PTY) allocation, processes run via sudo can write to the terminal's input buffer using TIOCSTI ioctls, enabling terminal hijacking and command injection back into the user's shell.",
			Severity:    SeverityMedium,
			Remediation: "Add 'Defaults use_pty' globally to the sudoers file.",
		})
	}

	// Check 3: Dangerous env_keep list
	dangerousEnvVars := []string{
		"LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "LD_DEBUG",
		"PYTHONPATH", "PYTHONHOME", "PERLLIB", "PERL5LIB",
		"RUBYLIB", "GEM_PATH", "PATH", "SHELL", "ENV", "BASH_ENV",
	}

	var foundDangerous []string
	for _, opt := range globalOptions {
		// Look for list operations adding to env_keep
		op, isListOp := opt["operation"].(string)
		if isListOp && (op == "list_add" || op == "list_assign") {
			if list, exists := opt["env_keep"]; exists {
				var items []string
				if anyItems, ok := list.([]any); ok {
					for _, item := range anyItems {
						if str, ok := item.(string); ok {
							items = append(items, str)
						}
					}
				} else if strItems, ok := list.([]string); ok {
					items = strItems
				}

				for _, item := range items {
					upperItem := strings.ToUpper(item)
					for _, dangerous := range dangerousEnvVars {
						if upperItem == dangerous {
							foundDangerous = append(foundDangerous, item)
						}
					}
				}
			}
		}
	}

	if len(foundDangerous) > 0 {
		findings = append(findings, Finding{
			ID:          "SUDO-DEF-004",
			Title:       "Dangerous Environment Variables Preserved (env_keep)",
			Description: fmt.Sprintf("The policy explicitly preserves dangerous environment variables in env_keep: %s. This can allow local users to inject code into elevated processes (e.g. via dynamic linker hijack LD_PRELOAD, or PYTHONPATH/PERL5LIB library paths).", strings.Join(foundDangerous, ", ")),
			Severity:    SeverityCritical,
			Remediation: "Remove dynamic library path and interpreter path environment variables from 'env_keep' additions in sudoers Defaults.",
		})
	}

	// Check 4: visiblepw enabled
	if isTrue("visiblepw") {
		findings = append(findings, Finding{
			ID:          "SUDO-DEF-005",
			Title:       "visiblepw Flag Enabled",
			Description: "The 'visiblepw' option is enabled globally. This forces sudo to print the password in cleartext if prompting on a terminal, exposing it to shoulder surfing or screen logs.",
			Severity:    SeverityHigh,
			Remediation: "Remove 'Defaults visiblepw' or explicitly set 'Defaults !visiblepw'.",
		})
	}

	// Check 5: pwfeedback enabled
	if isTrue("pwfeedback") {
		findings = append(findings, Finding{
			ID:          "SUDO-DEF-006",
			Title:       "pwfeedback Flag Enabled",
			Description: "The 'pwfeedback' option is enabled. It displays asterisks (*) when typing passwords, which visually leaks the password length and has historically had security vulnerabilities.",
			Severity:    SeverityLow,
			Remediation: "Remove 'Defaults pwfeedback' or explicitly set 'Defaults !pwfeedback' (asterisks feedback is disabled by default).",
		})
	}

	return findings
}
