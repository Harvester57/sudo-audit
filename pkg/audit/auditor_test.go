package audit

import (
	"sudo-check/pkg/gtfobins"
	"testing"
)

func TestRunAudit(t *testing.T) {
	gtfoClient, err := gtfobins.NewClient()
	if err != nil {
		t.Fatalf("Failed to load GTFObins database: %v", err)
	}

	// Create a mock policy representing typical vulnerabilities
	policy := &SudoersPolicy{
		Defaults: []DefaultBinding{
			{
				Binding: nil, // Global
				Options: []Option{
					{"visiblepw": true},
					{"pwfeedback": true},
					{"use_pty": false},
					{"operation": "list_add", "env_keep": []any{"LD_PRELOAD", "SOME_OTHER_VAR"}},
				},
			},
		},
		UserSpecs: []UserSpec{
			{
				UserList: []Member{{Username: "alice"}},
				HostList: []Member{{Hostname: "ALL"}},
				CmndSpecs: []CmndSpec{
					{
						Options: []Option{
							{"authenticate": false}, // NOPASSWD
						},
						Commands: []Member{
							{Command: "ALL"},                            // Alice has ALL with NOPASSWD
							{Command: "/usr/bin/find"},                  // Alice can run find
							{Command: "/usr/bin/cat /var/log/*"},        // Alice has wildcard command
							{Command: "/usr/bin/passwd", Negated: true}, // Alice has negated command
						},
					},
				},
			},
		},
	}

	findings := RunAudit(policy, gtfoClient)

	// We expect findings for:
	// 1. Missing secure_path (SUDO-DEF-001)
	// 2. Disabled/missing use_pty (SUDO-DEF-003)
	// 3. Dangerous env_keep (SUDO-DEF-004)
	// 4. visiblepw enabled (SUDO-DEF-005)
	// 5. pwfeedback enabled (SUDO-DEF-006)
	// 6. Negated command (SUDO-CMD-001)
	// 7. Passwordless ALL (SUDO-CMD-003)
	// 8. Wildcard in command (SUDO-CMD-004)
	// 9. GTFObins find bypass (SUDO-GTFO-002 because of NOPASSWD)

	findingMap := make(map[string]bool)
	for _, f := range findings {
		findingMap[f.ID] = true
	}

	expectedIDs := []string{
		"SUDO-DEF-001",
		"SUDO-DEF-003",
		"SUDO-DEF-004",
		"SUDO-DEF-005",
		"SUDO-DEF-006",
		"SUDO-CMD-001",
		"SUDO-CMD-003",
		"SUDO-CMD-004",
		"SUDO-GTFO-002",
	}

	for _, id := range expectedIDs {
		if !findingMap[id] {
			t.Errorf("Expected finding with ID %s to be reported, but it was not.", id)
		}
	}

	// Verify that sudo version check passes compile and correct vulnerabilities list
	sysFindings, err := AuditSudoVersion("1.8.31p1")
	if err != nil {
		t.Fatalf("AuditSudoVersion failed: %v", err)
	}

	hasBaron := false
	for _, f := range sysFindings {
		if f.ID == "CVE-2021-3156" {
			hasBaron = true
		}
	}
	if !hasBaron {
		t.Errorf("Expected sudo 1.8.31p1 to be vulnerable to Baron Samedit (CVE-2021-3156)")
	}
}
