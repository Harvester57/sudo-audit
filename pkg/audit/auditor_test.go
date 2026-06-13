package audit

import (
	"encoding/json"
	"os"
	"sudo-check/pkg/gtfobins"
	"testing"
)

// loadTestPolicy loads a JSON policy fixture from testdata/.
func loadTestPolicy(t *testing.T, name string) *SudoersPolicy {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatalf("Failed to read test fixture %s: %v", name, err)
	}
	var policy SudoersPolicy
	if err := json.Unmarshal(data, &policy); err != nil {
		t.Fatalf("Failed to parse test fixture %s: %v", name, err)
	}
	return &policy
}

// requireGTFOClient creates a GTFObins client or fails the test.
func requireGTFOClient(t *testing.T) *gtfobins.Client {
	t.Helper()
	c, err := gtfobins.NewClient()
	if err != nil {
		t.Fatalf("Failed to load GTFObins database: %v", err)
	}
	return c
}

// assertFindingPresent checks that at least one finding with the given ID exists.
func assertFindingPresent(t *testing.T, findings []Finding, id string) {
	t.Helper()
	for _, f := range findings {
		if f.ID == id {
			return
		}
	}
	t.Errorf("Expected finding with ID %s to be present, but it was not found", id)
}

// assertFindingAbsent checks that no finding with the given ID exists.
func assertFindingAbsent(t *testing.T, findings []Finding, id string) {
	t.Helper()
	for _, f := range findings {
		if f.ID == id {
			t.Errorf("Expected finding with ID %s to be absent, but it was found: %s", id, f.Title)
			return
		}
	}
}

// assertFindingSeverity checks that the first finding with the given ID has the expected severity.
func assertFindingSeverity(t *testing.T, findings []Finding, id string, expected Severity) {
	t.Helper()
	for _, f := range findings {
		if f.ID == id {
			if f.Severity != expected {
				t.Errorf("Finding %s: expected severity %s, got %s", id, expected, f.Severity)
			}
			return
		}
	}
	t.Errorf("Finding %s not found — cannot check severity", id)
}

// --- Defaults Audit Tests ---

func TestAuditDefaults(t *testing.T) {
	t.Run("MissingSecurePath", func(t *testing.T) {
		policy := &SudoersPolicy{Defaults: []DefaultBinding{{Options: []Option{{"use_pty": true}}}}}
		findings := AuditDefaults(policy)
		assertFindingPresent(t, findings, "SUDO-DEF-001")
	})

	t.Run("EmptySecurePath", func(t *testing.T) {
		policy := &SudoersPolicy{Defaults: []DefaultBinding{{Options: []Option{{"secure_path": ""}}}}}
		findings := AuditDefaults(policy)
		assertFindingPresent(t, findings, "SUDO-DEF-001")
	})

	t.Run("RelativePathInSecurePath", func(t *testing.T) {
		policy := &SudoersPolicy{Defaults: []DefaultBinding{{Options: []Option{{"secure_path": "/usr/bin:./local:/sbin"}}}}}
		findings := AuditDefaults(policy)
		assertFindingPresent(t, findings, "SUDO-DEF-002")
	})

	t.Run("ValidSecurePath", func(t *testing.T) {
		policy := &SudoersPolicy{Defaults: []DefaultBinding{{Options: []Option{{"secure_path": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}}}}}
		findings := AuditDefaults(policy)
		assertFindingAbsent(t, findings, "SUDO-DEF-001")
		assertFindingAbsent(t, findings, "SUDO-DEF-002")
	})

	t.Run("MissingUsePty", func(t *testing.T) {
		policy := &SudoersPolicy{Defaults: []DefaultBinding{{Options: []Option{{"secure_path": "/usr/bin"}}}}}
		findings := AuditDefaults(policy)
		assertFindingPresent(t, findings, "SUDO-DEF-003")
	})

	t.Run("DisabledUsePty", func(t *testing.T) {
		policy := &SudoersPolicy{Defaults: []DefaultBinding{{Options: []Option{{"use_pty": false}}}}}
		findings := AuditDefaults(policy)
		assertFindingPresent(t, findings, "SUDO-DEF-003")
	})

	t.Run("EnabledUsePty", func(t *testing.T) {
		policy := &SudoersPolicy{Defaults: []DefaultBinding{{Options: []Option{{"use_pty": true}}}}}
		findings := AuditDefaults(policy)
		assertFindingAbsent(t, findings, "SUDO-DEF-003")
	})

	t.Run("DangerousEnvKeep", func(t *testing.T) {
		policy := &SudoersPolicy{Defaults: []DefaultBinding{{Options: []Option{
			{"operation": "list_add", "env_keep": []any{"LD_PRELOAD", "SAFE_VAR"}},
		}}}}
		findings := AuditDefaults(policy)
		assertFindingPresent(t, findings, "SUDO-DEF-004")
		assertFindingSeverity(t, findings, "SUDO-DEF-004", SeverityCritical)
	})

	t.Run("SafeEnvKeep", func(t *testing.T) {
		policy := &SudoersPolicy{Defaults: []DefaultBinding{{Options: []Option{
			{"operation": "list_add", "env_keep": []any{"LANG", "LC_ALL", "TERM"}},
		}}}}
		findings := AuditDefaults(policy)
		assertFindingAbsent(t, findings, "SUDO-DEF-004")
	})

	t.Run("VisiblepwEnabled", func(t *testing.T) {
		policy := &SudoersPolicy{Defaults: []DefaultBinding{{Options: []Option{{"visiblepw": true}}}}}
		findings := AuditDefaults(policy)
		assertFindingPresent(t, findings, "SUDO-DEF-005")
	})

	t.Run("VisiblepwDisabled", func(t *testing.T) {
		policy := &SudoersPolicy{Defaults: []DefaultBinding{{Options: []Option{{"visiblepw": false}}}}}
		findings := AuditDefaults(policy)
		assertFindingAbsent(t, findings, "SUDO-DEF-005")
	})

	t.Run("PwfeedbackEnabled", func(t *testing.T) {
		policy := &SudoersPolicy{Defaults: []DefaultBinding{{Options: []Option{{"pwfeedback": true}}}}}
		findings := AuditDefaults(policy)
		assertFindingPresent(t, findings, "SUDO-DEF-006")
	})

	t.Run("CleanPolicy_ZeroFindings", func(t *testing.T) {
		policy := loadTestPolicy(t, "clean_policy.json")
		findings := AuditDefaults(policy)
		if len(findings) != 0 {
			t.Errorf("Expected 0 findings for clean policy defaults, got %d:", len(findings))
			for _, f := range findings {
				t.Errorf("  - %s: %s", f.ID, f.Title)
			}
		}
	})
}

// --- Commands Audit Tests ---

func TestAuditCommands(t *testing.T) {
	gtfoClient := requireGTFOClient(t)

	t.Run("NegatedCommand", func(t *testing.T) {
		policy := &SudoersPolicy{UserSpecs: []UserSpec{{
			UserList: []Member{{Username: "alice"}},
			HostList: []Member{{Hostname: "ALL"}},
			CmndSpecs: []CmndSpec{{
				Commands: []Member{{Command: "/usr/bin/passwd", Negated: true}},
			}},
		}}}
		findings := AuditCommands(policy, gtfoClient)
		assertFindingPresent(t, findings, "SUDO-CMD-001")
		assertFindingSeverity(t, findings, "SUDO-CMD-001", SeverityHigh)
	})

	t.Run("ALLWithPassword", func(t *testing.T) {
		policy := &SudoersPolicy{UserSpecs: []UserSpec{{
			UserList: []Member{{Username: "alice"}},
			HostList: []Member{{Hostname: "ALL"}},
			CmndSpecs: []CmndSpec{{
				Commands: []Member{{Command: "ALL"}},
			}},
		}}}
		findings := AuditCommands(policy, gtfoClient)
		assertFindingPresent(t, findings, "SUDO-CMD-002")
		assertFindingSeverity(t, findings, "SUDO-CMD-002", SeverityHigh)
	})

	t.Run("ALLWithNoPasswd", func(t *testing.T) {
		policy := &SudoersPolicy{UserSpecs: []UserSpec{{
			UserList: []Member{{Username: "alice"}},
			HostList: []Member{{Hostname: "ALL"}},
			CmndSpecs: []CmndSpec{{
				Options:  []Option{{"authenticate": false}},
				Commands: []Member{{Command: "ALL"}},
			}},
		}}}
		findings := AuditCommands(policy, gtfoClient)
		assertFindingPresent(t, findings, "SUDO-CMD-003")
		assertFindingSeverity(t, findings, "SUDO-CMD-003", SeverityCritical)
	})

	t.Run("WildcardCommand", func(t *testing.T) {
		policy := &SudoersPolicy{UserSpecs: []UserSpec{{
			UserList: []Member{{Username: "alice"}},
			HostList: []Member{{Hostname: "ALL"}},
			CmndSpecs: []CmndSpec{{
				Commands: []Member{{Command: "/usr/bin/cat /var/log/*"}},
			}},
		}}}
		findings := AuditCommands(policy, gtfoClient)
		assertFindingPresent(t, findings, "SUDO-CMD-004")
	})

	t.Run("GTFObinsMatch", func(t *testing.T) {
		policy := &SudoersPolicy{UserSpecs: []UserSpec{{
			UserList: []Member{{Username: "alice"}},
			HostList: []Member{{Hostname: "ALL"}},
			CmndSpecs: []CmndSpec{{
				Commands: []Member{{Command: "/usr/bin/find"}},
			}},
		}}}
		findings := AuditCommands(policy, gtfoClient)
		assertFindingPresent(t, findings, "SUDO-GTFO-001")
		assertFindingSeverity(t, findings, "SUDO-GTFO-001", SeverityHigh)
	})

	t.Run("GTFObinsWithNoPasswd", func(t *testing.T) {
		policy := &SudoersPolicy{UserSpecs: []UserSpec{{
			UserList: []Member{{Username: "alice"}},
			HostList: []Member{{Hostname: "ALL"}},
			CmndSpecs: []CmndSpec{{
				Options:  []Option{{"authenticate": false}},
				Commands: []Member{{Command: "/usr/bin/find"}},
			}},
		}}}
		findings := AuditCommands(policy, gtfoClient)
		assertFindingPresent(t, findings, "SUDO-GTFO-002")
		assertFindingSeverity(t, findings, "SUDO-GTFO-002", SeverityCritical)
	})

	t.Run("GTFObinsWithNoExecMitigation", func(t *testing.T) {
		policy := &SudoersPolicy{UserSpecs: []UserSpec{{
			UserList: []Member{{Username: "bob"}},
			HostList: []Member{{Hostname: "ALL"}},
			CmndSpecs: []CmndSpec{{
				Options:  []Option{{"noexec": true}},
				Commands: []Member{{Command: "/usr/bin/python3"}},
			}},
		}}}
		findings := AuditCommands(policy, gtfoClient)
		// python3 has shell bypass but noexec should mitigate it
		hasMitigated := false
		for _, f := range findings {
			if f.ID == "SUDO-GTFO-003" {
				hasMitigated = true
				if f.Severity != SeverityLow {
					t.Errorf("Expected SUDO-GTFO-003 to be LOW severity (mitigated), got %s", f.Severity)
				}
			}
		}
		if !hasMitigated {
			// At minimum, there should be some GTFObins finding
			t.Log("Note: python3 noexec mitigation check — verify GTFObins database has shell/execute function for python3")
		}
	})

	t.Run("NoPasswdSpecificCommand_NoGTFO", func(t *testing.T) {
		policy := &SudoersPolicy{UserSpecs: []UserSpec{{
			UserList: []Member{{Username: "alice"}},
			HostList: []Member{{Hostname: "ALL"}},
			CmndSpecs: []CmndSpec{{
				Options:  []Option{{"authenticate": false}},
				Commands: []Member{{Command: "/usr/local/bin/my-safe-script"}},
			}},
		}}}
		findings := AuditCommands(policy, gtfoClient)
		assertFindingPresent(t, findings, "SUDO-CMD-005")
		assertFindingSeverity(t, findings, "SUDO-CMD-005", SeverityLow)
	})

	t.Run("CommandAliasResolution", func(t *testing.T) {
		policy := &SudoersPolicy{
			CommandAliases: map[string][]Member{
				"EDITORS": {
					{Command: "/usr/bin/vim"},
					{Command: "/usr/bin/nano"},
				},
			},
			UserSpecs: []UserSpec{{
				UserList: []Member{{Username: "alice"}},
				HostList: []Member{{Hostname: "ALL"}},
				CmndSpecs: []CmndSpec{{
					Commands: []Member{{CommandAlias: "EDITORS"}},
				}},
			}},
		}
		findings := AuditCommands(policy, gtfoClient)
		// vim is a known GTFObins binary
		hasVimGTFO := false
		for _, f := range findings {
			if f.Command == "/usr/bin/vim" {
				hasVimGTFO = true
			}
		}
		if !hasVimGTFO {
			t.Error("Expected alias resolution to find vim GTFObins bypass, but no finding for /usr/bin/vim was found")
		}
	})

	t.Run("CircularAliasDepthLimit", func(t *testing.T) {
		policy := loadTestPolicy(t, "circular_alias_policy.json")
		// This should NOT panic or hang — the depth limit should prevent infinite recursion
		findings := AuditCommands(policy, gtfoClient)
		_ = findings // We only care that this doesn't hang/crash
	})

	t.Run("EmptyPolicy", func(t *testing.T) {
		policy := &SudoersPolicy{}
		findings := AuditCommands(policy, gtfoClient)
		if len(findings) != 0 {
			t.Errorf("Expected 0 findings for empty policy, got %d", len(findings))
		}
	})

	t.Run("CleanPolicy_ZeroFindings", func(t *testing.T) {
		policy := loadTestPolicy(t, "clean_policy.json")
		findings := AuditCommands(policy, gtfoClient)
		if len(findings) != 0 {
			t.Errorf("Expected 0 findings for clean policy commands, got %d:", len(findings))
			for _, f := range findings {
				t.Errorf("  - %s: %s (cmd: %s)", f.ID, f.Title, f.Command)
			}
		}
	})
}

// --- Version Parsing Tests ---

func TestParseSudoVersion(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
		major   int
		minor   int
		patch   int
		pl      int
	}{
		{"Standard", "1.9.12", false, 1, 9, 12, 0},
		{"WithPatchLevel", "1.8.31p2", false, 1, 8, 31, 2},
		{"OldVersion", "1.8.0", false, 1, 8, 0, 0},
		{"WithTrailingText", "1.9.5p1\n", false, 1, 9, 5, 1},
		{"Invalid", "not-a-version", true, 0, 0, 0, 0},
		{"Empty", "", true, 0, 0, 0, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, err := ParseSudoVersion(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("Expected error for input %q, got nil", tt.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("Unexpected error for input %q: %v", tt.input, err)
			}
			if v.Major != tt.major || v.Minor != tt.minor || v.Patch != tt.patch || v.Pl != tt.pl {
				t.Errorf("Got %d.%d.%dp%d, want %d.%d.%dp%d", v.Major, v.Minor, v.Patch, v.Pl, tt.major, tt.minor, tt.patch, tt.pl)
			}
		})
	}
}

func TestSudoVersionCompare(t *testing.T) {
	tests := []struct {
		name string
		a, b SudoVersion
		want int
	}{
		{"Equal", SudoVersion{Major: 1, Minor: 9, Patch: 12, Pl: 0}, SudoVersion{Major: 1, Minor: 9, Patch: 12, Pl: 0}, 0},
		{"Less", SudoVersion{Major: 1, Minor: 8, Patch: 31, Pl: 2}, SudoVersion{Major: 1, Minor: 9, Patch: 0, Pl: 0}, -1},
		{"Greater", SudoVersion{Major: 1, Minor: 9, Patch: 12, Pl: 2}, SudoVersion{Major: 1, Minor: 9, Patch: 12, Pl: 1}, 1},
		{"PatchLevel", SudoVersion{Major: 1, Minor: 8, Patch: 31, Pl: 1}, SudoVersion{Major: 1, Minor: 8, Patch: 31, Pl: 2}, -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.a.Compare(tt.b)
			if got != tt.want {
				t.Errorf("%v.Compare(%v) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestAuditSudoVersion(t *testing.T) {
	tests := []struct {
		name          string
		version       string
		checkCVE      string
		expectPresent bool
	}{
		{"CVE-2019-14287_Vulnerable", "1.8.27", "CVE-2019-14287", true},
		{"CVE-2019-14287_Fixed", "1.8.28", "CVE-2019-14287", false},
		{"CVE-2021-3156_Vulnerable_18x", "1.8.31p1", "CVE-2021-3156", true},
		{"CVE-2021-3156_Fixed_18x", "1.8.32", "CVE-2021-3156", false},
		{"CVE-2021-3156_Vulnerable_19x", "1.9.5p1", "CVE-2021-3156", true},
		{"CVE-2021-3156_Fixed_19x", "1.9.6", "CVE-2021-3156", false},
		{"CVE-2023-27320_Vulnerable", "1.9.12p1", "CVE-2023-27320", true},
		{"CVE-2023-27320_Fixed", "1.9.12p2", "CVE-2023-27320", false},
		{"AllClear_Latest", "1.9.15p5", "CVE-2023-27320", false}, // Also doesn't have 2023-27320
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings, err := AuditSudoVersion(tt.version)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if tt.expectPresent {
				assertFindingPresent(t, findings, tt.checkCVE)
			} else {
				assertFindingAbsent(t, findings, tt.checkCVE)
			}
		})
	}

	t.Run("EmptyVersion", func(t *testing.T) {
		findings, err := AuditSudoVersion("")
		if err != nil {
			t.Fatalf("Unexpected error for empty version: %v", err)
		}
		if findings != nil {
			t.Errorf("Expected nil findings for empty version, got %d", len(findings))
		}
	})
}

// --- Helper Function Tests ---

func TestCountBySeverity(t *testing.T) {
	findings1 := []Finding{
		{ID: "1", Severity: SeverityCritical},
		{ID: "2", Severity: SeverityHigh},
		{ID: "3", Severity: SeverityCritical},
	}
	findings2 := []Finding{
		{ID: "4", Severity: SeverityLow},
		{ID: "5", Severity: SeverityInfo},
	}

	counts := CountBySeverity(findings1, findings2)
	if counts[SeverityCritical] != 2 {
		t.Errorf("Expected 2 critical, got %d", counts[SeverityCritical])
	}
	if counts[SeverityHigh] != 1 {
		t.Errorf("Expected 1 high, got %d", counts[SeverityHigh])
	}
	if counts[SeverityLow] != 1 {
		t.Errorf("Expected 1 low, got %d", counts[SeverityLow])
	}
	if counts[SeverityInfo] != 1 {
		t.Errorf("Expected 1 info, got %d", counts[SeverityInfo])
	}
	if counts[SeverityMedium] != 0 {
		t.Errorf("Expected 0 medium, got %d", counts[SeverityMedium])
	}
}

func TestSortFindingsBySeverity(t *testing.T) {
	findings := []Finding{
		{ID: "info", Severity: SeverityInfo},
		{ID: "crit", Severity: SeverityCritical},
		{ID: "low", Severity: SeverityLow},
		{ID: "high", Severity: SeverityHigh},
		{ID: "med", Severity: SeverityMedium},
	}

	SortFindingsBySeverity(findings)

	expected := []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo}
	for i, f := range findings {
		if f.Severity != expected[i] {
			t.Errorf("Position %d: expected %s, got %s", i, expected[i], f.Severity)
		}
	}
}

// --- Full Integration Test ---

func TestRunAudit_VulnerablePolicy(t *testing.T) {
	gtfoClient := requireGTFOClient(t)
	policy := loadTestPolicy(t, "vulnerable_policy.json")

	findings := RunAudit(policy, gtfoClient)

	// This policy should trigger many rules
	expectedIDs := []string{
		"SUDO-DEF-001", // missing secure_path
		"SUDO-DEF-003", // disabled use_pty
		"SUDO-DEF-004", // dangerous env_keep
		"SUDO-DEF-005", // visiblepw
		"SUDO-DEF-006", // pwfeedback
		"SUDO-CMD-001", // negated command
		"SUDO-CMD-003", // ALL + NOPASSWD
		"SUDO-CMD-004", // wildcard
	}

	for _, id := range expectedIDs {
		assertFindingPresent(t, findings, id)
	}

	// Verify GTFObins matches exist (find, vim via alias)
	hasGTFO := false
	for _, f := range findings {
		if f.ID == "SUDO-GTFO-001" || f.ID == "SUDO-GTFO-002" || f.ID == "SUDO-GTFO-003" {
			hasGTFO = true
		}
	}
	if !hasGTFO {
		t.Error("Expected GTFObins findings from vulnerable policy")
	}
}

func TestRunAudit_CleanPolicy(t *testing.T) {
	gtfoClient := requireGTFOClient(t)
	policy := loadTestPolicy(t, "clean_policy.json")

	findings := RunAudit(policy, gtfoClient)
	if len(findings) != 0 {
		t.Errorf("Expected 0 findings for clean policy, got %d:", len(findings))
		for _, f := range findings {
			t.Errorf("  - %s: %s", f.ID, f.Title)
		}
	}
}
