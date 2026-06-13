package audit

import (
	"sudo-check/pkg/gtfobins"
)

// RunAudit runs all policy-level audit rules against the parsed sudoers policy.
func RunAudit(policy *SudoersPolicy, gtfoClient *gtfobins.Client) []Finding {
	var findings []Finding

	// Run global Defaults audits
	findings = append(findings, AuditDefaults(policy)...)

	// Run allowed commands / GTFObins audits
	findings = append(findings, AuditCommands(policy, gtfoClient)...)

	return findings
}
