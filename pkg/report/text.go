package report

import (
	"fmt"
	"io"
	"strings"
	"sudo-check/pkg/audit"
)

// ANSI color codes
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorPurple = "\033[35m"
	colorCyan   = "\033[36m"
	colorBold   = "\033[1m"
)

// GetSeverityColor returns the ANSI color code for a given severity.
func GetSeverityColor(sev audit.Severity) string {
	switch sev {
	case audit.SeverityCritical:
		return colorRed + colorBold
	case audit.SeverityHigh:
		return colorPurple + colorBold
	case audit.SeverityMedium:
		return colorYellow + colorBold
	case audit.SeverityLow:
		return colorCyan
	case audit.SeverityInfo:
		return colorBlue
	default:
		return colorReset
	}
}

// WriteTextReport formats the audit results as human-readable plaintext.
func WriteTextReport(result *audit.AuditResult, w io.Writer) error {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("%s=== SUDOERS SECURITY AUDIT REPORT ===%s\n\n", colorBold, colorReset))
	if result.Hostname != "" {
		sb.WriteString(fmt.Sprintf("Target Hostname: %s\n", result.Hostname))
	}
	if result.SudoVersion != "" {
		sb.WriteString(fmt.Sprintf("Sudo Version:    %s\n", result.SudoVersion))
	}
	sb.WriteString("\n")

	// Print System Findings (sorted by severity)
	if len(result.SystemFindings) > 0 {
		sorted := make([]audit.Finding, len(result.SystemFindings))
		copy(sorted, result.SystemFindings)
		audit.SortFindingsBySeverity(sorted)

		sb.WriteString(fmt.Sprintf("%s--- System Vulnerability Findings (%d) ---%s\n", colorBold, len(sorted), colorReset))
		for _, f := range sorted {
			color := GetSeverityColor(f.Severity)
			sb.WriteString(fmt.Sprintf("[%s%s%s] %s: %s\n", color, f.Severity, colorReset, f.ID, f.Title))
			sb.WriteString(fmt.Sprintf("  Description: %s\n", f.Description))
			sb.WriteString(fmt.Sprintf("  Remediation: %s\n\n", f.Remediation))
		}
	}

	// Print Policy Findings (sorted by severity)
	if len(result.PolicyFindings) > 0 {
		sorted := make([]audit.Finding, len(result.PolicyFindings))
		copy(sorted, result.PolicyFindings)
		audit.SortFindingsBySeverity(sorted)

		sb.WriteString(fmt.Sprintf("%s--- Sudoers Policy Findings (%d) ---%s\n", colorBold, len(sorted), colorReset))
		for _, f := range sorted {
			color := GetSeverityColor(f.Severity)
			sb.WriteString(fmt.Sprintf("[%s%s%s] %s: %s\n", color, f.Severity, colorReset, f.ID, f.Title))
			if f.User != "" {
				sb.WriteString(fmt.Sprintf("  User/Group:  %s\n", f.User))
			}
			if f.Command != "" {
				sb.WriteString(fmt.Sprintf("  Command:     %s\n", f.Command))
			}
			sb.WriteString(fmt.Sprintf("  Description: %s\n", f.Description))
			sb.WriteString(fmt.Sprintf("  Remediation: %s\n\n", f.Remediation))
		}
	} else {
		sb.WriteString("No sudoers policy misconfigurations found.\n")
	}

	// Print Summary stats using helper
	counts := audit.CountBySeverity(result.SystemFindings, result.PolicyFindings)

	sb.WriteString(fmt.Sprintf("%s--- Summary of Findings ---%s\n", colorBold, colorReset))
	sb.WriteString(fmt.Sprintf("  %sCRITICAL:%s %d\n", colorRed, colorReset, counts[audit.SeverityCritical]))
	sb.WriteString(fmt.Sprintf("  %sHIGH:%s     %d\n", colorPurple, colorReset, counts[audit.SeverityHigh]))
	sb.WriteString(fmt.Sprintf("  %sMEDIUM:%s   %d\n", colorYellow, colorReset, counts[audit.SeverityMedium]))
	sb.WriteString(fmt.Sprintf("  %sLOW:%s      %d\n", colorCyan, colorReset, counts[audit.SeverityLow]))
	sb.WriteString(fmt.Sprintf("  %sINFO:%s     %d\n", colorBlue, colorReset, counts[audit.SeverityInfo]))
	sb.WriteString("\n")

	_, err := io.WriteString(w, sb.String())
	return err
}
