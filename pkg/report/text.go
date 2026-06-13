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

	// Print System Findings
	if len(result.SystemFindings) > 0 {
		sb.WriteString(fmt.Sprintf("%s--- System Vulnerability Findings (%d) ---%s\n", colorBold, len(result.SystemFindings), colorReset))
		for _, f := range result.SystemFindings {
			color := GetSeverityColor(f.Severity)
			sb.WriteString(fmt.Sprintf("[%s%s%s] %s: %s\n", color, f.Severity, colorReset, f.ID, f.Title))
			sb.WriteString(fmt.Sprintf("  Description: %s\n", f.Description))
			sb.WriteString(fmt.Sprintf("  Remediation: %s\n\n", f.Remediation))
		}
	}

	// Print Policy Findings
	if len(result.PolicyFindings) > 0 {
		sb.WriteString(fmt.Sprintf("%s--- Sudoers Policy Findings (%d) ---%s\n", colorBold, len(result.PolicyFindings), colorReset))
		for _, f := range result.PolicyFindings {
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

	// Print Summary stats
	criticalCount := 0
	highCount := 0
	mediumCount := 0
	lowCount := 0
	infoCount := 0

	count := func(f []audit.Finding) {
		for _, v := range f {
			switch v.Severity {
			case audit.SeverityCritical:
				criticalCount++
			case audit.SeverityHigh:
				highCount++
			case audit.SeverityMedium:
				mediumCount++
			case audit.SeverityLow:
				lowCount++
			case audit.SeverityInfo:
				infoCount++
			}
		}
	}
	count(result.SystemFindings)
	count(result.PolicyFindings)

	sb.WriteString(fmt.Sprintf("%s--- Summary of Findings ---%s\n", colorBold, colorReset))
	sb.WriteString(fmt.Sprintf("  %sCRITICAL:%s %d\n", colorRed, colorReset, criticalCount))
	sb.WriteString(fmt.Sprintf("  %sHIGH:%s     %d\n", colorPurple, colorReset, highCount))
	sb.WriteString(fmt.Sprintf("  %sMEDIUM:%s   %d\n", colorYellow, colorReset, mediumCount))
	sb.WriteString(fmt.Sprintf("  %sLOW:%s      %d\n", colorCyan, colorReset, lowCount))
	sb.WriteString(fmt.Sprintf("  %sINFO:%s     %d\n", colorBlue, colorReset, infoCount))
	sb.WriteString("\n")

	_, err := io.WriteString(w, sb.String())
	return err
}
