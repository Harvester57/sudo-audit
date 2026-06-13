package report

import (
	"encoding/json"
	"io"
	"sudo-check/internal/buildinfo"
	"sudo-check/pkg/audit"
)

// SarifLog represents the root of a SARIF log file
type SarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SarifRun `json:"runs"`
}

type SarifRun struct {
	Tool    SarifTool     `json:"tool"`
	Results []SarifResult `json:"results"`
}

type SarifTool struct {
	Driver SarifDriver `json:"driver"`
}

type SarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version,omitempty"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []SarifRule `json:"rules"`
}

type SarifRule struct {
	ID               string               `json:"id"`
	ShortDescription SarifMultiformatText `json:"shortDescription"`
}

type SarifMultiformatText struct {
	Text string `json:"text"`
}

type SarifResult struct {
	RuleID    string               `json:"ruleId"`
	Message   SarifMultiformatText `json:"message"`
	Level     string               `json:"level"` // "error", "warning", "note", "none"
	Locations []SarifLocation      `json:"locations,omitempty"`
}

type SarifLocation struct {
	PhysicalLocation SarifPhysicalLocation `json:"physicalLocation"`
}

type SarifPhysicalLocation struct {
	ArtifactLocation SarifArtifactLocation `json:"artifactLocation"`
}

type SarifArtifactLocation struct {
	URI string `json:"uri"`
}

// WriteSarifReport formats the audit results as a SARIF JSON report.
func WriteSarifReport(result *audit.AuditResult, w io.Writer) error {
	log := SarifLog{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
	}

	driver := SarifDriver{
		Name:           "sudo-check",
		Version:        buildinfo.Version,
		InformationURI: "https://github.com/Florian/sudo-check",
		Rules:          []SarifRule{},
	}

	// Helper to map audit severity to SARIF levels
	mapLevel := func(sev audit.Severity) string {
		switch sev {
		case audit.SeverityCritical, audit.SeverityHigh:
			return "error"
		case audit.SeverityMedium, audit.SeverityLow:
			return "warning"
		case audit.SeverityInfo:
			return "note"
		default:
			return "none"
		}
	}

	results := []SarifResult{}
	ruleMap := make(map[string]bool)

	addFindings := func(findings []audit.Finding, defaultURI string) {
		for _, f := range findings {
			// Add rule metadata if not already present
			if !ruleMap[f.ID] {
				driver.Rules = append(driver.Rules, SarifRule{
					ID: f.ID,
					ShortDescription: SarifMultiformatText{
						Text: f.Title,
					},
				})
				ruleMap[f.ID] = true
			}

			uri := defaultURI
			if f.Context != "" {
				uri = f.Context
			}

			results = append(results, SarifResult{
				RuleID: f.ID,
				Message: SarifMultiformatText{
					Text: f.Description + "\nRemediation: " + f.Remediation,
				},
				Level: mapLevel(f.Severity),
				Locations: []SarifLocation{
					{
						PhysicalLocation: SarifPhysicalLocation{
							ArtifactLocation: SarifArtifactLocation{
								URI: uri,
							},
						},
					},
				},
			})
		}
	}

	addFindings(result.SystemFindings, "system-configuration")
	addFindings(result.PolicyFindings, "file:///etc/sudoers")

	run := SarifRun{
		Tool: SarifTool{
			Driver: driver,
		},
		Results: results,
	}

	log.Runs = []SarifRun{run}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(log)
}
