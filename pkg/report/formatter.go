package report

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sudo-check/pkg/audit"
)

// GenerateReports generates all requested reports inside the target outputDir.
// Returns a map of format names to generated file paths.
func GenerateReports(result *audit.AuditResult, formats []string, outputDir string) (map[string]string, error) {
	if outputDir != "" {
		if err := os.MkdirAll(outputDir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create output directory: %w", err)
		}
	}

	generated := make(map[string]string)

	for _, format := range formats {
		format = strings.ToLower(strings.TrimSpace(format))
		switch format {
		case "text", "txt":
			var outPath string
			if outputDir != "" {
				outPath = filepath.Join(outputDir, "report.txt")
				f, err := os.Create(outPath)
				if err != nil {
					return nil, fmt.Errorf("failed to create text report file: %w", err)
				}
				if err := WriteTextReport(result, f); err != nil {
					f.Close()
					return nil, fmt.Errorf("failed to write text report: %w", err)
				}
				f.Close()
				generated["text"] = outPath
			} else {
				// If no output dir, write to stdout
				if err := WriteTextReport(result, os.Stdout); err != nil {
					return nil, fmt.Errorf("failed to write text report to stdout: %w", err)
				}
				generated["text"] = "stdout"
			}
		case "sarif":
			if outputDir == "" {
				continue // SARIF requires an output file/dir
			}
			outPath := filepath.Join(outputDir, "report.sarif")
			f, err := os.Create(outPath)
			if err != nil {
				return nil, fmt.Errorf("failed to create SARIF report file: %w", err)
			}
			if err := WriteSarifReport(result, f); err != nil {
				f.Close()
				return nil, fmt.Errorf("failed to write SARIF report: %w", err)
			}
			f.Close()
			generated["sarif"] = outPath
		case "html":
			if outputDir == "" {
				continue
			}
			outPath := filepath.Join(outputDir, "report.html")
			f, err := os.Create(outPath)
			if err != nil {
				return nil, fmt.Errorf("failed to create HTML report file: %w", err)
			}
			if err := WriteHTMLReport(result, f); err != nil {
				f.Close()
				return nil, fmt.Errorf("failed to write HTML report: %w", err)
			}
			f.Close()
			generated["html"] = outPath
		case "pdf":
			if outputDir == "" {
				continue
			}
			outPath := filepath.Join(outputDir, "report.pdf")
			f, err := os.Create(outPath)
			if err != nil {
				return nil, fmt.Errorf("failed to create PDF report file: %w", err)
			}
			if err := WritePDFReport(result, f); err != nil {
				f.Close()
				return nil, fmt.Errorf("failed to write PDF report: %w", err)
			}
			f.Close()
			generated["pdf"] = outPath
		}
	}

	return generated, nil
}
