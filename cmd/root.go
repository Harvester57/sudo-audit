package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var (
	OutputDir      string
	Formats        string
	GtfoBinsPath   string
	CvtSudoersPath string
)

var rootCmd = &cobra.Command{
	Use:   "sudo-check",
	Short: "sudo-check audits sudoers policies and target host configurations for security risks",
	Long: `A statically compiled command-line utility to audit sudoers configuration policies 
for security misconfigurations, dangerous defaults, and privilege escalation vectors 
via the GTFObins database.

It supports scanning pre-converted JSON policies (from cvtsudoers) or running autonomously 
on target systems using the local cvtsudoers command.`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&OutputDir, "output-dir", "o", "", "Directory to save the generated reports (if not set, plaintext reports are written to stdout)")
	rootCmd.PersistentFlags().StringVarP(&Formats, "formats", "f", "text,sarif,pdf,html", "Comma-separated list of output formats (text, sarif, pdf, html)")
	rootCmd.PersistentFlags().StringVar(&GtfoBinsPath, "gtfobins-path", "", "Path to custom gtfobins.json database snapshot")
	rootCmd.PersistentFlags().StringVar(&CvtSudoersPath, "cvtsudoers-path", "", "Path to custom cvtsudoers binary")
}

// GetFormatsList returns the slice of formatted outputs selected by the user.
func GetFormatsList() []string {
	parts := strings.Split(Formats, ",")
	var cleaned []string
	for _, p := range parts {
		c := strings.TrimSpace(p)
		if c != "" {
			cleaned = append(cleaned, c)
		}
	}
	return cleaned
}
