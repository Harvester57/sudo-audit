package cmd

import (
	"fmt"
	"sudo-check/internal/buildinfo"

	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print detailed version and build information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("sudo-check %s\n", buildinfo.Version)
		fmt.Printf("  commit: %s\n", buildinfo.Commit)
		fmt.Printf("  built:  %s\n", buildinfo.Date)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
