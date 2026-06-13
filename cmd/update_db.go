package cmd

import (
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/spf13/cobra"
)

var (
	dbOutputPath string
)

var updateDbCmd = &cobra.Command{
	Use:   "update-db",
	Short: "Fetch and update the GTFObins database",
	Long:  `Downloads the latest database JSON from gtfobins.org/api.json and saves it to a file.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		url := "https://gtfobins.org/api.json"
		fmt.Printf("Fetching latest GTFObins database from %s...\n", url)

		resp, err := http.Get(url)
		if err != nil {
			return fmt.Errorf("failed to fetch database: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("server returned non-OK status: %s", resp.Status)
		}

		// Create target file
		f, err := os.Create(dbOutputPath)
		if err != nil {
			return fmt.Errorf("failed to create target file: %w", err)
		}
		defer f.Close()

		_, err = io.Copy(f, resp.Body)
		if err != nil {
			return fmt.Errorf("failed to save database: %w", err)
		}

		fmt.Printf("GTFObins database updated successfully and saved to '%s'!\n", dbOutputPath)
		return nil
	},
}

func init() {
	updateDbCmd.Flags().StringVarP(&dbOutputPath, "output", "p", "gtfobins.json", "Output path for the updated gtfobins.json")
	rootCmd.AddCommand(updateDbCmd)
}
