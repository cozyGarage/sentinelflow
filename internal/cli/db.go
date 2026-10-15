package cli

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/cozygarage/sentinelflow/internal/vulndb"
)

var dbEcosystems []string

var dbCmd = &cobra.Command{
	Use:   "db",
	Short: "Manage the offline vulnerability database",
	Long: `Download OSV advisories for air-gapped scans.

After 'sentinelflow db update', 'sentinelflow scan --offline' (or
scanners.dependencies.offline: true) answers dependency lookups locally.
Set SENTINELFLOW_CACHE_DIR to choose where the database lives, e.g. a CI cache path.`,
}

var dbUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Download or refresh the offline OSV database",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		for _, eco := range dbEcosystems {
			if !slices.Contains(vulndb.OfflineEcosystems, eco) {
				return fmt.Errorf("unknown ecosystem %q (supported: %s)", eco, strings.Join(vulndb.OfflineEcosystems, ", "))
			}
		}
		dir := vulndb.OfflineDir()
		counts, err := vulndb.UpdateOffline(context.Background(), nil, dir, dbEcosystems)
		for _, eco := range dbEcosystems {
			if n, ok := counts[eco]; ok {
				fmt.Printf("%s %-9s %d advisories\n", color.GreenString("✓"), eco, n)
			}
		}
		if err != nil {
			return fmt.Errorf("db update failed: %w", err)
		}
		fmt.Printf("Saved to %s\n", dir)
		return nil
	},
}

var dbStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show when each ecosystem was last updated",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		dir := vulndb.OfflineDir()
		fmt.Println(dir)
		status := vulndb.OfflineStatus(dir)
		for _, eco := range vulndb.OfflineEcosystems {
			if t := status[eco]; t.IsZero() {
				fmt.Printf("  %-9s %s\n", eco, color.YellowString("missing"))
			} else {
				fmt.Printf("  %-9s %s\n", eco, t.Local().Format("2006-01-02 15:04"))
			}
		}
	},
}

func init() {
	dbUpdateCmd.Flags().StringSliceVar(&dbEcosystems, "ecosystems", vulndb.OfflineEcosystems, "ecosystems to download")
	dbCmd.AddCommand(dbUpdateCmd, dbStatusCmd)
}
