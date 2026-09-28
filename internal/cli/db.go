package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/cozygarage/sentinelflow/internal/vulndb"
	"github.com/cozygarage/sentinelflow/pkg/api"
)

var dbEcosystem string

var dbCmd = &cobra.Command{
	Use:   "db",
	Short: "Manage the offline OSV vulnerability cache",
}

var dbUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Download OSV ecosystem data into the local cache",
	RunE: func(cmd *cobra.Command, args []string) error {
		dir, err := vulndb.UpdateOffline(cmd.Context(), dbEcosystem)
		if err != nil {
			return api.ErrTool(err.Error())
		}
		fmt.Printf("OSV cache updated in %s\n", dir)
		return nil
	},
}

func init() {
	dbUpdateCmd.Flags().StringVar(&dbEcosystem, "ecosystem", "Go", "OSV ecosystem zip to download (Go, npm, PyPI, Maven, crates.io, RubyGems)")
	dbCmd.AddCommand(dbUpdateCmd)
	rootCmd.AddCommand(dbCmd)
}
