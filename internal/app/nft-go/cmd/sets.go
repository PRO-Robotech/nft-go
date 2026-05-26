package cmd

import (
	"github.com/PRO-Robotech/nft-go/pkg/nftenc"
	"github.com/PRO-Robotech/nft-go/pkg/nftlist"

	nftLib "github.com/google/nftables"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func newSetsCommand() *cobra.Command {
	c := &cobra.Command{
		Use:   "sets",
		Short: "list sets",
		RunE: func(cmd *cobra.Command, args []string) error {
			return listSets()
		},
	}
	return c
}

func listSets() error {
	conn, err := nftLib.New()
	if err != nil {
		return errors.WithMessage(err, "failed to create netlink connection")
	}
	defer conn.CloseLasting() //nolint:errcheck

	return listTables(conn, func(table *nftLib.Table) ([]nftenc.Encoder, error) {
		return nftlist.SetEncoders(conn, table)
	})
}
