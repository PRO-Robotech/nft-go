package cmd

import (
	"github.com/PRO-Robotech/nft-go/pkg/nftenc"
	"github.com/PRO-Robotech/nft-go/pkg/nftlist"

	nftLib "github.com/google/nftables"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func newChainsCommand() *cobra.Command {
	c := &cobra.Command{
		Use:   "chains",
		Short: "list chains",
		RunE: func(cmd *cobra.Command, args []string) error {
			return listChains()
		},
	}
	return c
}

func listChains() error {
	conn, err := nftLib.New()
	if err != nil {
		return errors.WithMessage(err, "failed to create netlink connection")
	}
	defer conn.CloseLasting() //nolint:errcheck

	return listTables(conn, func(table *nftLib.Table) ([]nftenc.Encoder, error) {
		var encs []nftenc.Encoder
		chainEncs, err := nftlist.ChainEncoders(conn, table, nil)
		if err != nil {
			return nil, err
		}
		return append(encs, chainEncs...), nil
	})
}
