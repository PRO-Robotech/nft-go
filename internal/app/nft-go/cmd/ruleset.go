package cmd

import (
	"github.com/PRO-Robotech/nft-go/pkg/nftenc"
	"github.com/PRO-Robotech/nft-go/pkg/nftlist"

	nftLib "github.com/google/nftables"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func newRuleSetCommand() *cobra.Command {
	c := &cobra.Command{
		Use:   "ruleset",
		Short: "list ruleset",
		RunE: func(cmd *cobra.Command, args []string) error {
			return listRuleSets()
		},
	}
	return c
}

func listRuleSets() error {
	conn, err := nftLib.New()
	if err != nil {
		return errors.WithMessage(err, "failed to create netlink connection")
	}
	defer conn.CloseLasting() //nolint:errcheck

	return listTables(conn, func(table *nftLib.Table) ([]nftenc.Encoder, error) {
		var encs []nftenc.Encoder
		setEncs, err := nftlist.SetEncoders(conn, table)
		if err != nil {
			return nil, err
		}
		encs = append(encs, setEncs...)
		chainEncs, err := nftlist.ChainEncoders(conn, table, func(chain *nftLib.Chain) ([]*nftenc.RuleEncoder, error) {
			return nftlist.RuleEncoders(conn, table, chain)
		})
		if err != nil {
			return nil, err
		}
		return append(encs, chainEncs...), nil
	})
}
