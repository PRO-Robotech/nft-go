package cmd

import (
	"github.com/PRO-Robotech/nft-go/pkg/nftenc"

	nftLib "github.com/google/nftables"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

type ruleEncFn func(*nftLib.Chain) ([]*nftenc.RuleEncoder, error)

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
		chainEncs, err := getChainEncoders(conn, table, nil)
		if err != nil {
			return nil, err
		}
		return append(encs, chainEncs...), nil
	})
}

func getChainEncoders(conn *nftLib.Conn, table *nftLib.Table, f ruleEncFn) ([]nftenc.Encoder, error) {
	var encs []nftenc.Encoder
	chains, err := conn.ListChainsOfTableFamily(table.Family)
	if err != nil {
		return nil, errors.WithMessagef(err,
			"failed to obtain list of chains from the netfilter for the table family='%s'",
			nftenc.TableFamily(table.Family),
		)
	}
	for _, chain := range chains {
		var rlEncs []*nftenc.RuleEncoder
		if f != nil {
			rlEncs, err = f(chain)
		}
		if err != nil {
			return nil, err
		}

		encs = append(encs, nftenc.NewChainEncoder(chain, rlEncs...))
	}

	return encs, nil
}
