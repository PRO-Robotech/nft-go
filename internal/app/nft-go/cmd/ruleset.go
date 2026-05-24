package cmd

import (
	"github.com/PRO-Robotech/nft-go/pkg/nftenc"

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
		setEncs, err := getSetEncoders(conn, table)
		if err != nil {
			return nil, err
		}
		encs = append(encs, setEncs...)
		chainEncs, err := getChainEncoders(conn, table, func(chain *nftLib.Chain) ([]*nftenc.RuleEncoder, error) {
			return getRuleEncoders(conn, table, chain)
		})
		if err != nil {
			return nil, err
		}
		return append(encs, chainEncs...), nil
	})
}

func getRuleEncoders(conn *nftLib.Conn, table *nftLib.Table, chain *nftLib.Chain) ([]*nftenc.RuleEncoder, error) {
	var encs []*nftenc.RuleEncoder
	rules, err := conn.GetRules(table, chain)
	if err != nil {
		return nil, errors.WithMessagef(
			err, "failed to obtain rules from the netfilter for the table name='%s' family='%s' and chain=%s",
			table.Name, nftenc.TableFamily(table.Family), chain.Name,
		)
	}
	for _, rule := range rules {
		encs = append(encs, nftenc.NewRuleEncoder(rule))
	}
	return encs, nil
}
