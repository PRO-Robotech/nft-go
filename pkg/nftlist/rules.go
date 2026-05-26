package nftlist

import (
	"github.com/PRO-Robotech/nft-go/pkg/nftenc"

	nftLib "github.com/google/nftables"
	"github.com/pkg/errors"
)

// RuleEncoders -
func RuleEncoders(conn *nftLib.Conn, table *nftLib.Table, chain *nftLib.Chain) ([]*nftenc.RuleEncoder, error) {
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
