package nftlist

import (
	"github.com/PRO-Robotech/nft-go/pkg/nftenc"

	nftLib "github.com/google/nftables"
	"github.com/pkg/errors"
)

type ruleEncFn func(*nftLib.Chain) ([]*nftenc.RuleEncoder, error)

// ChainEncoders -
func ChainEncoders(conn *nftLib.Conn, table *nftLib.Table, f ruleEncFn) ([]nftenc.Encoder, error) {
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
