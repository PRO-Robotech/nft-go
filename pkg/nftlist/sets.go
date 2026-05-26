package nftlist

import (
	"github.com/PRO-Robotech/nft-go/pkg/nftenc"

	nftLib "github.com/google/nftables"
	"github.com/pkg/errors"
)

// SetEncoders -
func SetEncoders(conn *nftLib.Conn, table *nftLib.Table) ([]nftenc.Encoder, error) {
	var encs []nftenc.Encoder

	sets, err := conn.GetSets(table)
	if err != nil {
		return nil, errors.WithMessagef(
			err, "failed to obtain list of sets from the netfilter for the table name='%s' family='%s'",
			table.Name, nftenc.TableFamily(table.Family),
		)
	}
	var elems []nftLib.SetElement
	for _, set := range sets {
		elems, err = conn.GetSetElements(set)
		if err != nil {
			return nil, errors.WithMessagef(err, "failed to obtain set elements for the set='%s'", set.Name)
		}
		encs = append(encs, nftenc.NewSetEncoder(set, nftenc.NewSetElemsEncoder(set.KeyType, set.Interval, elems)))
	}
	return encs, nil
}
