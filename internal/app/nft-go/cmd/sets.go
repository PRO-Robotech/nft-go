package cmd

import (
	"github.com/PRO-Robotech/nft-go/pkg/nftenc"

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
		return getSetEncoders(conn, table)
	})
}

func getSetEncoders(conn *nftLib.Conn, table *nftLib.Table) ([]nftenc.Encoder, error) {
	var encs []nftenc.Encoder

	sets, err := conn.GetSets(table)
	if err != nil {
		return nil, errors.WithMessagef(
			err, "failed to obtain list of sets from the netfilter for the table name='%s' family='%s'",
			table.Name, nftenc.TableFamily(table.Family),
		)
	}

	for _, set := range sets {
		elems, err := conn.GetSetElements(set)
		if err != nil {
			return nil, errors.WithMessagef(err, "failed to obtain set elements for the set='%s'", set.Name)
		}
		encs = append(encs, nftenc.NewSetEncoder(set, nftenc.NewSetElemsEncoder(set.KeyType, elems)))
	}
	return encs, nil
}
