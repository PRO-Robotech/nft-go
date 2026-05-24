package cmd

import (
	"fmt"

	"github.com/PRO-Robotech/nft-go/pkg/nftenc"

	nftLib "github.com/google/nftables"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

func newTablesCommand() *cobra.Command {
	c := &cobra.Command{
		Use:   "tables",
		Short: "list tables",
		RunE: func(cmd *cobra.Command, args []string) error {
			conn, err := nftLib.New()
			if err != nil {
				return errors.WithMessage(err, "failed to create netlink connection")
			}
			defer conn.CloseLasting() //nolint:errcheck

			return listTables(conn, nil)
		},
	}
	return c
}

func listTables(conn *nftLib.Conn, fn func(*nftLib.Table) ([]nftenc.Encoder, error)) error {
	tables, err := conn.ListTables()
	if err != nil {
		return errors.WithMessage(err, "failed to obtain list of tables from the netfilter")
	}

	for _, table := range tables {
		var encs []nftenc.Encoder
		if fn != nil {
			encs, err = fn(table)
		}
		if err != nil {
			return err
		}
		tblTxt, err := nftenc.NewTableEncoder(table, encs...).Format()
		if err != nil {
			return err
		}
		fmt.Println(tblTxt)
	}
	return nil
}
