package cmd

import (
	"fmt"

	"github.com/PRO-Robotech/nft-go/pkg/nftenc"
	"github.com/PRO-Robotech/nft-go/pkg/nftlist"

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
	encs, err := nftlist.TablesEncodersFunc(conn, fn)
	if err != nil {
		return err
	}
	for _, enc := range encs {
		tblTxt, err := enc.Format()
		if err != nil {
			return err
		}
		fmt.Println(tblTxt)
	}

	return nil
}
