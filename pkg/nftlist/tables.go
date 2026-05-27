package nftlist

import (
	"strings"

	"github.com/PRO-Robotech/nft-go/pkg/nftenc"

	nftLib "github.com/google/nftables"
	"github.com/pkg/errors"
)

type (
	// TablesOutput -
	TablesOutput struct {
		Text string
		JSON string
		Raw  []nftenc.RawTable
	}
)

// Tables -
func Tables(opts ...listOpt) (ret TablesOutput, err error) {
	var cfg listOpts
	for _, opt := range opts {
		opt.apply(&cfg)
	}

	encs, err := TablesEncoders()
	if err != nil {
		return ret, err
	}

	return TablesFromEncoders(encs, opts...)
}

// TablesFromEncoders -
func TablesFromEncoders(encs []*nftenc.TableEncoder, opts ...listOpt) (ret TablesOutput, err error) {
	var cfg listOpts
	for _, opt := range opts {
		opt.apply(&cfg)
	}
	var text strings.Builder
	jsonParts := make([]string, 0, len(encs))

	for _, enc := range encs {
		if !cfg.noRawOut {
			ret.Raw = append(ret.Raw, enc.Raw())
		}
		if !cfg.noTextOut {
			tblText, err := enc.Format()
			if err != nil {
				return ret, err
			}
			text.WriteString(tblText)
			text.WriteByte('\n')
		}

		if !cfg.noJSONOut {
			rawJSON, err := enc.MarshalJSON()
			if err != nil {
				return ret, err
			}
			if part := strings.TrimSpace(strings.Trim(string(rawJSON), "[]")); part != "" {
				jsonParts = append(jsonParts, part)
			}
		}
	}

	if !cfg.noTextOut {
		ret.Text = text.String()
	}
	if !cfg.noJSONOut {
		ret.JSON = "[" + strings.Join(jsonParts, ",") + "]"
	}

	return ret, nil
}

// TablesEncoders -
func TablesEncoders() ([]*nftenc.TableEncoder, error) {
	conn, err := nftLib.New()
	if err != nil {
		return nil, errors.WithMessage(err, "on create netlink connection")
	}
	defer conn.CloseLasting() //nolint:errcheck

	return TablesEncodersFunc(conn, func(table *nftLib.Table) ([]nftenc.Encoder, error) {
		var encs []nftenc.Encoder
		setEncs, e := SetEncoders(conn, table)
		if e != nil {
			return nil, e
		}
		encs = append(encs, setEncs...)
		var chainEncs []nftenc.Encoder
		chainEncs, e = ChainEncoders(conn, table, func(chain *nftLib.Chain) ([]*nftenc.RuleEncoder, error) {
			return RuleEncoders(conn, table, chain)
		})
		if e != nil {
			return nil, e
		}
		return append(encs, chainEncs...), nil
	})
}

// TablesEncodersFunc -
func TablesEncodersFunc(conn *nftLib.Conn, fn func(*nftLib.Table) ([]nftenc.Encoder, error)) (ret []*nftenc.TableEncoder, err error) {
	tables, err := conn.ListTables()
	if err != nil {
		return nil, errors.WithMessage(err, "failed to obtain list of tables from the netfilter")
	}

	var encs []nftenc.Encoder
	for _, table := range tables {
		if fn != nil {
			encs, err = fn(table)
		}
		if err != nil {
			return nil, err
		}
		ret = append(ret, nftenc.NewTableEncoder(table, encs...))
	}
	return ret, nil
}
