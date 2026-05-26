package nftenc

import (
	"encoding/json"
	"fmt"
	"strings"

	nftLib "github.com/google/nftables"
)

type (
	// TableEncoder is an encoder for a table.
	// It implements the Encoder interface.
	TableEncoder struct {
		table *nftLib.Table
		items []Encoder
	}

	// TableFamily is a type for table family.
	TableFamily nftLib.TableFamily
)

var _ Encoder = (*TableEncoder)(nil)

// NewTableEncoder creates a new TableEncoder.
// It takes a table and a list of items to encode.
// The items must be of type *RuleEncoder.
// If an item is not of type *RuleEncoder, it panics.
func NewTableEncoder(t *nftLib.Table, items ...Encoder) *TableEncoder {
	for _, item := range items {
		switch item.(type) {
		case *SetEncoder:
		case *ChainEncoder:
		default:
			panic(fmt.Sprintf("unsupported table item type %T", item))
		}
	}
	return &TableEncoder{table: t, items: items}
}

// String returns the string representation of the table without error checking.
func (enc *TableEncoder) String() string {
	str, _ := enc.Format()
	return str
}

// MustString returns the string representation of the table.
// It panics if the table is not valid or if there are any
// issues formatting table items.
func (enc *TableEncoder) MustString() string {
	str, err := enc.Format()
	if err != nil {
		panic(err)
	}
	return str
}

// Format returns the string representation of the table.
// It returns an error if the table is not valid or if there are any
// issues formatting table items.
// The table is formatted as:
//
//	table <family> <name> {
//	  <item1>
//	  <item2>
//	  ...
//	}
func (enc *TableEncoder) Format() (string, error) {
	tbl := enc.table
	sb := strings.Builder{}
	m := enc.ItemsToMap()

	write := func(typ Encoder) error {
		if group, ok := m[fmt.Sprintf("%T", typ)]; ok {
			str, err := enc.formatItems(group...)
			if err != nil {
				return err
			}
			sb.WriteString(str)
		}
		return nil
	}

	sb.WriteString(fmt.Sprintf("table %s %s {\n", TableFamily(tbl.Family), tbl.Name))
	if err := write((*SetEncoder)(nil)); err != nil {
		return "", err
	}
	if err := write((*ChainEncoder)(nil)); err != nil {
		return "", err
	}
	sb.WriteByte('}')
	return sb.String(), nil
}

// MarshalJSON encodes the table to JSON.
func (enc *TableEncoder) MarshalJSON() ([]byte, error) {
	t := struct {
		Family string `json:"family"`
		Name   string `json:"name"`
	}{
		Family: TableFamily(enc.table.Family).String(),
		Name:   enc.table.Name,
	}

	tbl, err := json.Marshal(map[string]any{"table": t})
	if err != nil {
		return nil, err
	}
	out := append([]json.RawMessage(nil), tbl)
	m := enc.ItemsToMap()
	encode := func(typ Encoder) error {
		if group, ok := m[fmt.Sprintf("%T", typ)]; ok {
			for _, item := range group {
				itemJson, e := item.MarshalJSON()
				if e != nil {
					return e
				}
				if len(itemJson) > 0 {
					out = append(out, itemJson)
				}
				if ch, ok := item.(*ChainEncoder); ok {
					var ruleJson []byte
					for _, rule := range ch.rules {
						ruleJson, e = rule.MarshalJSON()
						if e != nil {
							return e
						}
						out = append(out, ruleJson)
					}
				}
			}
		}
		return nil
	}
	if err = encode((*SetEncoder)(nil)); err != nil {
		return nil, err
	}

	if err = encode((*ChainEncoder)(nil)); err != nil {
		return nil, err
	}

	return json.Marshal(out)
}

func (enc *TableEncoder) ItemsToMap() map[string][]Encoder {
	m := make(map[string][]Encoder)
	for _, item := range enc.items {
		if item == nil {
			continue
		}
		key := fmt.Sprintf("%T", item)
		m[key] = append(m[key], item)
	}
	return m
}

func (enc *TableEncoder) formatItems(items ...Encoder) (string, error) {
	sb := strings.Builder{}
	for _, item := range items {
		if item == nil {
			continue
		}
		itemStr, err := item.Format()
		if err != nil {
			return "", err
		}
		if itemStr == "" {
			continue
		}
		sb.WriteByte('\t')
		sb.WriteString(itemStr)
		sb.WriteByte('\n')
	}
	return sb.String(), nil
}

// String returns the string representation of the table family.
// It returns "unspec" for unspecified family
func (t TableFamily) String() string {
	switch nftLib.TableFamily(t) {
	case nftLib.TableFamilyUnspecified:
		return "unspec"
	case nftLib.TableFamilyINet:
		return "inet"
	case nftLib.TableFamilyIPv4:
		return "ip"
	case nftLib.TableFamilyIPv6:
		return "ip6"
	case nftLib.TableFamilyARP:
		return "arp"
	case nftLib.TableFamilyNetdev:
		return "netdev"
	case nftLib.TableFamilyBridge:
		return "bridge"
	}
	return "unknown" //nolint:goconst
}
