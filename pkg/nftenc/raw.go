package nftenc

import nftLib "github.com/google/nftables"

type (
	// RawTable is a structural (non-textual) view of a table and its children
	RawTable struct {
		Table  *nftLib.Table
		Chains []RawChain
		Sets   []RawSet
	}
	// RawChain pairs a chain with its rules.
	RawChain struct {
		Chain *nftLib.Chain
		Rules []*nftLib.Rule
	}

	// RawSet pairs a set with its elements.
	RawSet struct {
		Set   *nftLib.Set
		Elems []SetElement
	}
)

func extractRawFromEncoder(enc *TableEncoder) (ret RawTable) {
	if enc == nil {
		return ret
	}
	ret = RawTable{Table: enc.table}
	for _, child := range enc.items {
		switch t := child.(type) {
		case *ChainEncoder:
			if v := t.Value(); v != nil {
				ret.Chains = append(ret.Chains, RawChain{Chain: v, Rules: t.Items()})
			}
		case *SetEncoder:
			if v := t.Value(); v != nil {
				ret.Sets = append(ret.Sets, RawSet{Set: v, Elems: t.Items()})
			}
		}
	}
	return ret
}
