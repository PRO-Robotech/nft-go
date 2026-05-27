package encoders

import (
	"fmt"
	"math/big"
	"sort"
	"strings"

	"github.com/H-BF/corlib/pkg/dict"
	rb "github.com/PRO-Robotech/nft-go/internal/bytes"
	"github.com/google/nftables"
)

type (
	setEncoder struct {
		set setEntry
	}
	setIR struct {
		setEntry
	}
)

func (s *setEncoder) EncodeIR(ctx *ctx) (irNode, error) {
	return &setIR{setEntry: s.set}, nil
}

func (s *setIR) Format() string {
	if !s.Anonymous {
		return fmt.Sprintf("@%s", s.Name)
	}

	parts := s.elemStrings()

	var b strings.Builder
	b.WriteByte('{')
	for i, p := range parts {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(p)
	}
	b.WriteByte('}')
	return b.String()
}

func (s *setIR) elemStrings() []string {
	const ipv4Bits, ipv6Bits = 32, 128
	if !s.Interval {
		out := make([]string, 0, len(s.elems))
		for _, e := range s.elems {
			out = append(out, s.keyToString(e.Key))
		}
		return out
	}

	sorted := s.sortedElems()
	switch s.KeyType {
	case nftables.TypeIPAddr:
		return intervalIPStrings(sorted, ipv4Bits)
	case nftables.TypeIP6Addr:
		return intervalIPStrings(sorted, ipv6Bits)
	}

	out := make([]string, 0, len(sorted))
	for i := 0; i < len(sorted); i++ {
		start := sorted[i]
		if start.IntervalEnd {
			continue
		}
		var end *nftables.SetElement
		if i+1 < len(sorted) && sorted[i+1].IntervalEnd {
			end = &sorted[i+1]
			i++
		}
		out = append(out, s.formatIntervalKey(start.Key, end))
	}
	return out
}

func (s *setIR) sortedElems() []nftables.SetElement {
	out := make([]nftables.SetElement, len(s.elems))
	copy(out, s.elems)
	sort.SliceStable(out, func(i, j int) bool {
		return rb.RawBytes(out[i].Key).Uint64() < rb.RawBytes(out[j].Key).Uint64()
	})
	return out
}

func (s *setIR) formatIntervalKey(startKey []byte, end *nftables.SetElement) string {
	startStr := s.keyToString(startKey)
	if end == nil {
		return startStr
	}
	endInt := new(big.Int).SetBytes(end.Key)
	lastInt := new(big.Int).Sub(endInt, big.NewInt(1))
	lastBytes := make([]byte, len(startKey))
	lb := lastInt.Bytes()
	copy(lastBytes[len(lastBytes)-len(lb):], lb)
	return fmt.Sprintf("%s-%s", startStr, s.keyToString(lastBytes))
}

func intervalIPStrings(sorted []nftables.SetElement, bits int) []string {
	out := make([]string, 0, len(sorted))
	for i := 0; i < len(sorted); i++ {
		start := sorted[i]
		if start.IntervalEnd {
			continue
		}
		var end *nftables.SetElement
		if i+1 < len(sorted) && sorted[i+1].IntervalEnd {
			end = &sorted[i+1]
			i++
		}
		out = append(out, formatIPInterval(start.Key, end, bits))
	}
	return out
}

func formatIPInterval(startKey []byte, end *nftables.SetElement, bits int) string {
	startIP := rb.RawBytes(startKey).Ip().String()
	if end == nil {
		return startIP
	}

	startInt := new(big.Int).SetBytes(startKey)
	endInt := new(big.Int).SetBytes(end.Key)
	size := new(big.Int).Sub(endInt, startInt)

	if size.Sign() <= 0 || size.Cmp(big.NewInt(1)) == 0 {
		return startIP
	}

	bitLen := size.BitLen() - 1
	pow := new(big.Int).Lsh(big.NewInt(1), uint(bitLen)) //nolint:gosec
	if size.Cmp(pow) == 0 && new(big.Int).Mod(startInt, size).Sign() == 0 {
		return fmt.Sprintf("%s/%d", startIP, bits-bitLen)
	}

	lastBytes := make([]byte, len(startKey))
	last := new(big.Int).Sub(endInt, big.NewInt(1)).Bytes()
	copy(lastBytes[len(lastBytes)-len(last):], last)
	return fmt.Sprintf("%s-%s", startIP, rb.RawBytes(lastBytes).Ip().String())
}

func (s *setIR) keyToString(k []byte) string {
	switch s.KeyType {
	case nftables.TypeVerdict,
		nftables.TypeString,
		nftables.TypeIFName:
		return rb.RawBytes(k).String()

	case nftables.TypeIPAddr,
		nftables.TypeIP6Addr:
		return rb.RawBytes(k).Ip().String()

	case nftables.TypeBitmask,
		nftables.TypeLLAddr,
		nftables.TypeEtherAddr,
		nftables.TypeTCPFlag,
		nftables.TypeMark,
		nftables.TypeUID,
		nftables.TypeGID:
		return rb.RawBytes(k).Text(rb.BaseHex)

	default:
		return rb.RawBytes(k).Text(rb.BaseDec)
	}
}

type (
	setCache struct {
		dict.HDict[setKey, setEntry]
	}
	setEntry struct {
		nftables.Set
		elems []nftables.SetElement
	}

	setKey struct {
		tableName string
		setName   string
		setId     uint32
	}
)

func (s *setCache) RefreshFromTable(t *nftables.Table) error {
	conn, err := nftables.New()
	if err != nil {
		return err
	}
	defer func() { _ = conn.CloseLasting() }()
	sets, err := conn.GetSets(t)
	if err != nil {
		return err
	}
	for _, set := range sets {
		if set != nil {
			elems, err := conn.GetSetElements(set)
			if err != nil {
				return err
			}
			s.Put(setKey{
				tableName: set.Table.Name,
				setName:   set.Name,
				setId:     set.ID,
			}, setEntry{
				Set:   *set,
				elems: elems,
			})
		}
	}
	return nil
}
