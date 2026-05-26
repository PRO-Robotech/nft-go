package nftenc

import (
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	rb "github.com/PRO-Robotech/nft-go/internal/bytes"

	linq "github.com/ahmetb/go-linq/v3"
	nftLib "github.com/google/nftables"
)

type (
	SetElemsEncoder struct {
		SetType  nftLib.SetDatatype
		Interval bool
		Elems    SetElems
	}

	SetElement nftLib.SetElement
	SetElems   []SetElement
)

var _ Encoder = (*SetElemsEncoder)(nil)

func NewSetElemsEncoder(setType nftLib.SetDatatype, interval bool, elems []nftLib.SetElement) *SetElemsEncoder {
	s := make(SetElems, len(elems))
	for i := range elems {
		s[i] = SetElement(elems[i])
	}
	return &SetElemsEncoder{
		SetType:  setType,
		Interval: interval,
		Elems:    s,
	}
}

func (enc *SetElemsEncoder) String() string {
	str, _ := enc.Format()
	return str
}

func (enc *SetElemsEncoder) MustString() string {
	str, err := enc.Format()
	if err != nil {
		panic(err)
	}
	return str
}

func (enc *SetElemsEncoder) Format() (string, error) {
	return strings.Join(enc.toStringList(), ", "), nil
}

func (enc *SetElemsEncoder) MarshalJSON() ([]byte, error) {
	return json.Marshal(enc.toStringList())
}

func (enc *SetElemsEncoder) toStringList() []string {
	if enc.Interval && (enc.SetType == nftLib.TypeIPAddr || enc.SetType == nftLib.TypeIP6Addr) {
		return enc.Elems.toIPIntervalStrings(enc.SetType)
	}
	return enc.Elems.ToStringListOrderedByType(enc.SetType)
}

func (s SetElems) toIPIntervalStrings(typ nftLib.SetDatatype) []string {
	bits := 32
	if typ == nftLib.TypeIP6Addr {
		bits = 128
	}
	sorted := s.SortAs(typ)
	out := make([]string, 0, len(sorted))
	for i := 0; i < len(sorted); i++ {
		start := sorted[i]
		if start.IntervalEnd {
			continue
		}
		var end *SetElement
		if i+1 < len(sorted) && sorted[i+1].IntervalEnd {
			end = &sorted[i+1]
			i++
		}
		out = append(out, formatIPInterval(start.Key, end, bits))
	}
	return out
}

func formatIPInterval(startKey []byte, end *SetElement, bits int) string {
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
	pow := new(big.Int).Lsh(big.NewInt(1), uint(bitLen))
	if size.Cmp(pow) == 0 && new(big.Int).Mod(startInt, size).Sign() == 0 {
		return fmt.Sprintf("%s/%d", startIP, bits-bitLen)
	}

	lastBytes := make([]byte, len(startKey))
	last := new(big.Int).Sub(endInt, big.NewInt(1)).Bytes()
	copy(lastBytes[len(lastBytes)-len(last):], last)
	return fmt.Sprintf("%s-%s", startIP, rb.RawBytes(lastBytes).Ip().String())
}

func (s SetElems) ToStringListOrderedByType(setType nftLib.SetDatatype) []string {
	elems := make([]string, 0, len(s))
	formatter := getElementFormatter(setType)
	for _, elem := range s.SortAs(setType) {
		if elem.IntervalEnd {
			continue
		}
		elems = append(elems, formatter(elem).String())
	}
	return elems
}

func (s SetElems) SortAs(typ nftLib.SetDatatype) SetElems {
	sortedElements := make(SetElems, 0, len(s))
	linq.From(s).
		OrderBy(func(i interface{}) interface{} {
			elem := i.(SetElement)
			switch typ {
			case nftLib.TypeVerdict,
				nftLib.TypeString,
				nftLib.TypeIFName:
				return 0
			}
			return rb.RawBytes(elem.Key).Uint64()
		}).
		ToSlice(&sortedElements)

	return sortedElements
}

func getElementFormatter(typ nftLib.SetDatatype) func(elem SetElement) fmt.Stringer {
	return func(elem SetElement) fmt.Stringer {
		switch typ {
		case nftLib.TypeVerdict,
			nftLib.TypeString,
			nftLib.TypeIFName:
			return SetElementTypeString(elem)
		case nftLib.TypeIPAddr,
			nftLib.TypeIP6Addr:
			return SetElementTypeIp(elem)
		case nftLib.TypeBitmask,
			nftLib.TypeLLAddr,
			nftLib.TypeEtherAddr,
			nftLib.TypeTCPFlag,
			nftLib.TypeMark,
			nftLib.TypeUID,
			nftLib.TypeGID:
			return SetElementTypeHex(elem)
		}
		return SetElementTypeDec(elem)
	}
}

const (
	baseDec = 10
	baseHex = 16
)

type (
	SetElementTypeString SetElement
	SetElementTypeIp     SetElement
	SetElementTypeHex    SetElement
	SetElementTypeDec    SetElement
)

func (s SetElementTypeString) String() string {
	return rb.RawBytes(s.Key).String()
}

func (s SetElementTypeIp) String() string {
	return rb.RawBytes(s.Key).Ip().String()
}

func (s SetElementTypeHex) String() string {
	return rb.RawBytes(s.Key).Text(baseHex)
}

func (s SetElementTypeDec) String() string {
	return rb.RawBytes(s.Key).Text(baseDec)
}
