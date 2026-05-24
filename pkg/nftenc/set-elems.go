package nftenc

import (
	"encoding/json"
	"fmt"
	"strings"

	rb "github.com/PRO-Robotech/nft-go/internal/bytes"

	linq "github.com/ahmetb/go-linq/v3"
	nftLib "github.com/google/nftables"
)

type (
	SetElemsEncoder struct {
		SetType nftLib.SetDatatype
		Elems   SetElems
	}

	SetElement nftLib.SetElement
	SetElems   []SetElement
)

var _ Encoder = (*SetElemsEncoder)(nil)

func NewSetElemsEncoder(setType nftLib.SetDatatype, elems []nftLib.SetElement) *SetElemsEncoder {
	s := make(SetElems, len(elems))
	for i := range elems {
		s[i] = SetElement(elems[i])
	}
	return &SetElemsEncoder{
		SetType: setType,
		Elems:   s,
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
	elems := enc.Elems.ToStringListOrderedByType(enc.SetType)
	return strings.Join(elems, ", "), nil
}

func (enc *SetElemsEncoder) MarshalJSON() ([]byte, error) {
	elems := enc.Elems.ToStringListOrderedByType(enc.SetType)

	return json.Marshal(elems)
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
	rb.RawBytes(s.Key).Uint64()
	return rb.RawBytes(s.Key).Ip().String()
}

func (s SetElementTypeHex) String() string {
	return rb.RawBytes(s.Key).Text(baseHex)
}

func (s SetElementTypeDec) String() string {
	return rb.RawBytes(s.Key).Text(baseDec)
}
