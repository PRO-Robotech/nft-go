package nftenc

import (
	"encoding/json"
	"fmt"
	"strings"

	nftLib "github.com/google/nftables"
)

type (
	SetEncoder struct {
		set      *nftLib.Set
		elemsEnc *SetElemsEncoder
	}
)

var _ Encoder = (*SetEncoder)(nil)

func NewSetEncoder(s *nftLib.Set, elemsEnc *SetElemsEncoder) *SetEncoder {
	return &SetEncoder{set: s, elemsEnc: elemsEnc}
}

func (enc *SetEncoder) String() string {
	str, _ := enc.Format()
	return str
}
func (enc *SetEncoder) MustString() string {
	str, err := enc.Format()
	if err != nil {
		panic(err)
	}
	return str
}
func (enc *SetEncoder) Format() (string, error) {
	sb := strings.Builder{}
	s := enc.set
	if s.Anonymous {
		return "", nil
	}

	sb.WriteString(fmt.Sprintf("set %s {\n\t\ttype %s\n\t\tflags %s\n\t\telements = { ",
		s.Name, s.KeyType.Name, strings.Join(enc.FlagsToStringLinst(), ",")))

	elems, err := enc.elemsEnc.Format()
	if err != nil {
		return "", err
	}
	sb.WriteString(elems)

	sb.WriteString(" }\n\t}")
	return sb.String(), nil
}

func (enc *SetEncoder) MarshalJSON() ([]byte, error) {
	if enc.set.Anonymous {
		return nil, nil
	}
	set := struct {
		Family   string   `json:"family"`
		Name     string   `json:"name"`
		Table    string   `json:"table"`
		Type     string   `json:"type"`
		Flags    []string `json:"flags"`
		Elements any      `json:"elem"`
	}{
		Family:   TableFamily(enc.set.Table.Family).String(),
		Name:     enc.set.Name,
		Table:    enc.set.Table.Name,
		Type:     enc.set.KeyType.Name,
		Flags:    enc.FlagsToStringLinst(),
		Elements: enc.elemsEnc,
	}

	return json.Marshal(map[string]any{"set": set})
}

func (enc *SetEncoder) FlagsToStringLinst() (flags []string) {
	s := enc.set
	if s.Constant {
		flags = append(flags, "constant")
	}

	if s.Anonymous {
		flags = append(flags, "anonymous")
	}

	if s.Interval {
		flags = append(flags, "interval")
	}

	if s.IsMap {
		flags = append(flags, "map")
	}

	if s.HasTimeout {
		flags = append(flags, "timeout")
	}

	if s.Concatenation {
		flags = append(flags, "concatenation")
	}

	return flags
}

func (enc *SetEncoder) Value() *nftLib.Set {
	return enc.set
}

func (enc *SetEncoder) Items() []SetElement {
	if enc.elemsEnc == nil {
		return nil
	}
	return enc.elemsEnc.Elems
}
