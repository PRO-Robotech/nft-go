package nftenc

import (
	"encoding/json"
	"fmt"
	"strings"

	exprenc "github.com/PRO-Robotech/nft-go/internal/expr-encoders"

	nftLib "github.com/google/nftables"
	userdata "github.com/google/nftables/userdata"
)

type (
	RuleEncoder struct {
		rule *nftLib.Rule
	}

	RuleNames struct {
		Names []string `json:"names"`
	}
)

var _ Encoder = (*RuleEncoder)(nil)

// NewRuleEncoder creates a new RuleEncoder
func NewRuleEncoder(r *nftLib.Rule) *RuleEncoder {
	return &RuleEncoder{rule: r}
}

// String returns a human-readable representation of a rule without errors
func (r *RuleEncoder) String() string {
	str, _ := r.Format()
	return str
}

// MustString returns a human-readable representation of a rule
// and panics if the rule is not valid
func (r *RuleEncoder) MustString() string {
	str, err := r.Format()
	if err != nil {
		panic(err)
	}
	return str
}

// Format returns a human-readable representation of a rule
// It returns an error if the rule is not valid
func (enc *RuleEncoder) Format() (string, error) {
	sb := strings.Builder{}
	expr, err := exprenc.NewRuleExprEncoder(enc.rule).Format()
	if err != nil {
		return "", err
	}
	if expr != "" {
		sb.WriteString(expr)
		if com := enc.Comment(); com != "" {
			sb.WriteString(fmt.Sprintf(" comment %q", com))
		}
		sb.WriteString(fmt.Sprintf(" # handle %d", enc.rule.Handle))
	}
	return sb.String(), nil
}

// MarshalJSON encodes the rule to JSON
func (enc *RuleEncoder) MarshalJSON() ([]byte, error) {
	rl := enc.rule

	rule := struct {
		Family  string `json:"family"`
		Table   string `json:"table"`
		Chain   string `json:"chain"`
		Handle  uint64 `json:"handle"`
		Comment string `json:"comment,omitempty"`
		Exprs   any    `json:"exprs"`
	}{
		Family:  TableFamily(rl.Table.Family).String(),
		Table:   rl.Table.Name,
		Chain:   rl.Chain.Name,
		Handle:  rl.Handle,
		Comment: enc.Comment(),
		Exprs:   exprenc.NewRuleExprEncoder(rl),
	}
	root := map[string]interface{}{
		"rule": rule,
	}

	return json.Marshal(root)
}

// Comment - return a rule comment
func (enc *RuleEncoder) Comment() (com string) {
	com, _ = userdata.GetString(enc.rule.UserData, userdata.TypeComment)
	return com
}
