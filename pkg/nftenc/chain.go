package nftenc

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	nftLib "github.com/google/nftables"
	"github.com/samber/lo"
)

type (
	ChainEncoder struct {
		chain *nftLib.Chain
		rules []*RuleEncoder
	}

	ChainHook     nftLib.ChainHook
	ChainPriority nftLib.ChainPriority
	ChainPolicy   nftLib.ChainPolicy
)

var _ Encoder = (*ChainEncoder)(nil)

func NewChainEncoder(c *nftLib.Chain, rules ...*RuleEncoder) *ChainEncoder {
	return &ChainEncoder{chain: c, rules: rules}
}
func (enc *ChainEncoder) String() string {
	str, _ := enc.Format()
	return str
}
func (enc *ChainEncoder) MustString() string {
	str, err := enc.Format()
	if err != nil {
		panic(err)
	}
	return str
}
func (enc *ChainEncoder) Format() (string, error) {
	sb := strings.Builder{}
	chain := enc.chain
	sb.WriteString(fmt.Sprintf("chain %s { # handle %d\n", chain.Name, chain.Handle))
	if chain.Type != "" || chain.Hooknum != nil || chain.Priority != nil || chain.Policy != nil {
		sb.WriteString("\t\t")
		if chain.Type != "" {
			sb.WriteString(fmt.Sprintf("type %s ", chain.Type))
		}
		if chain.Hooknum != nil {
			sb.WriteString(fmt.Sprintf("hook %s ", ChainHook(*chain.Hooknum)))
		}
		if chain.Priority != nil {
			sb.WriteString(fmt.Sprintf("priority %s; ", ChainPriority(*chain.Priority)))
		}
		if chain.Policy != nil {
			sb.WriteString(fmt.Sprintf("policy %s;", ChainPolicy(*chain.Policy)))
		}
		sb.WriteByte('\n')
	}

	for _, rule := range enc.rules {
		if rule == nil {
			continue
		}
		human, err := rule.Format()
		if err != nil {
			return "", err
		}
		if human == "" {
			continue
		}
		sb.WriteString("\t\t")
		sb.WriteString(human)
		sb.WriteByte('\n')
	}
	sb.WriteString("\t}")
	return sb.String(), nil
}
func (enc *ChainEncoder) MarshalJSON() ([]byte, error) {
	chain := struct {
		Family   string           `json:"family"`
		Table    string           `json:"table"`
		Name     string           `json:"name"`
		Handle   uint64           `json:"handle"`
		Type     nftLib.ChainType `json:"type,omitempty"`
		Hook     string           `json:"hook,omitempty"`
		Priority string           `json:"priority,omitempty"`
		Policy   string           `json:"policy,omitempty"`
	}{
		Family: TableFamily(enc.chain.Table.Family).String(),
		Table:  enc.chain.Table.Name,
		Handle: enc.chain.Handle,
		Name:   enc.chain.Name,
		Type:   enc.chain.Type,
	}
	if enc.chain.Hooknum != nil {
		chain.Hook = ChainHook(*enc.chain.Hooknum).String()
	}
	if enc.chain.Priority != nil {
		chain.Priority = ChainPriority(*enc.chain.Priority).String()
	}
	if enc.chain.Policy != nil {
		chain.Policy = ChainPolicy(*enc.chain.Policy).String()
	}

	return json.Marshal(map[string]any{"chain": chain})
}

func (enc *ChainEncoder) Value() *nftLib.Chain {
	return enc.chain
}

func (enc *ChainEncoder) Items() []*nftLib.Rule {
	return lo.Map(enc.rules, func(r *RuleEncoder, _ int) *nftLib.Rule { return r.rule })
}

func (c ChainHook) String() string {
	switch nftLib.ChainHook(c) {
	case *nftLib.ChainHookPrerouting:
		return "prerouting"
	case *nftLib.ChainHookInput:
		return "input"
	case *nftLib.ChainHookForward:
		return "forward"
	case *nftLib.ChainHookOutput:
		return "output"
	case *nftLib.ChainHookPostrouting:
		return "postrouting"
	case *nftLib.ChainHookIngress:
		return "ingress"
	}
	return "unknown" //nolint:goconst
}

func (c ChainPriority) String() string {
	return strconv.FormatInt(int64(int32(c)), 10)
}

func (p ChainPolicy) String() string {
	switch nftLib.ChainPolicy(p) {
	case nftLib.ChainPolicyDrop:
		return "drop"
	case nftLib.ChainPolicyAccept:
		return "accept"
	}
	return "unknown"
}
