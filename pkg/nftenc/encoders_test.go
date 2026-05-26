package nftenc

import (
	"fmt"
	"net"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/google/nftables/userdata"
	"github.com/stretchr/testify/suite"
	"golang.org/x/sys/unix"
)

type encodersTestSuite struct {
	suite.Suite
}

var comment = "{`names`:[`rule1`,`rule2`],`IPv`:4}"

func (sui *encodersTestSuite) Test_RulesEncode() {

	testCases := []struct {
		name        string
		rule        nftables.Rule
		expRuleStr  string
		expRuleJson []byte
	}{
		{
			name: "rule without comments",
			rule: nftables.Rule{
				Table: &nftables.Table{
					Name:   "filter",
					Family: nftables.TableFamilyIPv4,
				},
				Chain: &nftables.Chain{
					Name:     "FORWARD",
					Type:     nftables.ChainTypeFilter,
					Hooknum:  nftables.ChainHookForward,
					Priority: nftables.ChainPriorityFilter,
				},
				Handle: 1,
				Exprs: []expr.Any{
					&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
					&expr.Cmp{
						Op:       expr.CmpOpEq,
						Register: 1,
						Data:     []byte{unix.IPPROTO_TCP},
					},
					&expr.Counter{},
					&expr.Log{},
					&expr.Verdict{
						Kind: expr.VerdictAccept,
					},
				},
			},
			expRuleStr:  "counter packets 0 bytes 0 log accept # handle 1",
			expRuleJson: []byte(`{"rule":{"family":"ip","table":"filter","chain":"FORWARD","handle":1,"exprs":[{"match":{"op":"==","left":{"meta":{"key":"l4proto"}},"right":"tcp"}},{"counter":{"bytes":0,"packets":0}},{"log":null},{"accept":null}]}}`),
		},
		{
			name: "rule with comments",
			rule: nftables.Rule{
				Table: &nftables.Table{
					Name:   "filter",
					Family: nftables.TableFamilyIPv4,
				},
				Chain: &nftables.Chain{
					Name:     "FORWARD",
					Type:     nftables.ChainTypeFilter,
					Hooknum:  nftables.ChainHookForward,
					Priority: nftables.ChainPriorityFilter,
				},
				Handle: 1,
				Exprs: []expr.Any{
					&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
					&expr.Cmp{
						Op:       expr.CmpOpNeq,
						Register: 1,
						Data:     []byte("lo"),
					},
					&expr.Immediate{Register: 1, Data: []byte{1}},
					&expr.Meta{Key: expr.MetaKeyNFTRACE, SourceRegister: true, Register: 1},
					&expr.Verdict{
						Kind:  expr.VerdictGoto,
						Chain: "FW-OUT",
					},
				},
				UserData: userdata.AppendString([]byte(nil), userdata.TypeComment, comment),
			},
			expRuleStr:  fmt.Sprintf("oifname != lo meta nftrace set 1 goto FW-OUT comment %q # handle 1", comment),
			expRuleJson: []byte(fmt.Sprintf(`{"rule":{"family":"ip","table":"filter","chain":"FORWARD","handle":1,"comment":%q,"exprs":[{"match":{"op":"!=","left":{"meta":{"key":"oifname"}},"right":"lo"}},{"mangle":{"key":{"meta":{"key":"nftrace"}},"value":1}},{"goto":{"target":"FW-OUT"}}]}}`, comment)),
		},
	}

	for _, tc := range testCases {
		sui.Run(tc.name, func() {
			rlEnc := NewRuleEncoder(&tc.rule)
			str, err := rlEnc.Format()
			sui.Require().NoError(err)
			sui.Require().Equal(tc.expRuleStr, str)
			j, err := rlEnc.MarshalJSON()
			sui.Require().NoError(err)
			sui.Require().Equal(tc.expRuleJson, j)
		})
	}
}

func (sui *encodersTestSuite) Test_TableEncode() {
	policy := nftables.ChainPolicyAccept
	setName := "ipSet"
	tbl := &nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "filter",
	}
	chain := &nftables.Chain{
		Name:     "output",
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityFilter,
		Table:    tbl,
		Type:     nftables.ChainTypeFilter,
		Policy:   &policy,
	}
	testCases := []struct {
		name       string
		table      *nftables.Table
		set        *nftables.Set
		setElems   []nftables.SetElement
		chain      *nftables.Chain
		rule       *nftables.Rule
		expTextTbl string
		expJsonTbl []byte
	}{
		{
			name:  "basic table",
			table: tbl,
			set: &nftables.Set{
				Name:     setName,
				Table:    tbl,
				KeyType:  nftables.TypeIPAddr,
				Constant: true,
				Interval: true,
			},
			setElems: []nftables.SetElement{
				{
					Key: []byte(net.ParseIP("10.34.11.179").To4()),
				},
				{
					Key:         []byte(net.ParseIP("10.34.11.180").To4()),
					IntervalEnd: true,
				},
			},
			chain: chain,
			rule: &nftables.Rule{
				Table:  tbl,
				Chain:  chain,
				Handle: 5,
				Exprs: []expr.Any{
					&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
					&expr.Cmp{
						Op:       expr.CmpOpEq,
						Register: 1,
						Data:     []byte{unix.IPPROTO_TCP},
					},
					&expr.Counter{},
					&expr.Log{},
					&expr.Verdict{
						Kind: expr.VerdictAccept,
					},
				},
				UserData: userdata.AppendString([]byte(nil), userdata.TypeComment, comment),
			},
			expJsonTbl: fmt.Appendf(nil, `[{"table":{"family":"ip","name":"filter"}},{"set":{"family":"ip","name":"ipSet","table":"filter","type":"ipv4_addr","flags":["constant","interval"],"elem":["10.34.11.179"]}},{"chain":{"family":"ip","table":"filter","name":"output","handle":0,"type":"filter","hook":"output","priority":"0","policy":"accept"}},{"rule":{"family":"ip","table":"filter","chain":"output","handle":5,"comment":%q,"exprs":[{"match":{"op":"==","left":{"meta":{"key":"l4proto"}},"right":"tcp"}},{"counter":{"bytes":0,"packets":0}},{"log":null},{"accept":null}]}}]`, comment),
			expTextTbl: `table ip filter {
	set ipSet {
		type ipv4_addr
		flags constant,interval
		elements = { 10.34.11.179 }
	}
	chain output { # handle 0
		type filter hook output priority 0; policy accept;
		counter packets 0 bytes 0 log accept comment "` + comment + `" # handle 5
	}
}`,
		},
	}

	for _, tc := range testCases {
		sui.Run(tc.name, func() {
			tblEnc := NewTableEncoder(tc.table,
				NewSetEncoder(tc.set,
					NewSetElemsEncoder(tc.set.KeyType, tc.set.Interval, tc.setElems),
				),
				NewChainEncoder(tc.chain,
					NewRuleEncoder(tc.rule),
				),
			)
			str, err := tblEnc.Format()
			sui.Require().NoError(err)
			sui.Require().Equal(tc.expTextTbl, str)
			j, err := tblEnc.MarshalJSON()
			sui.Require().NoError(err)
			sui.Require().Equal(tc.expJsonTbl, j)
		})
	}
}

func Test_Encoders(t *testing.T) {
	suite.Run(t, new(encodersTestSuite))
}

func (sui *encodersTestSuite) Test_TableEncodeSkipsAnonymousSets() {
	tbl := &nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   "filter",
	}
	namedSet := &nftables.Set{
		Name:     "ipSet",
		Table:    tbl,
		KeyType:  nftables.TypeIPAddr,
		Constant: true,
		Interval: true,
	}
	namedElems := []nftables.SetElement{
		{Key: []byte(net.ParseIP("10.34.11.179").To4())},
		{Key: []byte(net.ParseIP("10.34.11.180").To4()), IntervalEnd: true},
	}
	anonSet := &nftables.Set{
		Name:      "__set0",
		Table:     tbl,
		KeyType:   nftables.TypeInetService,
		Anonymous: true,
		Constant:  true,
	}
	anonElems := []nftables.SetElement{
		{Key: binaryutil.BigEndian.PutUint16(80)},
		{Key: binaryutil.BigEndian.PutUint16(443), IntervalEnd: true},
	}

	tblEnc := NewTableEncoder(tbl,
		NewSetEncoder(namedSet, NewSetElemsEncoder(namedSet.KeyType, namedSet.Interval, namedElems)),
		NewSetEncoder(anonSet, NewSetElemsEncoder(anonSet.KeyType, anonSet.Interval, anonElems)),
	)

	expText := `table ip filter {
	set ipSet {
		type ipv4_addr
		flags constant,interval
		elements = { 10.34.11.179 }
	}
}`
	str, err := tblEnc.Format()
	sui.Require().NoError(err)
	sui.Require().Equal(expText, str)
	sui.Require().NotContains(str, "__set0")

	expJSON := []byte(`[{"table":{"family":"ip","name":"filter"}},{"set":{"family":"ip","name":"ipSet","table":"filter","type":"ipv4_addr","flags":["constant","interval"],"elem":["10.34.11.179"]}}]`)
	j, err := tblEnc.MarshalJSON()
	sui.Require().NoError(err)
	sui.Require().Equal(expJSON, j)
	sui.Require().NotContains(string(j), "__set0")
}

func (sui *encodersTestSuite) Test_SetElemsIntervalEncode() {
	testCases := []struct {
		name    string
		typ     nftables.SetDatatype
		elems   []nftables.SetElement
		expText string
	}{
		{
			name: "ipv4 /16 cidr",
			typ:  nftables.TypeIPAddr,
			elems: []nftables.SetElement{
				{Key: []byte(net.ParseIP("10.0.0.0").To4())},
				{Key: []byte(net.ParseIP("10.1.0.0").To4()), IntervalEnd: true},
			},
			expText: "10.0.0.0/16",
		},
		{
			name: "ipv4 range",
			typ:  nftables.TypeIPAddr,
			elems: []nftables.SetElement{
				{Key: []byte(net.ParseIP("1.0.0.0").To4())},
				{Key: []byte(net.ParseIP("1.0.0.6").To4()), IntervalEnd: true},
			},
			expText: "1.0.0.0-1.0.0.5",
		},
		{
			name: "ipv4 single host",
			typ:  nftables.TypeIPAddr,
			elems: []nftables.SetElement{
				{Key: []byte(net.ParseIP("10.0.3.1").To4())},
				{Key: []byte(net.ParseIP("10.0.3.2").To4()), IntervalEnd: true},
			},
			expText: "10.0.3.1",
		},
		{
			name: "ipv6 single host",
			typ:  nftables.TypeIP6Addr,
			elems: []nftables.SetElement{
				{Key: []byte(net.ParseIP("fe80::1"))},
				{Key: []byte(net.ParseIP("fe80::2")), IntervalEnd: true},
			},
			expText: "fe80::1",
		},
		{
			name: "ipv6 /64 cidr",
			typ:  nftables.TypeIP6Addr,
			elems: []nftables.SetElement{
				{Key: []byte(net.ParseIP("2001:db8::"))},
				{Key: []byte(net.ParseIP("2001:db8:0:1::")), IntervalEnd: true},
			},
			expText: "2001:db8::/64",
		},
	}

	for _, tc := range testCases {
		sui.Run(tc.name, func() {
			enc := NewSetElemsEncoder(tc.typ, true, tc.elems)
			str, err := enc.Format()
			sui.Require().NoError(err)
			sui.Require().Equal(tc.expText, str)
		})
	}
}
