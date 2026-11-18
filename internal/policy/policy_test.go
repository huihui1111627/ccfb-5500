package policy

import (
	"testing"

	"github.com/edu-net/bgpsim/internal/bgpsim"
)

func TestPrefixListMatch(t *testing.T) {
	pl := &PrefixList{Name: "pl", Entries: []PrefixListEntry{
		{Prefix: "10.0.0.0/8", GE: 24},
		{Prefix: "192.168.0.0/16"},
	}}
	cases := map[string]bool{
		"10.1.2.0/24":    true,
		"10.0.0.0/8":     false, // 长度 8 不满足 ge 24
		"192.168.0.0/16": true,
		"192.168.1.0/24": false,
		"8.8.8.8/32":     false,
	}
	for prefix, want := range cases {
		got, err := pl.Match(prefix)
		if err != nil || got != want {
			t.Errorf("prefix %s: want %v got %v err=%v", prefix, want, got, err)
		}
	}
}

func TestASPathRegexpUnderscore(t *testing.T) {
	rx, err := NewASPathRegexp("_65100_")
	if err != nil {
		t.Fatal(err)
	}
	if !rx.Match("65100 65200") {
		t.Error("leading underscore should anchor 65100 to path start")
	}
	if rx.Match("65200 65100") {
		t.Error("leading underscore must not match when 65100 is not first")
	}
	// 两侧都有 AS：中间的下划线匹配 AS 间空白。
	rxMid, _ := NewASPathRegexp("65200_65100")
	if !rxMid.Match("65200 65100 65300") {
		t.Error("middle underscore should match the space between AS numbers")
	}
	// 裸数字（无下划线）按子串匹配，可出现在路径任意位置。
	rx2, _ := NewASPathRegexp("65100")
	if !rx2.Match("65200 65100 65300") {
		t.Error("bare number should match anywhere")
	}
	if rx2.Match("65200 65300") {
		t.Error("absent number must not match")
	}
	// 尾随下划线锚定路径最后一个 AS。
	rxEnd, _ := NewASPathRegexp("65100_")
	if !rxEnd.Match("65200 65100") {
		t.Error("trailing underscore should match when 65100 is last")
	}
	if rxEnd.Match("65100 65200") {
		t.Error("trailing underscore must not match when 65100 is not last")
	}
}

func TestRouteMapActionsAndImplicitDeny(t *testing.T) {
	lp := uint32(300)
	ps := &PolicySet{
		PrefixLists: []PrefixList{{Name: "pl", Entries: []PrefixListEntry{
			{Prefix: "100.0.0.0/24"},
		}}},
		RouteMaps: []RouteMap{{
			Name: "RM",
			Entries: []RouteMapEntry{
				{Seq: 10, Match: MatchCondition{PrefixLists: []string{"pl"}},
					Actions: []Action{
						{SetLocalPref: &lp},
						{AddCommunities: []uint32{bgpsim.Community(65000, 5)}},
						{PrependASPath: []uint32{65000, 65000}},
					}},
			},
		}},
	}
	c, err := NewCompiler(ps)
	if err != nil {
		t.Fatal(err)
	}
	r := &bgpsim.Route{Prefix: "100.0.0.0/24", Attrs: bgpsim.Attributes{ASPath: []uint32{65100}}}
	d, err := c.Apply("RM", r)
	if err != nil || !d.Permit {
		t.Fatalf("apply failed: permit=%v err=%v", d.Permit, err)
	}
	if r.Attrs.LocalPref != 300 {
		t.Errorf("local pref not set: %d", r.Attrs.LocalPref)
	}
	if len(r.Attrs.ASPath) != 3 || r.Attrs.ASPath[0] != 65000 {
		t.Errorf("prepend failed: %v", r.Attrs.ASPath)
	}
	if !r.Attrs.HasCommunity(bgpsim.Community(65000, 5)) {
		t.Error("community not added")
	}
	// 未命中任何节点 → 隐式 deny。
	r2 := &bgpsim.Route{Prefix: "8.8.8.8/32"}
	d2, _ := c.Apply("RM", r2)
	if d2.Permit {
		t.Error("unmatched route should hit implicit deny")
	}
}

func TestDenyAction(t *testing.T) {
	ps := &PolicySet{
		PrefixLists: []PrefixList{{Name: "pl", Entries: []PrefixListEntry{{Prefix: "100.0.0.0/24"}}}},
		RouteMaps: []RouteMap{{Name: "RM", Entries: []RouteMapEntry{
			{Seq: 10, Match: MatchCondition{PrefixLists: []string{"pl"}}, Actions: []Action{{Result: "deny"}}},
			{Seq: 20},
		}}},
	}
	c, _ := NewCompiler(ps)
	r := &bgpsim.Route{Prefix: "100.0.0.0/24"}
	if d, _ := c.Apply("RM", r); d.Permit {
		t.Error("deny action not honored")
	}
}
