package bgpsim

import "testing"

func mkRoute(from, nh string, lp, med uint32, origin Origin, asPath []uint32, igpCost int, peer PeerType) *Route {
	return &Route{
		Prefix: "100.0.0.0/24", ReceivedFrom: from, NextHop: nh, PeerType: peer,
		IGPCost: igpCost,
		Attrs:   Attributes{LocalPref: lp, MED: med, Origin: origin, ASPath: asPath},
	}
}

func ridOf(id string) string {
	m := map[string]string{"a": "10.0.0.1", "b": "10.0.0.2", "c": "10.0.0.3"}
	return m[id]
}

// TestSelectBestOrdering 验证完整选路顺序中每一级都能独立决定胜负。
func TestSelectBestOrdering(t *testing.T) {
	cases := []struct {
		name string
		r1   *Route
		r2   *Route
		want string
	}{
		{"local_pref",
			mkRoute("a", "nh", 100, 0, OriginIGP, []uint32{100}, 1, PeerEBGP),
			mkRoute("b", "nh", 200, 0, OriginIGP, []uint32{100}, 1, PeerEBGP), "b"},
		{"as_path",
			mkRoute("a", "nh", 100, 0, OriginIGP, []uint32{100}, 1, PeerEBGP),
			mkRoute("b", "nh", 100, 0, OriginIGP, []uint32{100, 200, 300}, 1, PeerEBGP), "a"},
		{"origin",
			mkRoute("a", "nh", 100, 0, OriginIGP, []uint32{100}, 1, PeerEBGP),
			mkRoute("b", "nh", 100, 0, OriginIncomplete, []uint32{100}, 1, PeerEBGP), "a"},
		{"med",
			mkRoute("a", "nh", 100, 10, OriginIGP, []uint32{100}, 1, PeerEBGP),
			mkRoute("b", "nh", 100, 50, OriginIGP, []uint32{100}, 1, PeerEBGP), "a"},
		{"igp_cost",
			mkRoute("a", "nh", 100, 0, OriginIGP, []uint32{100}, 5, PeerEBGP),
			mkRoute("b", "nh", 100, 0, OriginIGP, []uint32{100}, 50, PeerEBGP), "a"},
		{"router_id",
			mkRoute("b", "nh", 100, 0, OriginIGP, []uint32{100}, 5, PeerEBGP),
			mkRoute("a", "nh", 100, 0, OriginIGP, []uint32{100}, 5, PeerEBGP), "a"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := SelectBest("100.0.0.0/24", []*Route{tc.r1, tc.r2}, ridOf,
				SelectionOptions{MaxPaths: 1})
			if res.Primary == nil || res.Primary.ReceivedFrom != tc.want {
				got := ""
				if res.Primary != nil {
					got = res.Primary.ReceivedFrom
				}
				t.Fatalf("want winner %s, got %s", tc.want, got)
			}
		})
	}
}

// TestMEDOnlyComparedForSameNeighbor 验证相邻 AS 不同时跳过 MED 比较。
func TestMEDOnlyComparedForSameNeighbor(t *testing.T) {
	// 相邻 AS 不同：MED 不比较，进入后续阶段；两条 eBGP、IGP 开销相同，靠 RouterID 决胜。
	r1 := mkRoute("a", "nh", 100, 999, OriginIGP, []uint32{100}, 1, PeerEBGP)
	r2 := mkRoute("b", "nh", 100, 1, OriginIGP, []uint32{200}, 1, PeerEBGP)
	res := SelectBest("p", []*Route{r1, r2}, ridOf, SelectionOptions{MaxPaths: 1})
	if res.Primary.ReceivedFrom != "a" {
		t.Fatalf("MED should be ignored for different neighbor AS, got %s", res.Primary.ReceivedFrom)
	}
}

// TestECMPAndHash 验证等价路径集合与五元组哈希的确定性、均匀性。
func TestECMPAndHash(t *testing.T) {
	var routes []*Route
	for _, id := range []string{"a", "b", "c", "d"} {
		routes = append(routes, mkRoute(id, "nh", 100, 10, OriginIGP, []uint32{100}, 5, PeerEBGP))
	}
	res := SelectBest("p", routes, ridOf, SelectionOptions{MaxPaths: 3})
	if len(res.ECMP) != 3 {
		t.Fatalf("want 3 ECMP paths (MaxPaths=3), got %d", len(res.ECMP))
	}
	flow := FiveTuple{SrcIP: "1.1.1.1", DstIP: "2.2.2.2", Proto: 6, SrcPort: 1, DstPort: 2}
	idx := SelectECMPPath(res.ECMP, flow)
	if idx < 0 || idx >= 3 {
		t.Fatalf("hash index out of range: %d", idx)
	}
	// 同一流必须稳定落到同一条路径。
	for i := 0; i < 10; i++ {
		if SelectECMPPath(res.ECMP, flow) != idx {
			t.Fatal("ECMP hash not deterministic for same flow")
		}
	}
	// 大量不同流应分布到全部路径（粗检均匀性）。
	seen := map[int]bool{}
	for i := uint16(0); i < 1000; i++ {
		f := FiveTuple{SrcIP: "10.0.0.1", DstIP: "100.0.0.1", Proto: 6, SrcPort: i, DstPort: 80}
		seen[SelectECMPPath(res.ECMP, f)] = true
	}
	if len(seen) != 3 {
		t.Fatalf("hash did not spread across all 3 paths, got %d", len(seen))
	}
}

func TestPrefixContainsAndList(t *testing.T) {
	p := MustParsePrefix("10.0.0.0/8")
	if !p.Contains(MustParsePrefix("10.1.2.3/32")) {
		t.Error("10/8 should contain 10.1.2.3/32")
	}
	if p.Contains(MustParsePrefix("11.0.0.0/8")) {
		t.Error("10/8 should not contain 11/8")
	}
	// ge/le 语义。
	target := MustParsePrefix("10.1.0.0/24")
	ok, err := target.MatchPrefixListRule("10.0.0.0/8", 20, 26)
	if err != nil || !ok {
		t.Error("ge/le match should succeed")
	}
	ok, err = target.MatchPrefixListRule("10.0.0.0/8", 25, 26)
	if err != nil || ok {
		t.Error("/24 should fail ge 25")
	}
}

func TestCommunityRoundTrip(t *testing.T) {
	c, err := ParseCommunity("65001:100")
	if err != nil {
		t.Fatal(err)
	}
	if CommunityString(c) != "65001:100" {
		t.Fatalf("round trip failed: %s", CommunityString(c))
	}
}
