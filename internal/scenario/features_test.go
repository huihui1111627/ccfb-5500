package scenario

import (
	"net/netip"
	"testing"

	"bgpsim/internal/bgp"
	"bgpsim/internal/dampening"
	"bgpsim/internal/ecmp"
	"bgpsim/internal/model"
	"bgpsim/internal/policy"
	"bgpsim/internal/rpki"
	"bgpsim/internal/sim"
)

// TestMultipathInstall verifies that equal-cost paths beyond the decision
// process's tie-breaks are all installed, and that the configured group size
// caps them.
func TestMultipathInstall(t *testing.T) {
	mk := func() *model.Network {
		return &model.Network{
			Name: "ecmp",
			Routers: []*model.Router{
				router("r", 64500, "10.0.0.1"),
				router("p1", 65001, "10.0.0.2"),
				router("p2", 65002, "10.0.0.3"),
				router("p3", 65003, "10.0.0.4"),
			},
			Links: []model.Link{
				link("r", "p1", 10), link("r", "p2", 10), link("r", "p3", 10),
			},
			Announcements: []*model.Announcement{
				ann("p1", "198.51.100.0/24"), ann("p2", "198.51.100.0/24"), ann("p3", "198.51.100.0/24"),
			},
			Config: model.DefaultSimConfig(),
		}
	}
	for _, tc := range []struct {
		max  int
		want int
	}{{max: 4, want: 3}, {max: 2, want: 2}, {max: 1, want: 1}} {
		n := mk()
		n.Config.ECMPMaxPaths = tc.max
		if err := n.Build(); err != nil {
			t.Fatal(err)
		}
		pol, _ := policy.Compile(n)
		e := sim.New(n, pol, rpki.New(nil))
		e.Seed()
		e.Converge(20)
		p := n.PrefixIndex("198.51.100.0/24")
		lr := e.RIB[n.RouterIndex("r")][p]
		if got := len(lr.ECMP); got != tc.want {
			t.Errorf("ecmpMaxPaths=%d installed %d paths, want %d", tc.max, got, tc.want)
		}
	}
}

// TestECMPFlowDistribution verifies the five-tuple hash spreads flows and is
// stable: the same flow always maps to the same member.
func TestECMPFlowDistribution(t *testing.T) {
	flows := 10000
	counts := make([]int, 4)
	for i := 0; i < flows; i++ {
		ft := ecmp.FiveTuple{
			SrcIP:   mustNetAddr("10.1.2.3"),
			DstIP:   mustNetAddr("198.51.100.77"),
			SrcPort: uint16(1024 + i%60000),
			DstPort: 443,
			Proto:   6,
		}
		idx := ecmp.Index(ft, 4)
		if idx < 0 || idx >= 4 {
			t.Fatalf("index out of range: %d", idx)
		}
		counts[idx]++
		if again := ecmp.Index(ft, 4); again != idx {
			t.Fatalf("unstable hash: %d vs %d", idx, again)
		}
	}
	for i, c := range counts {
		if c < flows/4*8/10 || c > flows/4*12/10 {
			t.Errorf("path %d carried %d of %d flows: distribution is too uneven", i, c, flows)
		}
	}
}

func mustNetAddr(s string) netip.Addr { return netip.MustParseAddr(s) }

func mustPrefix(s string) netip.Prefix { return netip.MustParsePrefix(s) }

// TestPolicyActions covers each supported policy match and action.
func TestPolicyActions(t *testing.T) {
	build := func(pols []model.Policy) (*sim.Engine, *model.Network) {
		n := &model.Network{
			Name: "pol",
			Routers: []*model.Router{
				router("b", 64500, "10.0.0.1"),
				router("p1", 65001, "10.0.0.2"),
				router("p2", 65002, "10.0.0.3"),
			},
			Links: []model.Link{link("b", "p1", 10), link("b", "p2", 10)},
			Announcements: []*model.Announcement{
				ann("p1", "198.51.100.0/24", path(65100)),
				ann("p2", "198.51.100.0/24", path(65200)),
			},
			Config:   model.DefaultSimConfig(),
			Policies: pols,
		}
		if err := n.Build(); err != nil {
			t.Fatal(err)
		}
		pol, err := policy.Compile(n)
		if err != nil {
			t.Fatal(err)
		}
		e := sim.New(n, pol, rpki.New(nil))
		e.Seed()
		e.Converge(20)
		return e, n
	}

	t.Run("as-path-regex-sets-local-pref", func(t *testing.T) {
		e, n := build([]model.Policy{{
			Name: "prefer-65100", Direction: "import",
			Match:   model.PolicyMatch{ASPathRegex: "_65100$"},
			Actions: model.PolicyActions{SetLocalPref: intp(250)},
		}})
		rt := e.Best(n.RouterIndex("b"), n.PrefixIndex("198.51.100.0/24"))
		if rt.Attr.LocalPref != 250 {
			t.Fatalf("local pref %d, want 250", rt.Attr.LocalPref)
		}
	})
	t.Run("community-match-all", func(t *testing.T) {
		e, n := build([]model.Policy{
			{Name: "tag", Direction: "import", Neighbor: "p1",
				Actions: model.PolicyActions{AddCommunities: []model.Community{model.NewCommunity(64500, 1), model.NewCommunity(64500, 2)}}},
			{Name: "match-all", Direction: "import",
				Match: model.PolicyMatch{
					Communities:    []model.Community{model.NewCommunity(64500, 1), model.NewCommunity(64500, 2)},
					CommunityMatch: "all"},
				Actions: model.PolicyActions{SetLocalPref: intp(300)}},
		})
		rt := e.Best(n.RouterIndex("b"), n.PrefixIndex("198.51.100.0/24"))
		if rt.Attr.LocalPref != 300 {
			t.Fatalf("local pref %d, want 300 from community match", rt.Attr.LocalPref)
		}
		if rt.Peer != n.RouterIndex("p1") {
			t.Fatalf("selected %s, want p1", n.Routers[rt.Peer].Name)
		}
	})
	t.Run("prefix-list-deny", func(t *testing.T) {
		e, n := build([]model.Policy{{
			Name: "deny-198", Direction: "import",
			Match:   model.PolicyMatch{PrefixList: []model.PrefixListEntry{{Prefix: "198.0.0.0/8", Ge: 8, Le: 24, Action: "permit"}}},
			Actions: model.PolicyActions{Action: "deny"},
		}})
		if rt := e.Best(n.RouterIndex("b"), n.PrefixIndex("198.51.100.0/24")); rt != nil {
			t.Fatalf("prefix should have been denied, got path via %s", n.Routers[rt.Peer].Name)
		}
	})
	t.Run("prepend-lengthens-path", func(t *testing.T) {
		e, n := build([]model.Policy{{
			Name: "prepend-p1", Direction: "import", Neighbor: "p1",
			Actions: model.PolicyActions{PrependASN: 64500, PrependCount: 3},
		}})
		rt := e.Best(n.RouterIndex("b"), n.PrefixIndex("198.51.100.0/24"))
		if rt.Peer != n.RouterIndex("p2") {
			t.Fatalf("selected %s, want p2 after prepending p1 three times", n.Routers[rt.Peer].Name)
		}
	})
}

// TestRPKIStates checks valid, invalid and not-found classification.
func TestRPKIStates(t *testing.T) {
	v := rpki.New([]model.ROA{{Prefix: "198.51.100.0/24", MaxLen: 24, OriginAS: 65001}})
	cases := []struct {
		prefix string
		asn    uint32
		want   model.ValidationState
	}{
		{"198.51.100.0/24", 65001, model.RPKIValid},
		{"198.51.100.0/24", 65002, model.RPKIInvalid},
		{"198.51.100.0/25", 65001, model.RPKIInvalid}, // more specific than maxLength
		{"203.0.113.0/24", 65001, model.RPKINotFound},
	}
	for _, tc := range cases {
		p := mustPrefix(tc.prefix)
		if got := v.Validate(p, tc.asn); got != tc.want {
			t.Errorf("validate %s origin %d = %s, want %s", tc.prefix, tc.asn, got, tc.want)
		}
	}
}

// TestDampeningDecay exercises the RFC 2439 arithmetic directly: three flaps
// suppress, and after two half-lives the penalty is low enough to reuse.
func TestDampeningDecay(t *testing.T) {
	d := dampening.New(dampening.Config{
		Enabled: true, PenaltyPerFlap: 1000, Suppress: 2000, Reuse: 750,
		HalfLifeSec: 900, MaxPenalty: 12000,
	})
	st := d.Get(0, 0)
	if d.Flap(st, 0) {
		t.Fatal("one flap must not suppress")
	}
	if !d.Flap(st, 0) {
		t.Fatal("two flaps (2000) must reach the suppress threshold")
	}
	if st.Penalty != 2000 {
		t.Fatalf("penalty %v, want 2000", st.Penalty)
	}
	// One half-life: 1000, still above the reuse threshold.
	d.DecayAll(900, 900)
	if !st.Suppressed {
		t.Fatal("after one half-life the prefix must still be suppressed (penalty 1000 > 750)")
	}
	// Two half-lives: 500, below reuse.
	d.DecayAll(900, 1800)
	if st.Suppressed {
		t.Fatal("after two half-lives the prefix must be reusable (penalty 500 < 750)")
	}
	if st.Penalty != 500 {
		t.Fatalf("penalty %v, want 500", st.Penalty)
	}
}

// TestDampeningSuppressesFlappingPrefix drives a real flapping origin through
// the simulator and checks the prefix stops being advertised.
func TestDampeningSuppressesFlappingPrefix(t *testing.T) {
	n := &model.Network{
		Name: "flap",
		Routers: []*model.Router{
			router("e", 64500, "10.0.0.1"),
			router("c", 64500, "10.0.0.2"),
		},
		Links:         []model.Link{link("e", "c", 10)},
		Announcements: []*model.Announcement{ann("e", "198.51.100.0/24")},
		Config:        model.DefaultSimConfig(),
	}
	n.Config.Dampening = model.DampeningConfig{
		Enabled: true, PenaltyPerFlap: 1000, Suppress: 2000, Reuse: 750,
		HalfLifeSec: 900, MaxPenalty: 12000,
	}
	if err := n.Build(); err != nil {
		t.Fatal(err)
	}
	pol, _ := policy.Compile(n)
	e := sim.New(n, pol, rpki.New(nil))
	e.Seed()
	e.Converge(20)
	p := n.PrefixIndex("198.51.100.0/24")
	c := n.RouterIndex("c")
	if e.Best(c, p) == nil {
		t.Fatal("prefix not present after first convergence")
	}
	// Flap the origin three times by clearing and re-seeding its
	// announcement.  Each withdrawal adds a penalty at the receiver.
	for i := 0; i < 3; i++ {
		e.WithdrawOrigin("e", p)
		e.Converge(20)
		e.RestoreOrigin("e", p)
		e.Converge(20)
	}
	if !e.Damp.Suppressed(c, p) {
		t.Fatalf("prefix should be suppressed after repeated flaps; penalty state: %+v", e.Damp.Snapshot())
	}
	// Suppression means no route is installed even though the origin is up.
	e.Converge(20)
	if rt := e.Best(c, p); rt != nil {
		t.Fatalf("suppressed prefix still installed via %s", n.Routers[rt.Peer].Name)
	}
}

// TestDecisionTraceShape verifies the trace records every step and a reason
// for every loser, which is what the "why this path" panel renders.
func TestDecisionTraceShape(t *testing.T) {
	c := Cases()[0]
	e, n, err := c.Run()
	if err != nil {
		t.Fatal(err)
	}
	d := e.Decision(n.RouterIndex(c.Observe), n.PrefixIndex(c.Prefix))
	if d == nil {
		t.Fatal("no decision")
	}
	if len(d.Candidates) != 2 {
		t.Fatalf("%d candidates, want 2", len(d.Candidates))
	}
	if d.Winner < 0 || !d.Candidates[d.Winner].Winner {
		t.Fatal("winner not marked")
	}
	for _, cand := range d.Candidates {
		if cand.Winner {
			continue
		}
		if cand.Reason == "" || cand.EliminatedAt < 0 {
			t.Fatalf("loser %s has no elimination reason", cand.Peer)
		}
	}
	if len(d.Steps) == 0 {
		t.Fatal("trace has no steps")
	}
	if d.Steps[0].Index != bgp.StepWeight {
		t.Fatalf("first step is %s, want weight", d.Steps[0].Name)
	}
}
