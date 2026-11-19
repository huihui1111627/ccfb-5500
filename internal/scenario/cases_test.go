// Package scenario holds the verification suite: hand-computed reference
// cases for the decision process, and the larger fault/policy scenarios used
// to check that a simulation never produces a routing loop or black hole.
package scenario

import (
	"fmt"
	"testing"

	"bgpsim/internal/bgp"
	"bgpsim/internal/model"
	"bgpsim/internal/policy"
	"bgpsim/internal/rpki"
	"bgpsim/internal/sim"
)

// Case is one hand-computed decision-process example.
//
// Each case is deliberately tiny: a handful of routers, one prefix, and a
// comment trail that shows the arithmetic.  The expected winner names the peer
// whose route must be selected at the observing router, and the expected step
// records which step of the decision process decided it.
type Case struct {
	Name     string
	Why      string
	Network  *model.Network
	Policies []model.Policy
	ROAs     []model.ROA
	Observe  string // router whose Loc-RIB is checked
	Prefix   string
	WantPeer string // expected winning peer ("local" for the origin router)
	WantStep int    // bgp.Step* constant that should have eliminated the losers
	WantECMP int    // expected multipath member count (0 means 1)
	WantRPKI string // optional expected validation state of the selected path
}

// Run builds and converges the case network and returns the selected route.
func (c *Case) Run() (*sim.Engine, *model.Network, error) {
	n := c.Network
	n.Policies = c.Policies
	n.ROAs = c.ROAs
	if err := n.Build(); err != nil {
		return nil, nil, err
	}
	pol, err := policy.Compile(n)
	if err != nil {
		return nil, nil, err
	}
	e := sim.New(n, pol, rpki.New(n.ROAs))
	e.Seed()
	if rounds := e.Converge(50); rounds >= 50 {
		return nil, n, fmt.Errorf("did not converge")
	}
	return e, n, nil
}

// Check verifies the case and returns a human-readable explanation.
func (c *Case) Check() error {
	e, n, err := c.Run()
	if err != nil {
		return fmt.Errorf("%s: %v", c.Name, err)
	}
	rx := n.RouterIndex(c.Observe)
	if rx < 0 {
		return fmt.Errorf("%s: unknown observer %q", c.Name, c.Observe)
	}
	p := n.PrefixIndex(c.Prefix)
	if p < 0 {
		return fmt.Errorf("%s: unknown prefix %q", c.Name, c.Prefix)
	}
	rt := e.Best(rx, p)
	if rt == nil {
		return fmt.Errorf("%s: %s has no path for %s", c.Name, c.Observe, c.Prefix)
	}
	gotPeer := "local"
	if rt.Peer >= 0 {
		gotPeer = n.Routers[rt.Peer].Name
	}
	if gotPeer != c.WantPeer {
		return fmt.Errorf("%s: %s selected peer %q, want %q (path %q lp %d)",
			c.Name, c.Observe, gotPeer, c.WantPeer, rt.Attr.ASPathString(), rt.Attr.LocalPref)
	}
	if c.WantRPKI != "" && string(rt.Attr.RPKI) != c.WantRPKI {
		return fmt.Errorf("%s: RPKI state %q, want %q", c.Name, rt.Attr.RPKI, c.WantRPKI)
	}
	want := c.WantECMP
	if want == 0 {
		want = 1
	}
	lr := e.RIB[rx][p]
	if len(lr.ECMP) != want {
		return fmt.Errorf("%s: ECMP group has %d paths, want %d", c.Name, len(lr.ECMP), want)
	}
	if c.WantStep >= 0 {
		dec := e.Decision(rx, p)
		if dec == nil {
			return fmt.Errorf("%s: no decision trace", c.Name)
		}
		// The winner must be the one that survived, and at least one loser
		// must have been eliminated at the expected step.
		elimAtWant := false
		for _, cand := range dec.Candidates {
			if cand.Winner {
				continue
			}
			if cand.EliminatedAt == c.WantStep {
				elimAtWant = true
			}
		}
		if !elimAtWant {
			var got []int
			for _, cand := range dec.Candidates {
				if !cand.Winner {
					got = append(got, cand.EliminatedAt)
				}
			}
			return fmt.Errorf("%s: no candidate eliminated at step %s (eliminations at %v)",
				c.Name, bgp.StepName(c.WantStep), got)
		}
	}
	return nil
}

// --- helpers ---------------------------------------------------------------

func router(name string, asn uint32, id string) *model.Router {
	return &model.Router{Name: name, ASN: asn, RouterID: id}
}

func link(a, b string, cost int) model.Link {
	return model.Link{A: a, B: b, Cost: cost, Capacity: 10, Kind: "core"}
}

func ann(router, prefix string, attrs ...func(*model.Announcement)) *model.Announcement {
	a := &model.Announcement{Router: router, Prefix: prefix, OriginType: model.OriginIGP}
	for _, f := range attrs {
		f(a)
	}
	return a
}

func path(asns ...uint32) func(*model.Announcement) {
	return func(a *model.Announcement) { a.ASPath = asns }
}

func med(v int) func(*model.Announcement) {
	return func(a *model.Announcement) { a.MED = v }
}

func origin(o model.OriginType) func(*model.Announcement) {
	return func(a *model.Announcement) { a.OriginType = o }
}

func community(asn, val uint16) func(*model.Announcement) {
	return func(a *model.Announcement) {
		a.Communities = append(a.Communities, model.NewCommunity(asn, val))
	}
}

func locpref(v int) func(*model.Announcement) {
	return func(a *model.Announcement) { a.LocalPref = v }
}

// Cases returns every hand-checked reference case.
func Cases() []*Case {
	return []*Case{
		// ----------------------------------------------------------------
		// 1. Local preference is absolute.  AS64500 has two providers and
		// sees a /24 with a short path via B and a long path via A.  A is
		// marked local-preference 200 by policy, so A wins even though its
		// AS_PATH is three hops longer.
		// ----------------------------------------------------------------
		{
			Name: "local-preference-beats-as-path-length",
			Why: "LP 200 via A wins over LP 100 via B even though B's AS_PATH is shorter; " +
				"local preference is compared before path length (RFC 4271 9.1.2.2 step 2).",
			Network: func() *model.Network {
				n := &model.Network{
					Name: "lp-vs-aslen",
					Routers: []*model.Router{
						router("r", 64500, "10.0.0.1"),
						router("a", 65001, "10.0.0.2"),
						router("b", 65002, "10.0.0.3"),
					},
					Links: []model.Link{link("r", "a", 10), link("r", "b", 10)},
					Announcements: []*model.Announcement{
						ann("a", "198.51.100.0/24", path(65100, 65200, 65300)),
						ann("b", "198.51.100.0/24"),
					},
				}
				return n
			}(),
			Policies: []model.Policy{{
				Name: "prefer-a", Direction: "import", Neighbor: "a",
				Actions: model.PolicyActions{SetLocalPref: intp(200)},
			}},
			Observe: "r", Prefix: "198.51.100.0/24", WantPeer: "a",
			WantStep: bgp.StepLocalPref,
		},
		// ----------------------------------------------------------------
		// 2. With equal local preference the shorter AS_PATH wins.
		//    A: [65001] (1 hop), B: [65002, 65003] (2 hops).
		// ----------------------------------------------------------------
		{
			Name: "shortest-as-path",
			Why:  "AS_PATH length 1 via A beats length 2 via B when local preference ties.",
			Network: &model.Network{
				Name: "aslen",
				Routers: []*model.Router{
					router("r", 64500, "10.0.0.1"),
					router("a", 65001, "10.0.0.2"),
					router("b", 65002, "10.0.0.3"),
				},
				Links: []model.Link{link("r", "a", 10), link("r", "b", 10)},
				Announcements: []*model.Announcement{
					ann("a", "198.51.100.0/24"),
					ann("b", "198.51.100.0/24", path(65003)),
				},
			},
			Observe: "r", Prefix: "198.51.100.0/24", WantPeer: "a",
			WantStep: bgp.StepASPathLen,
		},
		// ----------------------------------------------------------------
		// 3. Equal preference and length: ORIGIN decides.  IGP < EGP <
		//    INCOMPLETE; A is INCOMPLETE, B is EGP, so B wins.
		// ----------------------------------------------------------------
		{
			Name: "origin-type-igp-before-egp-before-incomplete",
			Why:  "ORIGIN EGP via B beats INCOMPLETE via A (IGP < EGP < INCOMPLETE).",
			Network: &model.Network{
				Name: "origin",
				Routers: []*model.Router{
					router("r", 64500, "10.0.0.1"),
					router("a", 65001, "10.0.0.2"),
					router("b", 65002, "10.0.0.3"),
				},
				Links: []model.Link{link("r", "a", 10), link("r", "b", 10)},
				Announcements: []*model.Announcement{
					ann("a", "198.51.100.0/24", origin(model.OriginIncomplete)),
					ann("b", "198.51.100.0/24", origin(model.OriginEGP)),
				},
			},
			Observe: "r", Prefix: "198.51.100.0/24", WantPeer: "b",
			WantStep: bgp.StepOrigin,
		},
		// ----------------------------------------------------------------
		// 4. Same neighbour AS, same IGP cost: the lower MED wins.
		//    The two routes are from the same AS 65001, so MED is compared.
		// ----------------------------------------------------------------
		{
			Name: "med-lower-wins-within-one-neighbour-as",
			Why:  "Two routes from AS65001, MED 50 and MED 200: the lower MED wins.",
			Network: &model.Network{
				Name: "med",
				Routers: []*model.Router{
					router("r", 64500, "10.0.0.1"),
					router("p1", 65001, "10.0.0.2"),
					router("p2", 65001, "10.0.0.3"),
				},
				Links: []model.Link{link("r", "p1", 10), link("r", "p2", 10)},
				Announcements: []*model.Announcement{
					ann("p1", "198.51.100.0/24", med(200)),
					ann("p2", "198.51.100.0/24", med(50)),
				},
			},
			Observe: "r", Prefix: "198.51.100.0/24", WantPeer: "p2",
			WantStep: bgp.StepMED,
		},
		// ----------------------------------------------------------------
		// 5. MED across different neighbour ASes is not compared by default.
		//    MED 1 via AS65001 vs MED 2 via AS65002: both survive the MED
		//    step, the lower IGP cost decides.  Here both links cost 10, so
		//    the router-ID step decides, and the lower peer ID wins.
		// ----------------------------------------------------------------
		{
			Name: "med-not-compared-across-different-as",
			Why: "MED from different neighbouring ASes is ignored unless always-compare-med " +
				"is set, so the tie falls through to the IGP cost and then the advertising router ID.",
			Network: &model.Network{
				Name: "med-diff-as",
				Routers: []*model.Router{
					router("r", 64500, "10.0.0.1"),
					router("p1", 65001, "10.0.0.50"),
					router("p2", 65002, "10.0.0.40"),
				},
				Links: []model.Link{link("r", "p1", 10), link("r", "p2", 10)},
				Announcements: []*model.Announcement{
					ann("p1", "198.51.100.0/24", med(1)),
					ann("p2", "198.51.100.0/24", med(2)),
				},
			},
			Observe: "r", Prefix: "198.51.100.0/24", WantPeer: "p2",
			WantStep: bgp.StepRouterID,
		},
		// ----------------------------------------------------------------
		// 6. eBGP beats iBGP at equal local preference and equal AS_PATH
		//    length.  r has an eBGP session with x (AS65001) and an iBGP
		//    session with border eb, which also peers with x.  Both paths
		//    are one AS hop long; the eBGP-learned one wins.
		// ----------------------------------------------------------------
		{
			Name: "ebgp-preferred-over-ibgp",
			Why:  "An eBGP-learned path beats an iBGP-learned path at equal local preference and AS_PATH length.",
			Network: &model.Network{
				Name: "ebgp-vs-ibgp",
				Routers: []*model.Router{
					router("r", 64500, "10.0.0.1"),
					router("eb", 64500, "10.0.0.2"),
					router("x", 65001, "10.0.0.4"),
				},
				Links: []model.Link{link("r", "eb", 10), link("r", "x", 10), link("eb", "x", 10)},
				Announcements: []*model.Announcement{
					ann("x", "198.51.100.0/24"),
				},
			},
			Observe: "r", Prefix: "198.51.100.0/24", WantPeer: "x",
			WantStep: bgp.StepEBGP,
		},
		// ----------------------------------------------------------------
		// 7. IGP cost to the exit router decides when everything else ties.
		//    Two borders advertise the same external prefix over iBGP.  c
		//    reaches b1 over a cost-10 path and b2 over cost-50, so the exit
		//    through b1 wins at step 7.
		// ----------------------------------------------------------------
		{
			Name: "igp-cost-to-egress",
			Why:  "Equal LP, path length, origin and MED: the lower IGP cost to the exit router wins.",
			Network: &model.Network{
				Name: "igp-cost",
				Routers: []*model.Router{
					router("c", 64500, "10.0.0.1"),
					router("b1", 64500, "10.0.0.2"),
					router("b2", 64500, "10.0.0.3"),
					router("p1", 65001, "10.0.0.4"),
					router("p2", 65002, "10.0.0.5"),
				},
				Links: []model.Link{
					link("c", "b1", 10), link("c", "b2", 50),
					link("b1", "p1", 10), link("b2", "p2", 10),
				},
				Announcements: []*model.Announcement{
					// p1 and p2 are different ASes, so MED is not compared.
					ann("p1", "198.51.100.0/24"),
					ann("p2", "198.51.100.0/24"),
				},
			},
			Observe: "c", Prefix: "198.51.100.0/24", WantPeer: "b1",
			WantStep: bgp.StepIGP,
		},
		// ----------------------------------------------------------------
		// 8. Two iBGP paths with identical attributes: the lower ORIGINATOR
		//    (router ID) wins.  ib-2 has the lower ID.
		// ----------------------------------------------------------------
		{
			Name: "router-id-tiebreak",
			Why:  "Identical local preference, AS_PATH, origin and IGP cost: the lower advertising router ID wins.",
			Network: &model.Network{
				Name: "router-id",
				Routers: []*model.Router{
					router("r", 64500, "10.0.0.1"),
					router("ib1", 64500, "10.0.0.90"),
					router("ib2", 64500, "10.0.0.20"),
					// Give both the same eBGP source so the iBGP paths are
					// otherwise identical.
					router("ext", 65001, "10.0.0.4"),
				},
				Links: []model.Link{link("ib1", "ext", 10), link("ib2", "ext", 10), link("r", "ib1", 10), link("r", "ib2", 10)},
				Announcements: []*model.Announcement{
					ann("ext", "198.51.100.0/24"),
				},
			},
			Observe: "r", Prefix: "198.51.100.0/24", WantPeer: "ib2",
			// The two iBGP candidates tie through IGP (same cost to ext),
			// so the router-ID step removes ib1.
			WantStep: bgp.StepRouterID,
		},
		// ----------------------------------------------------------------
		// 9. Route reflection: one client originates, the reflector reflects
		//    to the second client, and CLUSTER_LIST carries the reflector's
		//    cluster ID.
		// ----------------------------------------------------------------
		{
			Name: "route-reflector-reflects-client-route",
			Why:  "An RR reflects a client's route to other clients and stamps CLUSTER_LIST; it never sends it back to the originator.",
			Network: &model.Network{
				Name: "rr",
				Routers: []*model.Router{
					{Name: "rr1", ASN: 64500, RouterID: "10.0.0.1", RR: true, Clients: []string{"c1", "c2"}},
					router("c1", 64500, "10.0.0.2"),
					router("c2", 64500, "10.0.0.3"),
					router("ext", 65001, "10.0.0.4"),
				},
				Links: []model.Link{link("rr1", "c1", 10), link("rr1", "c2", 10), link("c1", "ext", 10)},
				Announcements: []*model.Announcement{
					ann("ext", "198.51.100.0/24"),
				},
			},
			Observe: "c2", Prefix: "198.51.100.0/24", WantPeer: "rr1",
			WantStep: -1,
		},
		// ----------------------------------------------------------------
		// 10. Two reflectors with different cluster IDs must not form a
		//     reflection loop.  c1 originates the prefix and is a client of
		//     rr1; rr1 reflects it to rr2 (a non-client, but the route came
		//     from a client) and stamps cluster A.  rr2 reflects it on to its
		//     client c2 and stamps cluster B.  rr2 does not send it back to
		//     rr1 because rr1 is a non-client and rr2 learned the route from
		//     a non-client, so the loop terminates after one pass.
		// ----------------------------------------------------------------
		{
			Name: "two-reflectors-do-not-form-a-loop",
			Why: "CLUSTER_LIST (and the client/non-client rule) stops a reflected route from being " +
				"reflected back between two route reflectors; c2 receives it with a two-entry CLUSTER_LIST.",
			Network: &model.Network{
				Name: "rr-loop",
				Routers: []*model.Router{
					{Name: "rr1", ASN: 64500, RouterID: "10.0.0.1", ClusterID: "10.0.1.1", RR: true, Clients: []string{"c1"}},
					{Name: "rr2", ASN: 64500, RouterID: "10.0.0.2", ClusterID: "10.0.1.2", RR: true, Clients: []string{"c2"}},
					router("c1", 64500, "10.0.0.3"),
					router("c2", 64500, "10.0.0.4"),
					router("ext", 65001, "10.0.0.6"),
				},
				Links: []model.Link{
					link("rr1", "c1", 10), link("rr1", "rr2", 10),
					link("rr2", "c2", 10), link("c1", "ext", 10),
				},
				Announcements: []*model.Announcement{
					ann("ext", "198.51.100.0/24"),
				},
			},
			Observe: "c2", Prefix: "198.51.100.0/24", WantPeer: "rr2",
			WantStep: -1,
		},
		// ----------------------------------------------------------------
		// 11. RPKI: the ROA authorises AS65100, the announced path ends in
		//     AS65200, so the route is invalid at the border.  The same
		//     prefix is also offered by a different provider via the
		//     authorised origin AS, which validates.
		// ----------------------------------------------------------------
		{
			Name: "rpki-invalid-loses-to-valid",
			Why:  "The origin AS in the ROA is 65100; provider A's path ends in 65200 (invalid), provider B's in 65100 (valid).",
			Network: &model.Network{
				Name: "rpki",
				Routers: []*model.Router{
					router("b1", 64500, "10.0.0.1"),
					router("b2", 64500, "10.0.0.2"),
					router("pa", 65001, "10.0.0.3"),
					router("pb", 65002, "10.0.0.4"),
				},
				Links: []model.Link{link("b1", "pa", 10), link("b2", "pb", 10), link("b1", "b2", 10)},
				Announcements: []*model.Announcement{
					ann("pa", "198.51.100.0/24", path(65200)),
					ann("pb", "198.51.100.0/24", path(65100)),
				},
			},
			ROAs: []model.ROA{{Prefix: "198.51.100.0/24", MaxLen: 24, OriginAS: 65100}},
			// The invalid path is degraded to local preference 40 by the
			// default RPKI policy, so the valid one wins.
			Observe: "b1", Prefix: "198.51.100.0/24", WantPeer: "b2",
			WantStep: bgp.StepLocalPref,
			WantRPKI: "valid",
		},
	}
}

func intp(v int) *int { return &v }

// RunAllCases runs every reference case.
func RunAllCases() []error {
	var errs []error
	for _, c := range Cases() {
		if err := c.Check(); err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}

// TestReferenceCases is the Go test entry point for the hand-computed cases.
func TestReferenceCases(t *testing.T) {
	for _, c := range Cases() {
		c := c
		t.Run(c.Name, func(t *testing.T) {
			if err := c.Check(); err != nil {
				t.Fatalf("%v\nwhy: %s", err, c.Why)
			}
		})
	}
}
