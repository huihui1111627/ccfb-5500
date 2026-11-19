package sim_test

import (
	"testing"

	"bgpsim/internal/gen"
	"bgpsim/internal/model"
	"bgpsim/internal/policy"
	"bgpsim/internal/rpki"
	"bgpsim/internal/sim"
)

func buildNet(t *testing.T, cities, prefixes int) (*model.Network, *sim.Engine) {
	t.Helper()
	g := gen.DefaultOptions()
	g.Cities = cities
	g.Prefixes = prefixes
	n, err := gen.Build(g)
	if err != nil {
		t.Fatal(err)
	}
	n.Policies = gen.DefaultPolicy(g.ProvinceAS, nil)
	if err := n.Build(); err != nil {
		t.Fatal(err)
	}
	pol, err := policy.Compile(n)
	if err != nil {
		t.Fatal(err)
	}
	e := sim.New(n, pol, rpki.New(n.ROAs))
	e.Seed()
	return n, e
}

// TestColdStartConverges verifies the baseline reaches a stable state and that
// a second Converge call is a no-op.
func TestColdStartConverges(t *testing.T) {
	_, e := buildNet(t, 4, 300)
	rounds := e.Converge(100)
	if rounds >= 100 {
		t.Fatalf("did not converge in 100 rounds")
	}
	if rounds == 0 {
		t.Fatal("converged without doing any work")
	}
	if again := e.Converge(100); again != 0 {
		t.Fatalf("already-converged engine reported %d more rounds", again)
	}
}

// TestEveryPrefixInstalled verifies that every prefix with an announcement is
// installed at the core.
func TestEveryPrefixInstalled(t *testing.T) {
	n, e := buildNet(t, 4, 300)
	e.Converge(100)
	core := n.RouterIndex("core-1")
	for _, a := range n.Announcements {
		if e.Best(core, a.PrefixIdx) == nil {
			t.Fatalf("core-1 has no path for %s", n.PrefixString(a.PrefixIdx))
		}
	}
}

// TestNoForwardingLoop verifies no installed path in our AS leaves and
// re-enters it.
func TestNoForwardingLoop(t *testing.T) {
	n, e := buildNet(t, 5, 400)
	e.Converge(100)
	ourAS := n.Routers[0].ASN
	for r, rtr := range n.Routers {
		if rtr.ASN != ourAS {
			continue
		}
		entries, _ := e.RouterRIB(r, "", 0, 0)
		for _, en := range entries {
			hops := splitASPath(en.Best.ASPath)
			for i, asn := range hops {
				if i > 0 && asn == ourAS {
					t.Fatalf("%s: %s path %q loops through our AS", rtr.Name, en.Prefix, en.Best.ASPath)
				}
			}
		}
	}
}

// TestLinkFailureReconverges verifies a provider link cut produces a new
// stable state with no black holes.
func TestLinkFailureReconverges(t *testing.T) {
	n, e := buildNet(t, 4, 300)
	e.Converge(100)
	var li = -1
	for i := range n.Links {
		if n.Links[i].Kind == "upstream" {
			li = i
			break
		}
	}
	if li < 0 {
		t.Fatal("no upstream link")
	}
	e.SetLinkDown(li, true)
	rounds := e.Converge(100)
	if rounds >= 100 {
		t.Fatal("did not reconverge after a link failure")
	}
	if again := e.Converge(100); again != 0 {
		t.Fatalf("state did not stabilise: %d extra rounds", again)
	}
	// No installed path may point at an unreachable next hop.
	for r := range n.Routers {
		entries, _ := e.RouterRIB(r, "", 0, 0)
		for _, en := range entries {
			if en.Blackhole {
				t.Fatalf("%s: %s installed with an unreachable next hop", n.Routers[r].Name, en.Prefix)
			}
		}
	}
}

// TestSessionSigtermPropagates verifies that killing a border router removes
// its eBGP-learned paths from the rest of the AS rather than leaving them as
// black holes.
func TestRouterFailurePropagates(t *testing.T) {
	n, e := buildNet(t, 4, 300)
	e.Converge(100)
	var border = -1
	for i, r := range n.Routers {
		if r.Role == "border" {
			border = i
			break
		}
	}
	if border < 0 {
		t.Fatal("no border router")
	}
	core := n.RouterIndex("core-1")
	// Find a prefix whose core path egresses through the border.
	var target = -1
	for p := 0; p < len(n.PrefixesV); p++ {
		if b := e.Best(core, p); b != nil && b.Egress == border {
			target = p
			break
		}
	}
	e.SetRouterDown(border, true)
	e.Converge(100)
	// The prefix may still be reachable through another provider, but it must
	// no longer egress through the failed border.
	if b := e.Best(core, target); b != nil && b.Egress == border {
		t.Fatalf("core-1 still egresses the failed border for %s", n.PrefixString(target))
	}
	// And the router itself has been emptied.
	entries, _ := e.RouterRIB(border, "", 0, 0)
	if len(entries) != 0 {
		t.Fatalf("failed router still has %d installed prefixes", len(entries))
	}
}

func splitASPath(s string) []uint32 {
	var out []uint32
	var cur uint32
	have := false
	for i := 0; i <= len(s); i++ {
		var c byte
		if i < len(s) {
			c = s[i]
		}
		if i == len(s) || c == ' ' || c == '{' || c == '}' || c == ',' {
			if have {
				out = append(out, cur)
				cur, have = 0, false
			}
			continue
		}
		if c < '0' || c > '9' {
			continue
		}
		cur = cur*10 + uint32(c-'0')
		have = true
	}
	return out
}
