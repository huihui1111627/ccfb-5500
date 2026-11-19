package traffic

import (
	"math"
	"testing"

	"bgpsim/internal/gen"
	"bgpsim/internal/model"
	"bgpsim/internal/policy"
	"bgpsim/internal/rpki"
	"bgpsim/internal/sim"
)

func build(t *testing.T, cities, prefixes int) (*sim.Engine, *model.Network) {
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
	e.Converge(100)
	return e, n
}

// TestBaselineBalanced verifies the generated network distributes traffic
// across providers rather than pinning it to one, and that every prefix with
// traffic has a path.
func TestBaselineBalanced(t *testing.T) {
	e, n := build(t, 6, 400)
	rep := Analyze(n, e, 128)
	if rep.UnroutedGbps > 0 {
		t.Errorf("%.3f Gbps of traffic has no path", rep.UnroutedGbps)
	}
	if len(rep.Upstreams) == 0 {
		t.Fatal("no upstream links found")
	}
	for _, u := range rep.Upstreams {
		if u.Utilisation > 1.0 {
			t.Errorf("%s is already over capacity at baseline (%.1f%%)", u.Link, u.Utilisation*100)
		}
	}
	// No single provider should carry everything; a balanced baseline is the
	// whole point of having three.
	nonZero := 0
	for _, u := range rep.Upstreams {
		if u.LoadGbps > 0 {
			nonZero++
		}
	}
	if nonZero < 2 {
		t.Errorf("only %d upstream links carry traffic; the baseline is not balanced", nonZero)
	}
}

// TestBorderFailureConcentratesTraffic verifies the platform's primary
// promise: failing one provider's border pushes the remaining links up, and
// the report flags oversubscription instead of hiding it.
func TestBorderFailureConcentratesTraffic(t *testing.T) {
	e, n := build(t, 6, 400)
	before := Analyze(n, e, 128)
	var borderIdx = -1
	for i, r := range n.Routers {
		if r.Role == "border" {
			borderIdx = i
			break
		}
	}
	if borderIdx < 0 {
		t.Fatal("no border router in the generated network")
	}
	// Fail the border and reconverge.
	e.SetRouterDown(borderIdx, true)
	e.Converge(100)
	after := Analyze(n, e, 128)

	if after.RoutedGbps <= 0 {
		t.Fatal("all traffic became unroutable after a single border failure")
	}
	// Some other link must be carrying more than it did before.
	maxBefore, maxAfter := before.MaxUtil, after.MaxUtil
	if maxAfter <= maxBefore {
		t.Errorf("max utilisation did not rise after a border failure (%.3f -> %.3f)", maxBefore, maxAfter)
	}
	// And the failed border's own upstream link must be flagged down.
	for _, u := range after.Upstreams {
		if u.A == n.Routers[borderIdx].Name || u.B == n.Routers[borderIdx].Name {
			if u.Up {
				t.Errorf("upstream link %s is still reported up after its border failed", u.Link)
			}
		}
	}
}

// TestUtilisationMath checks the arithmetic: load and capacity produce the
// reported utilisation, and ECMP split shares sum to the flow rate.
func TestUtilisationMath(t *testing.T) {
	e, n := build(t, 5, 200)
	rep := Analyze(n, e, 64)
	for _, l := range rep.Links {
		if l.CapacityGbps <= 0 {
			continue
		}
		want := l.LoadGbps / l.CapacityGbps
		if math.Abs(l.Utilisation-want) > 1e-9 {
			t.Errorf("%s: utilisation %.6f, want %.6f", l.Link, l.Utilisation, want)
		}
	}
	for _, f := range rep.Flows {
		sum := 0.0
		for _, s := range f.Split {
			sum += s
		}
		if math.Abs(sum-f.RateGbps) > 1e-9 {
			t.Errorf("%s: split sums to %.6f, want %.6f", f.Prefix, sum, f.RateGbps)
		}
		if f.ECMP != len(f.Paths) {
			t.Errorf("%s: ecmp %d but %d paths", f.Prefix, f.ECMP, len(f.Paths))
		}
	}
}
