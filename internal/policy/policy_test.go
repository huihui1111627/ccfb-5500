package policy_test

import (
	"net/netip"
	"testing"

	"bgpsim/internal/bgp"
	"bgpsim/internal/model"
	"bgpsim/internal/policy"
)

func mustPrefix(t *testing.T) netip.Prefix {
	t.Helper()
	return netip.MustParsePrefix("198.51.100.0/24")
}

// attrFor builds an attribute whose AS_PATH is exactly path, left to right.
func attrFor(path []uint32) *bgp.Attr {
	a := bgp.NewAttr(100)
	if len(path) > 0 {
		last := path[len(path)-1]
		a = a.Prepend(last, 1)
		for i := len(path) - 2; i >= 0; i-- {
			a = a.Prepend(path[i], 1)
		}
	}
	return a
}

func TestASPathRegexDialect(t *testing.T) {
	// The Cisco-style "_" boundary must match an AS at the start, middle or
	// end of the rendered path, and must not match a partial AS number.
	for _, tc := range []struct {
		regex string
		path  []uint32
		want  bool
	}{
		{"_64500_", []uint32{65001, 64500}, true},
		{"_64500_", []uint32{64500}, true},
		{"_64500_", []uint32{65001, 64500, 65002}, true},
		{"_64500_", []uint32{65001}, false},
		{"^65001", []uint32{65001, 64500}, true},
		{"^65001", []uint32{65002, 65001}, false},
	} {
		if err := policy.ValidateASPathRegex(tc.regex); err != nil {
			t.Fatalf("%s: %v", tc.regex, err)
		}
		n := &model.Network{
			Routers: []*model.Router{{Name: "r", ASN: 1, RouterID: "10.0.0.1"}},
			Policies: []model.Policy{{
				Name: "p", Direction: "import",
				Match:   model.PolicyMatch{ASPathRegex: tc.regex},
				Actions: model.PolicyActions{SetLocalPref: intp(200)},
			}},
		}
		if err := n.Build(); err != nil {
			t.Fatal(err)
		}
		eng, err := policy.Compile(n)
		if err != nil {
			t.Fatal(err)
		}
		res := eng.Apply(n, 0, -1, policy.Inbound, mustPrefix(t), attrFor(tc.path))
		got := res.SetLP != nil
		if got != tc.want {
			t.Errorf("regex %q against path %v: matched=%v, want %v", tc.regex, tc.path, got, tc.want)
		}
	}
}

func TestBadRegexRejected(t *testing.T) {
	n := &model.Network{
		Routers: []*model.Router{{Name: "r", ASN: 1, RouterID: "10.0.0.1"}},
		Policies: []model.Policy{{
			Name: "bad", Match: model.PolicyMatch{ASPathRegex: "_["},
		}},
	}
	if err := n.Build(); err != nil {
		t.Fatal(err)
	}
	if _, err := policy.Compile(n); err == nil {
		t.Fatal("compile accepted an invalid regex")
	}
}

func TestPrefixListFirstMatchWins(t *testing.T) {
	n := &model.Network{
		Routers: []*model.Router{{Name: "r", ASN: 1, RouterID: "10.0.0.1"}},
		Policies: []model.Policy{
			{
				Name: "permit-198-then-deny-supernet", Direction: "import",
				Match: model.PolicyMatch{PrefixList: []model.PrefixListEntry{
					{Prefix: "198.51.100.0/24", Ge: 24, Le: 24, Action: "permit"},
					{Prefix: "198.0.0.0/8", Ge: 8, Le: 32, Action: "deny"},
				}},
				Actions: model.PolicyActions{SetLocalPref: intp(150)},
			},
		},
	}
	if err := n.Build(); err != nil {
		t.Fatal(err)
	}
	eng, err := policy.Compile(n)
	if err != nil {
		t.Fatal(err)
	}
	a := bgp.NewAttr(100)
	// The exact /24 hits the first (permit) entry.
	res := eng.Apply(n, 0, -1, policy.Inbound, netip.MustParsePrefix("198.51.100.0/24"), a)
	if res.SetLP == nil {
		t.Fatal("exact prefix did not hit the permit entry")
	}
	// A different /24 in the same /8 hits the second (deny) entry, which
	// returns no match for the whole policy.
	res = eng.Apply(n, 0, -1, policy.Inbound, netip.MustParsePrefix("198.51.101.0/24"), a)
	if res.SetLP != nil {
		t.Fatal("a prefix matched by a deny entry should not action")
	}
}

func TestBindingsRespected(t *testing.T) {
	n := &model.Network{
		Routers: []*model.Router{
			{Name: "a", ASN: 1, RouterID: "10.0.0.1"},
			{Name: "b", ASN: 1, RouterID: "10.0.0.2"},
		},
		Policies: []model.Policy{{
			Name: "only-a", Router: "a", Direction: "import",
			Actions: model.PolicyActions{SetLocalPref: intp(200)},
		}},
	}
	if err := n.Build(); err != nil {
		t.Fatal(err)
	}
	eng, err := policy.Compile(n)
	if err != nil {
		t.Fatal(err)
	}
	p := netip.MustParsePrefix("198.51.100.0/24")
	if res := eng.Apply(n, 0, -1, policy.Inbound, p, bgp.NewAttr(100)); res.SetLP == nil {
		t.Error("router a should have matched")
	}
	if res := eng.Apply(n, 1, -1, policy.Inbound, p, bgp.NewAttr(100)); res.SetLP != nil {
		t.Error("router b should not have matched")
	}
}

func TestDescribeSmoke(t *testing.T) {
	if d := policy.Describe(model.Policy{Name: "x"}); d == "" {
		t.Fatal("empty description")
	}
}

func intp(v int) *int { return &v }
