package gen_test

import (
	"encoding/json"
	"testing"

	"bgpsim/internal/gen"
	"bgpsim/internal/model"
)

// TestBuildAndRoundTrip generates a network, validates it, serialises it the
// way the importer expects, and loads it back to the same shape.
func TestBuildAndRoundTrip(t *testing.T) {
	opts := gen.DefaultOptions()
	opts.Cities = 4
	opts.Prefixes = 400
	n, err := gen.Build(opts)
	if err != nil {
		t.Fatal(err)
	}
	n.Policies = gen.DefaultPolicy(opts.ProvinceAS, nil)
	if err := n.Build(); err != nil {
		t.Fatal(err)
	}
	if len(n.Routers) < 20 {
		t.Fatalf("only %d routers", len(n.Routers))
	}
	if len(n.PrefixesV) != opts.Prefixes {
		t.Fatalf("%d prefixes, want %d", len(n.PrefixesV), opts.Prefixes)
	}
	// Every prefix must have at least one announcement.
	have := map[int]bool{}
	for _, a := range n.Announcements {
		have[a.PrefixIdx] = true
	}
	for p := 0; p < len(n.PrefixesV); p++ {
		if !have[p] {
			t.Fatalf("prefix %s has no announcement", n.PrefixString(p))
		}
	}
	data, err := json.Marshal(n)
	if err != nil {
		t.Fatal(err)
	}
	var back model.Network
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("round-trip decode: %v", err)
	}
	if len(back.Routers) != len(n.Routers) {
		t.Errorf("round-trip routers %d, want %d", len(back.Routers), len(n.Routers))
	}
	if len(back.Announcements) != len(n.Announcements) {
		t.Errorf("round-trip announcements %d, want %d", len(back.Announcements), len(n.Announcements))
	}
	if err := back.Build(); err != nil {
		t.Fatalf("round-tripped network does not build: %v", err)
	}
	if len(back.PrefixesV) != len(n.PrefixesV) {
		t.Errorf("round-trip prefixes %d, want %d", len(back.PrefixesV), len(n.PrefixesV))
	}
}

// TestInvalidOriginRejected makes sure a bad ORIGIN value is caught at load
// rather than silently exported as "unknown".
func TestInvalidOriginRejected(t *testing.T) {
	n := &model.Network{
		Routers: []*model.Router{{Name: "r", ASN: 1, RouterID: "10.0.0.1"}},
		Announcements: []*model.Announcement{{
			Router: "r", Prefix: "198.51.100.0/24", OriginType: model.OriginType(7),
		}},
	}
	if err := n.Build(); err == nil {
		t.Fatal("Build accepted an out-of-range ORIGIN")
	}
}

// TestDeterministic verifies the same seed produces byte-identical output.
func TestDeterministic(t *testing.T) {
	mk := func() []byte {
		opts := gen.DefaultOptions()
		opts.Cities = 3
		opts.Prefixes = 200
		n, err := gen.Build(opts)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(n)
		return b
	}
	a, b := mk(), mk()
	if string(a) != string(b) {
		t.Fatal("the generator is not deterministic for a fixed seed")
	}
}
