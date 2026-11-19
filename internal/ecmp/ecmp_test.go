package ecmp_test

import (
	"net/netip"
	"testing"

	"bgpsim/internal/ecmp"
)

func TestIndexStableAndBounded(t *testing.T) {
	ft := ecmp.FiveTuple{
		SrcIP: netip.MustParseAddr("10.1.2.3"), DstIP: netip.MustParseAddr("198.51.100.7"),
		SrcPort: 40000, DstPort: 443, Proto: 6,
	}
	first := ecmp.Index(ft, 8)
	for i := 0; i < 100; i++ {
		if got := ecmp.Index(ft, 8); got != first {
			t.Fatalf("hash is unstable: %d vs %d", got, first)
		}
	}
	if first < 0 || first >= 8 {
		t.Fatalf("index out of range: %d", first)
	}
	if ecmp.Index(ft, 1) != 0 {
		t.Fatal("a single-path group must map every flow to 0")
	}
}

func TestDistributeSumsToTotal(t *testing.T) {
	shares := ecmp.Distribute(1000, 12.5, 4)
	sum := 0.0
	for _, s := range shares {
		sum += s
	}
	if d := sum - 12.5; d > 1e-9 || d < -1e-9 {
		t.Fatalf("shares sum to %v, want 12.5", sum)
	}
	// Every path should get a non-trivial share with 1000 flows.
	for i, s := range shares {
		if s < 1.0 {
			t.Errorf("path %d got only %v Gbps of 12.5", i, s)
		}
	}
}
