package bgp_test

import (
	"testing"

	"bgpsim/internal/bgp"
	"bgpsim/internal/model"
)

func TestASPathPrependAndLength(t *testing.T) {
	a := bgp.NewAttr(100)
	a = a.WithOrigin(model.OriginIGP)
	a = a.Prepend(64500, 1)
	a = a.Prepend(64500, 2)
	if got := a.ASPathString(); got != "64500 64500 64500" {
		t.Fatalf("path %q", got)
	}
	if a.ASLen != 3 {
		t.Fatalf("length %d, want 3", a.ASLen)
	}
	if !a.HasAS(64500) {
		t.Fatal("HasAS missed our own AS")
	}
	if a.HasAS(64600) {
		t.Fatal("HasAS found an AS that is not present")
	}
	if a.OriginAS() != 64500 {
		t.Fatalf("origin AS %d", a.OriginAS())
	}
	if a.FirstAS() != 64500 {
		t.Fatalf("first AS %d", a.FirstAS())
	}
}

func TestASSetCountsAsOne(t *testing.T) {
	a := bgp.NewAttr(100)
	a.Segments = []model.ASeg{
		{Type: model.ASSequence, ASNs: []uint32{65001}},
		{Type: model.ASSet, ASNs: []uint32{65002, 65003, 65004}},
		{Type: model.ASSequence, ASNs: []uint32{65005}},
	}
	a.ASLen = 3 // 1 + 1 for the set + 1
	if got := a.ASPathString(); got != "65001 {65002,65003,65004} 65005" {
		t.Fatalf("path %q", got)
	}
	if a.OriginAS() != 65005 {
		t.Fatalf("origin AS %d", a.OriginAS())
	}
}

func TestCommunities(t *testing.T) {
	a := bgp.NewAttr(100)
	a = a.AddCommunities([]model.Community{model.NewCommunity(65000, 1), model.NewCommunity(65000, 2)})
	a = a.AddCommunities([]model.Community{model.NewCommunity(65000, 2), model.NewCommunity(65000, 3)})
	if len(a.Communities) != 3 {
		t.Fatalf("%d communities, want 3 (deduplicated)", len(a.Communities))
	}
	if !a.HasCommunity(model.NewCommunity(65000, 3)) {
		t.Fatal("missing community")
	}
	if a.HasCommunity(model.NewCommunity(65000, 9)) {
		t.Fatal("phantom community")
	}
}

func TestReflectionStampsClusterOnce(t *testing.T) {
	a := bgp.NewAttr(100)
	a = a.WithReflection(1, 42)
	a = a.WithReflection(1, 43) // same cluster, must not duplicate
	if len(a.ClusterList) != 1 || a.ClusterList[0] != 1 {
		t.Fatalf("cluster list %v", a.ClusterList)
	}
	if a.OriginatorID != 42 {
		t.Fatalf("originator %d, want 42 (first wins)", a.OriginatorID)
	}
	if !a.HasCluster(1) {
		t.Fatal("HasCluster missed the cluster")
	}
	a = a.WithReflection(2, 42)
	if len(a.ClusterList) != 2 {
		t.Fatalf("expected two clusters, got %v", a.ClusterList)
	}
}

func TestCommunityParse(t *testing.T) {
	for _, tc := range []struct {
		in  string
		asn uint16
		val uint16
		ok  bool
	}{
		{"65000:100", 65000, 100, true},
		{"0:0", 0, 0, true},
		{"65535:65535", 65535, 65535, true},
		{"70000:1", 0, 0, false}, // ASN too large
		{"1:65536", 0, 0, false}, // value too large
		{"nope", 0, 0, false},
	} {
		c, err := model.ParseCommunity(tc.in)
		if tc.ok && err != nil {
			t.Errorf("%s: unexpected error %v", tc.in, err)
			continue
		}
		if !tc.ok {
			if err == nil {
				t.Errorf("%s: expected an error", tc.in)
			}
			continue
		}
		if c.ASN() != tc.asn || c.Value() != tc.val {
			t.Errorf("%s parsed as %d:%d", tc.in, c.ASN(), c.Value())
		}
	}
}
