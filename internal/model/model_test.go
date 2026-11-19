package model_test

import (
	"testing"

	"bgpsim/internal/model"
)

func base() *model.Network {
	return &model.Network{
		Name: "t",
		Routers: []*model.Router{
			{Name: "a", ASN: 1, RouterID: "10.0.0.1", RR: true, Clients: []string{"b", "c"}},
			{Name: "b", ASN: 1, RouterID: "10.0.0.2"},
			{Name: "c", ASN: 1, RouterID: "10.0.0.3"},
			{Name: "x", ASN: 2, RouterID: "10.0.0.4"},
		},
		Links: []model.Link{
			{A: "a", B: "b", Cost: 10},
			{A: "c", B: "x", Cost: 10},
		},
		Announcements: []*model.Announcement{
			{Router: "c", Prefix: "198.51.100.0/24"},
		},
	}
}

func TestBuildSessionsAndClients(t *testing.T) {
	n := base()
	if err := n.Build(); err != nil {
		t.Fatal(err)
	}
	// a-b and a-c are iBGP (client sessions), c-x is eBGP.
	var ibgp, ebgp int
	for _, s := range n.Sessions {
		if s.EBGP {
			ebgp++
		} else {
			ibgp++
		}
	}
	if ebgp != 1 {
		t.Errorf("%d eBGP sessions, want 1", ebgp)
	}
	if ibgp != 2 {
		t.Errorf("%d iBGP sessions, want 2 (RR to each client)", ibgp)
	}
	// c should learn it is a client of a.
	ci := n.RouterIndex("c")
	found := false
	for _, rr := range n.ClientOf[ci] {
		if n.Routers[rr].Name == "a" {
			found = true
		}
	}
	if !found {
		t.Error("c is not registered as a client of a")
	}
}

func TestSPFDistances(t *testing.T) {
	n := base()
	if err := n.Build(); err != nil {
		t.Fatal(err)
	}
	a := n.RouterIndex("a")
	b := n.RouterIndex("b")
	x := n.RouterIndex("x")
	if d := n.SPF[a][b]; d != 10 {
		t.Errorf("a-b distance %d, want 10", d)
	}
	// a and x are in different ASes, so the intra-AS SPF has no route.
	if d := n.SPF[a][x]; d != -1 {
		t.Errorf("a-x distance %d, want -1 (cross-AS)", d)
	}
	if d := n.IGPCost(a, b); d != 10 {
		t.Errorf("IGP cost a->b %d, want 10", d)
	}
}

func TestDuplicateRouterRejected(t *testing.T) {
	n := &model.Network{
		Routers: []*model.Router{
			{Name: "a", ASN: 1, RouterID: "10.0.0.1"},
			{Name: "a", ASN: 1, RouterID: "10.0.0.2"},
		},
	}
	if err := n.Build(); err == nil {
		t.Fatal("Build accepted a duplicate router name")
	}
}

func TestUnknownReferencesRejected(t *testing.T) {
	n := &model.Network{
		Routers:       []*model.Router{{Name: "a", ASN: 1, RouterID: "10.0.0.1"}},
		Announcements: []*model.Announcement{{Router: "nope", Prefix: "198.51.100.0/24"}},
	}
	if err := n.Build(); err == nil {
		t.Fatal("Build accepted an announcement from an unknown router")
	}
}

func TestBadPrefixRejected(t *testing.T) {
	n := &model.Network{
		Routers:       []*model.Router{{Name: "a", ASN: 1, RouterID: "10.0.0.1"}},
		Announcements: []*model.Announcement{{Router: "a", Prefix: "not-a-prefix"}},
	}
	if err := n.Build(); err == nil {
		t.Fatal("Build accepted a malformed prefix")
	}
}

func TestAutoClientAttachment(t *testing.T) {
	// A non-RR router with no explicit client list is attached to every RR in
	// its AS so the topology still converges.
	n := base()
	n.Routers[1].Clients = nil
	n.Routers[0].Clients = nil
	if err := n.Build(); err != nil {
		t.Fatal(err)
	}
	b := n.RouterIndex("b")
	if len(n.ClientOf[b]) == 0 {
		t.Fatal("b was not auto-attached to an RR")
	}
}
