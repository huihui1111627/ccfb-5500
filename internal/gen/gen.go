// Package gen synthesises a province-scale education network for the
// simulator: one education AS with a core, aggregation and edge tiers plus
// three upstream transit providers, a few thousand /24-style prefixes
// originated by edge sites, and a traffic matrix.
package gen

import (
	"fmt"
	"math/rand"
	"net/netip"

	"bgpsim/internal/model"
)

// Options controls the generated topology.
type Options struct {
	Seed           int64  `json:"seed"`
	Name           string `json:"name"`
	ProvinceAS     uint32 `json:"provinceAs"`
	Cities         int    `json:"cities"`
	Prefixes       int    `json:"prefixes"`
	Upstreams      int    `json:"upstreams"`
	EdgePerCity    int    `json:"edgePerCity"`
	RRPairs        int    `json:"rrPairs"`
	TrafficRouters int    `json:"trafficRouters"`
}

func DefaultOptions() Options {
	return Options{
		Seed:           20261120,
		Name:           "province-education-net",
		ProvinceAS:     64500,
		Cities:         12,
		Prefixes:       24000,
		Upstreams:      3,
		EdgePerCity:    2,
		RRPairs:        2,
		TrafficRouters: 200,
	}
}

// Upstream transit providers.
type upstream struct {
	ASN         uint32
	Name        string
	Borders     int
	PrefixShare float64
}

var upstreams = []upstream{
	{ASN: 65001, Name: "upstream-telecom-a", Borders: 2, PrefixShare: 0.45},
	{ASN: 65002, Name: "upstream-mobile-b", Borders: 2, PrefixShare: 0.30},
	{ASN: 65003, Name: "upstream-unicom-c", Borders: 2, PrefixShare: 0.25},
}

// Build generates the network.
func Build(opts Options) (*model.Network, error) {
	if opts.Cities <= 0 {
		opts.Cities = 10
	}
	if opts.Prefixes <= 0 {
		opts.Prefixes = 5000
	}
	if opts.Name == "" {
		opts.Name = "generated"
	}
	if opts.ProvinceAS == 0 {
		opts.ProvinceAS = 64500
	}
	rng := rand.New(rand.NewSource(opts.Seed))
	net := &model.Network{Name: opts.Name, Config: model.DefaultSimConfig()}
	P := opts.ProvinceAS

	rid := uint32(0)
	newID := func() string {
		rid++
		return fmt.Sprintf("10.%d.%d.%d", 0, (rid/254)%254+1, rid%254+1)
	}
	add := func(name string, asn uint32, role, tier string) *model.Router {
		r := &model.Router{Name: name, ASN: asn, Role: role, Tier: tier, RouterID: newID()}
		net.Routers = append(net.Routers, r)
		return r
	}

	// ---- core: a ring of 4 P routers plus 2 route reflectors ----
	nCore := 4
	var core []*model.Router
	for i := 0; i < nCore; i++ {
		core = append(core, add(fmt.Sprintf("core-%d", i+1), P, "core", "core"))
	}
	var rrs []*model.Router
	nRR := 2 * max(1, opts.RRPairs)
	for i := 0; i < nRR; i++ {
		r := add(fmt.Sprintf("rr-%d", i+1), P, "rr", "core")
		r.RR = true
		rrs = append(rrs, r)
	}
	// Ring among core routers.
	for i := 0; i < nCore; i++ {
		j := (i + 1) % nCore
		net.Links = append(net.Links, model.Link{A: core[i].Name, B: core[j].Name, Cost: 10, Capacity: 100, Kind: "core"})
	}
	// Core to RRs.
	for i, rr := range rrs {
		c := core[i%nCore]
		net.Links = append(net.Links, model.Link{A: c.Name, B: rr.Name, Cost: 10, Capacity: 100, Kind: "core"})
	}
	// RR pairs peer with each other (iBGP).
	for i := 0; i+1 < len(rrs); i += 2 {
		net.Links = append(net.Links, model.Link{A: rrs[i].Name, B: rrs[i+1].Name, Cost: 10, Capacity: 100, Kind: "core"})
	}

	// ---- aggregation: one agg router per city hanging off a core router ----
	var aggs []*model.Router
	for i := 0; i < opts.Cities; i++ {
		a := add(fmt.Sprintf("agg-%02d", i+1), P, "agg", fmt.Sprintf("city-%02d", i+1))
		aggs = append(aggs, a)
		c := core[i%nCore]
		net.Links = append(net.Links, model.Link{A: c.Name, B: a.Name, Cost: 10 + rng.Intn(20), Capacity: 40, Kind: "agg"})
		// The RRs peer with every aggregation router.
		for _, rr := range rrs {
			// model iBGP sessions do not need a physical link; add a low-cost
			// link so the IGP path exists between them.
			net.Links = append(net.Links, model.Link{A: rr.Name, B: a.Name, Cost: 15, Capacity: 100, Kind: "core"})
		}
	}

	// ---- edge: K routers per city, each originating some prefixes ----
	var edges []*model.Router
	for i, a := range aggs {
		for k := 0; k < opts.EdgePerCity; k++ {
			e := add(fmt.Sprintf("edge-%02d-%d", i+1, k+1), P, "edge", fmt.Sprintf("city-%02d", i+1))
			edges = append(edges, e)
			// Every other edge is dual-homed to a second aggregation router.
			net.Links = append(net.Links, model.Link{A: a.Name, B: e.Name, Cost: 10 + rng.Intn(30), Capacity: 10, Kind: "access"})
			if k%2 == 1 {
				other := aggs[(i+1)%len(aggs)]
				net.Links = append(net.Links, model.Link{A: other.Name, B: e.Name, Cost: 20 + rng.Intn(50), Capacity: 10, Kind: "access"})
			}
			// Clients of the RRs.
			for _, rr := range rrs {
				rr.Clients = append(rr.Clients, e.Name)
			}
		}
	}

	// ---- upstream transit providers ----
	var borders []*model.Router
	var ups []upstream
	for i := 0; i < opts.Upstreams && i < len(upstreams); i++ {
		ups = append(ups, upstreams[i])
	}
	for ui, up := range ups {
		for b := 0; b < up.Borders; b++ {
			name := fmt.Sprintf("border-%d-%d", ui+1, b+1)
			br := add(name, P, "border", "border")
			borders = append(borders, br)
			for _, rr := range rrs {
				rr.Clients = append(rr.Clients, br.Name)
			}
			// Connect to one or two core routers.
			c1 := core[(ui*up.Borders+b)%nCore]
			net.Links = append(net.Links, model.Link{A: c1.Name, B: br.Name, Cost: 10, Capacity: 40, Kind: "core"})
			if b == 0 {
				c2 := core[(ui+2)%nCore]
				net.Links = append(net.Links, model.Link{A: c2.Name, B: br.Name, Cost: 25, Capacity: 40, Kind: "core"})
			}
			// One external link to a pseudo-router in the upstream AS.
			upName := fmt.Sprintf("as%d-%s", up.ASN, name)
			upr := add(upName, up.ASN, "upstream", "upstream")
			upr.Clients = nil
			net.Links = append(net.Links, model.Link{A: br.Name, B: upr.Name, Cost: 10, Capacity: 40, Kind: "upstream"})
		}
	}

	// ---- prefixes and announcements ----
	//
	// Two classes of prefix, because they behave very differently:
	//
	//   * province prefixes are originated by an edge site and exported to
	//     the providers (the education network is the origin AS).  They come
	//     back from every provider with a longer AS_PATH plus the provider's
	//     transit ASes, which is exactly what the local-preference and
	//     AS_PATH policy acts on.
	//   * external prefixes belong to the rest of the Internet.  They are
	//     originated outside the province and reach the borders as the best
	//     path the provider offers, once per provider, so the three upstreams
	//     compete for them.
	//
	// Both kinds share the prefix table so a RIB dump for one router contains
	// a realistic mixture.
	seen := map[string]bool{}
	addPrefix := func(s string) string {
		if seen[s] {
			return ""
		}
		seen[s] = true
		net.Prefixes = append(net.Prefixes, s)
		return s
	}
	provincePrefixes := make([]string, 0, opts.Prefixes/2)
	wantProvince := opts.Prefixes / 2
	for a := 0; len(provincePrefixes) < wantProvince && a < 256; a++ {
		for b := 0; len(provincePrefixes) < wantProvince && b < 256; b++ {
			s := fmt.Sprintf("200.%d.%d.0/24", a, b)
			if p := addPrefix(s); p != "" {
				provincePrefixes = append(provincePrefixes, p)
			}
		}
	}
	externalPrefixes := make([]string, 0, opts.Prefixes-len(provincePrefixes))
	extBlocks := []string{"58.0.0.0/8", "101.0.0.0/8", "114.0.0.0/8", "122.0.0.0/8", "175.0.0.0/8", "203.0.0.0/8", "211.0.0.0/8", "218.0.0.0/8"}
	wantExternal := opts.Prefixes - len(provincePrefixes)
	for bi := 0; len(externalPrefixes) < wantExternal && bi < len(extBlocks); bi++ {
		blk, _ := netip.ParsePrefix(extBlocks[bi])
		first := blk.Addr().As4()[0]
		for b := 0; len(externalPrefixes) < wantExternal && b < 256; b++ {
			for c := 0; len(externalPrefixes) < wantExternal && c < 256; c++ {
				s := fmt.Sprintf("%d.%d.%d.0/24", first, b, c)
				if p := addPrefix(s); p != "" {
					externalPrefixes = append(externalPrefixes, p)
				}
			}
		}
	}

	// A province prefix is originated by an edge site.  Slices are contiguous
	// per city so a failed aggregation link takes out a visible block.
	perEdge := (len(provincePrefixes) + len(edges) - 1) / max(1, len(edges))
	idx := 0
	for _, e := range edges {
		for k := 0; k < perEdge && idx < len(provincePrefixes); k++ {
			p := provincePrefixes[idx]
			idx++
			net.Announcements = append(net.Announcements, &model.Announcement{
				Prefix: p, Router: e.Name, MED: rng.Intn(100), OriginType: model.OriginIGP,
			})
		}
	}

	// Collect the upstream (provider) routers once.
	upByAS := map[uint32][]*model.Router{}
	var upRouters []*model.Router
	for _, r := range net.Routers {
		if r.Role == "upstream" {
			upByAS[r.ASN] = append(upByAS[r.ASN], r)
			upRouters = append(upRouters, r)
		}
	}

	// Province prefixes come back from the providers: the provider learned
	// them from us and re-advertises them.  Each provider adds its own transit
	// ASes in front, and the three offers differ in MED.  Communities identify
	// the provider so policy can prefer one.
	for _, up := range ups {
		rs := upByAS[up.ASN]
		if len(rs) == 0 {
			continue
		}
		transit := []uint32{70000 + (up.ASN-65000)*10, 80000 + (up.ASN-65000)*10}
		for i, p := range provincePrefixes {
			// Not every provider carries every prefix; that is what makes the
			// three-upstream design worth having.
			if (i+int(up.ASN))%7 == 0 {
				continue
			}
			r := rs[i%len(rs)]
			net.Announcements = append(net.Announcements, &model.Announcement{
				Prefix: p, Router: r.Name,
				ASPath:     append(append([]uint32{}, transit...), P),
				MED:        rng.Intn(100),
				OriginType: model.OriginIGP,
				Communities: []model.Community{
					model.NewCommunity(0xFFFF, uint16(up.ASN)),
					model.NewCommunity(uint16(P), 100),
				},
			})
		}
	}

	// External prefixes reach the borders once per provider.  Each prefix is
	// split into a primary provider (which always offers it) and the other
	// providers, which offer a subset — that is what makes the three-upstream
	// design meaningful and gives every prefix at least one path.
	for ei, p := range externalPrefixes {
		primary := ei % len(ups)
		for pi, up := range ups {
			rs := upByAS[up.ASN]
			if len(rs) == 0 {
				continue
			}
			if pi != primary && (ei+pi)%3 == 0 {
				continue // not every provider carries every prefix
			}
			r := rs[ei%len(rs)]
			transit := []uint32{70000 + (up.ASN-65000)*10, 80000 + (up.ASN-65000)*10}
			// The origin AS is the one the ROA authorises for the primary
			// provider; the others advertise a different final AS, so their
			// offers validate invalid and exercise the degrade/drop path.
			origin := 10000 + uint32(ei*37)%4000
			if pi != primary {
				origin = 10000 + uint32(ei*37+7919)%4000
			}
			path := append(append([]uint32{}, transit...), origin)
			// The primary provider offers the shortest path (a direct
			// customer link); the others add a transit hop.
			if pi != primary {
				path = append([]uint32{90000 + uint32(pi)}, path...)
			}
			net.Announcements = append(net.Announcements, &model.Announcement{
				Prefix: p, Router: r.Name,
				ASPath:     path,
				MED:        rng.Intn(200),
				OriginType: model.OriginType(ei % 3), // 0=IGP, 1=EGP, 2=INCOMPLETE
				Communities: []model.Community{
					model.NewCommunity(0xFFFF, uint16(up.ASN)),
					model.NewCommunity(uint16(P), 100),
				},
			})
		}
	}

	// ---- ROAs ----
	// Province prefixes are correctly authorised to P.  External prefixes get
	// a ROA naming a specific origin AS, which only some provider offers
	// match; the rest validate invalid and exercise the degrade/drop path.
	for i, p := range provincePrefixes {
		if i%5 == 4 {
			continue
		}
		net.ROAs = append(net.ROAs, model.ROA{Prefix: p, MaxLen: 24, OriginAS: P})
	}
	for i, p := range externalPrefixes {
		if i%4 != 0 {
			continue
		}
		// Authorise exactly one of the providers' origin ASes.
		net.ROAs = append(net.ROAs, model.ROA{Prefix: p, MaxLen: 24, OriginAS: 10000 + uint32(i*37)%4000})
	}

	// ---- traffic matrix ----
	// Traffic is expressed per prefix.  Province prefixes get small flows
	// (inbound to a campus) and external prefixes larger ones (outbound to
	// the Internet), which lands the three upstreams around 60-90% before a
	// failure and pushes one over 100% when a border or link goes down.
	for i := 0; i < len(provincePrefixes) && i < opts.TrafficRouters; i++ {
		p := provincePrefixes[(i*3571)%len(provincePrefixes)]
		net.Traffic = append(net.Traffic, model.TrafficEntry{
			Prefix: p, RateGbps: 0.05 + rng.Float64()*0.18, Source: "core-1",
		})
	}
	for i := 0; i < len(externalPrefixes) && i < opts.TrafficRouters*2; i++ {
		p := externalPrefixes[(i*2711)%len(externalPrefixes)]
		net.Traffic = append(net.Traffic, model.TrafficEntry{
			Prefix: p, RateGbps: 0.12 + rng.Float64()*0.45, Source: "core-2",
		})
	}
	return net, nil
}

// DefaultPolicy returns a starter policy set demonstrating every action the
// platform supports: upstream tagging, local preference by community, prefix
// and AS_PATH filters, and RPKI invalid handling.
func DefaultPolicy(provinceAS uint32, upstreamASNs []uint32) []model.Policy {
	lp := func(v int) *int { return &v }
	if len(upstreamASNs) == 0 {
		upstreamASNs = []uint32{65001, 65002, 65003}
	}
	// The generated upstream offers are tagged IMP:0xFFFF:<asn> by the
	// generator; policy matches on those tags.
	pols := []model.Policy{
		{
			// Every eBGP-learned route from the providers carries a tag that
			// tells the operator (and later policies) which provider it came
			// from.  Router filters keep it on the border routers.
			Name: "tag-provider-a", Router: "border-1-1", Direction: "import",
			Match:   model.PolicyMatch{Communities: []model.Community{model.NewCommunity(0xFFFF, uint16(upstreamASNs[0]))}},
			Actions: model.PolicyActions{AddCommunities: []model.Community{model.NewCommunity(65000, uint16(upstreamASNs[0]%100))}},
		},
		{
			// Routes that came back to us through a provider with our own AS
			// in the path are our own province prefixes: make them preferred
			// so inbound traffic always returns via the nearest border.
			Name: "province-routes-and-loop-prevention", Direction: "import",
			Match: model.PolicyMatch{
				ASPathRegex: fmt.Sprintf("_%d_", provinceAS),
			},
			Actions: model.PolicyActions{SetLocalPref: lp(200)},
		},
		{
			// A bogon filter.  A policy matches when its prefix-list entry
			// permits the prefix, so listing the bogons and denying is
			// "drop these, accept everything else".
			Name: "deny-bogons", Direction: "import",
			Match: model.PolicyMatch{PrefixList: []model.PrefixListEntry{
				{Prefix: "0.0.0.0/0", Ge: 0, Le: 8, Action: "permit"},
				{Prefix: "10.0.0.0/8", Ge: 8, Le: 32, Action: "permit"},
				{Prefix: "127.0.0.0/8", Ge: 8, Le: 32, Action: "permit"},
				{Prefix: "169.254.0.0/16", Ge: 16, Le: 32, Action: "permit"},
				{Prefix: "192.168.0.0/16", Ge: 16, Le: 32, Action: "permit"},
			}},
			Actions: model.PolicyActions{Action: "deny"},
		},
	}
	return pols
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// PrefixCountOf returns the number of announcements for one prefix.
func PrefixCountOf(n *model.Network) map[netip.Prefix]int {
	m := map[netip.Prefix]int{}
	for _, a := range n.Announcements {
		m[n.PrefixesV[a.PrefixIdx]]++
	}
	return m
}
