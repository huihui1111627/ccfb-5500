// Package traffic turns a converged simulation plus a per-prefix traffic
// matrix into per-link load, and computes utilisation for every upstream and
// internal link.
package traffic

import (
	"sort"

	"bgpsim/internal/ecmp"
	"bgpsim/internal/model"
	"bgpsim/internal/sim"
)

// Flow is one prefix's traffic, resolved to the paths that carry it.
type Flow struct {
	Prefix   string    `json:"prefix"`
	RateGbps float64   `json:"rateGbps"`
	Paths    []string  `json:"paths"` // egress router names
	Split    []float64 `json:"split"` // per-path share, sums to RateGbps
	ECMP     int       `json:"ecmp"`
}

// LinkLoad is the utilisation of one link.
type LinkLoad struct {
	Link         string  `json:"link"`
	A            string  `json:"a"`
	B            string  `json:"b"`
	Kind         string  `json:"kind"`
	CapacityGbps float64 `json:"capacityGbps"`
	LoadGbps     float64 `json:"loadGbps"`
	Utilisation  float64 `json:"utilisation"` // 0..1+, >1 means oversubscribed
	Up           bool    `json:"up"`
	Flows        int     `json:"flows"`
}

// Report is the whole analysis.
type Report struct {
	Flows        []Flow     `json:"flows"`
	Links        []LinkLoad `json:"links"`
	Upstreams    []LinkLoad `json:"upstreams"`
	TotalGbps    float64    `json:"totalGbps"`
	RoutedGbps   float64    `json:"routedGbps"`
	UnroutedGbps float64    `json:"unroutedGbps"`
	MaxUtil      float64    `json:"maxUtil"`
	Overloaded   []string   `json:"overloaded"`
	SourceRouter string     `json:"sourceRouter"`
}

// Analyze computes the load report.  Traffic for a prefix is attributed from
// the configured source router (default core-1) along the selected path's
// egress router, and split across ECMP members with the five-tuple hash.
func Analyze(n *model.Network, e *sim.Engine, flows int) *Report {
	if flows <= 0 {
		flows = 512
	}
	r := &Report{}
	// Accumulate per-link load: for every router-to-egress pair, the traffic
	// walks the IGP shortest path.  We approximate the IGP path by the
	// shortest-path tree from the source router.
	load := map[int]float64{}
	perLinkFlows := map[int]int{}
	upGbps := map[int]float64{}

	srcName := "core-1"
	for _, t := range n.Traffic {
		if t.Source == "" {
			continue
		}
		srcName = t.Source
		break
	}
	src := n.RouterIndex(srcName)
	if src < 0 {
		src = 0
	}
	r.SourceRouter = n.Routers[src].Name

	for _, t := range n.Traffic {
		p := t.PrefixIdx
		from := src
		if t.Source != "" {
			if i := n.RouterIndex(t.Source); i >= 0 {
				from = i
			}
		}
		best := e.Best(from, p)
		if best == nil {
			r.UnroutedGbps += t.RateGbps
			continue
		}
		lr := e.RIB[from][p]
		var egresses []int
		for _, rt := range lr.ECMP {
			egresses = append(egresses, rt.Egress)
		}
		if len(egresses) == 0 {
			egresses = []int{best.Egress}
		}
		// Split using the five-tuple hash so unequal ECMP shares show up.
		shares := ecmp.Distribute(flows, t.RateGbps, len(egresses))
		fl := Flow{Prefix: t.Prefix, RateGbps: t.RateGbps, ECMP: len(egresses)}
		for i, eg := range egresses {
			fl.Paths = append(fl.Paths, n.Routers[eg].Name)
			fl.Split = append(fl.Split, shares[i])
			upGbps[eg] += shares[i]
			links := shortestPathLinks(n, e, from, eg)
			for _, li := range links {
				load[li] += shares[i]
				perLinkFlows[li]++
			}
		}
		r.Flows = append(r.Flows, fl)
		r.RoutedGbps += t.RateGbps
	}
	r.TotalGbps = r.RoutedGbps + r.UnroutedGbps

	for li := range n.Links {
		l := &n.Links[li]
		up := !e.LinkDown[li] && !e.RouterDown[l.AIdx] && !e.RouterDown[l.BIdx]
		ll := LinkLoad{
			Link: l.A + " - " + l.B,
			A:    l.A, B: l.B, Kind: l.Kind,
			CapacityGbps: l.Capacity,
			LoadGbps:     load[li],
			Up:           up,
			Flows:        perLinkFlows[li],
		}
		if l.Capacity > 0 {
			ll.Utilisation = ll.LoadGbps / l.Capacity
		}
		r.Links = append(r.Links, ll)
		if up && ll.Utilisation > r.MaxUtil {
			r.MaxUtil = ll.Utilisation
		}
		if up && ll.Utilisation > 1.0 {
			r.Overloaded = append(r.Overloaded, ll.Link)
		}
	}
	// Upstream links carry the traffic that leaves through the border on the
	// near side of the link, which is exactly what upGbps recorded as traffic
	// egressing via that border.
	for _, l := range n.Links {
		if l.Kind != "upstream" {
			continue
		}
		var border string
		if n.Routers[l.AIdx].ASN == n.Routers[0].ASN {
			border = l.A
		} else {
			border = l.B
		}
		// Find the border's upstream link index.
		ll := LinkLoad{Link: l.A + " - " + l.B, A: l.A, B: l.B, Kind: l.Kind,
			CapacityGbps: l.Capacity,
			Up:           !e.LinkDown[l.Index] && !e.RouterDown[l.AIdx] && !e.RouterDown[l.BIdx]}
		// Load on the upstream link is the sum of traffic exiting via this
		// border, which is the same as the internal links' contribution.
		ll.LoadGbps = upGbps[n.RouterIndex(border)]
		if l.Capacity > 0 {
			ll.Utilisation = ll.LoadGbps / l.Capacity
		}
		r.Upstreams = append(r.Upstreams, ll)
	}
	sort.Slice(r.Upstreams, func(i, j int) bool { return r.Upstreams[i].Link < r.Upstreams[j].Link })
	sort.Slice(r.Flows, func(i, j int) bool { return r.Flows[i].RateGbps > r.Flows[j].RateGbps })
	return r
}

// shortestPathLinks returns the link indexes on the IGP shortest path from
// src to dst, using the engine's current IGP distances.  When several paths
// have equal cost the function picks the deterministic one (lowest next-hop
// index) so a report is reproducible.
func shortestPathLinks(n *model.Network, e *sim.Engine, src, dst int) []int {
	if src == dst {
		return nil
	}
	var out []int
	cur := src
	seen := map[int]bool{}
	for cur != dst {
		if seen[cur] {
			return out // cycle guard
		}
		seen[cur] = true
		curDist := e.IGPCost(cur, dst)
		if curDist < 0 {
			return out
		}
		next := -1
		bestCost := -1
		bestLink := -1
		for _, li := range n.Routers[cur].Adj {
			l := &n.Links[li]
			if e.LinkDown[li] {
				continue
			}
			var nb int
			if l.AIdx == cur {
				nb = l.BIdx
			} else {
				nb = l.AIdx
			}
			if n.Routers[nb].ASN != n.Routers[cur].ASN {
				continue // IGP does not cross AS boundaries
			}
			d := e.IGPCost(nb, dst)
			if d < 0 {
				continue
			}
			total := d + l.Cost
			if curDist >= 0 && total != curDist {
				continue // only links that lie on a shortest path
			}
			if bestCost < 0 || total < bestCost || (total == bestCost && (next < 0 || nb < next)) {
				bestCost = total
				next = nb
				bestLink = li
			}
		}
		if next < 0 {
			return out
		}
		out = append(out, bestLink)
		cur = next
	}
	return out
}
