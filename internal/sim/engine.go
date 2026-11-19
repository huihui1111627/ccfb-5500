// Package sim implements the round-based BGP propagation model.
//
// Model, stated explicitly so results can be trusted:
//
//   - Time is discrete.  One round is Config.RoundSeconds.  A router
//     recomputes its best path for every prefix whose Adj-RIB-In changed in
//     the previous round, then advertises changes at the end of the round.
//     MRAI jitter and per-session timers are not modelled.
//   - Each router has a per-peer Adj-RIB-In and a Loc-RIB per prefix.
//   - eBGP: the sender prepends its ASN, sets the next hop and strips
//     LOCAL_PREF/MED; the receiver rejects paths containing its own ASN.
//   - iBGP: LOCAL_PREF is preserved, AS_PATH is not modified and the next hop
//     is the exit router.  Without a route reflector iBGP is a full mesh and
//     iBGP-learned routes are not re-advertised over iBGP (split horizon).
//   - Route reflection follows RFC 4456: client routes go to clients and
//     non-clients, non-client routes only to clients, nothing is reflected
//     back to its source, and a route whose CLUSTER_LIST already contains the
//     reflector's cluster ID is not reflected again.  This is what stops two
//     reflectors from looping routes between them.
//   - MED is compared only between paths whose leftmost AS is the same,
//     unless AlwaysCompareMED is set.
//   - The IGP metric in step 7 is the intra-AS shortest path from the router
//     to the exit router, recomputed when links or routers fail.
package sim

import (
	"fmt"
	"sort"

	"bgpsim/internal/bgp"
	"bgpsim/internal/dampening"
	"bgpsim/internal/model"
	"bgpsim/internal/policy"
	"bgpsim/internal/rpki"
)

// Route is one Adj-RIB-In / Loc-RIB entry.
type Route struct {
	Attr       *bgp.Attr
	Peer       int // router the route was received from (-1 = local)
	NextHop    int // BGP next-hop router
	Egress     int // router where traffic leaves this AS
	Link       int // egress link, -1 for iBGP/local
	FromEBGP   bool
	Local      bool
	ReceivedIn int // round number
}

// LocRIB is the selected path set for one (router, prefix).
type LocRIB struct {
	Best  *Route
	ECMP  []*Route
	Round int
}

// Engine is one simulation over a network.
type Engine struct {
	Net  *model.Network
	Pol  *policy.Engine
	RPKI *rpki.Validator
	Damp *dampening.Tracker
	Opts bgp.DecisionOptions

	RIB [][]*LocRIB
	adj [][][]*Route

	RouterDown     map[int]bool
	LinkDown       map[int]bool
	SessionDown    map[[2]int]bool
	sessionWasDown map[[2]int]bool

	igp   [][]int
	dirty map[int64]struct{}
	round int
	now   int64

	Updates   int
	Changes   []Change // recorded per-round diffs, capped
	truncated bool
	withheld  map[string]bool // "router|prefix" origins temporarily removed
	localIdx  [][]int         // per-router live announcement indexes
}

// Change is one RIB change for replay.
type Change struct {
	Round     int    `json:"round"`
	Router    string `json:"router"`
	Prefix    string `json:"prefix"`
	Withdrawn bool   `json:"withdrawn,omitempty"`
	ASPath    string `json:"asPath,omitempty"`
	Peer      string `json:"peer,omitempty"`
	NextHop   string `json:"nextHop,omitempty"`
	LocalPref uint32 `json:"localPref,omitempty"`
	MED       uint32 `json:"med,omitempty"`
	Origin    string `json:"origin,omitempty"`
	RPKI      string `json:"rpki,omitempty"`
	FromEBGP  bool   `json:"fromEBGP,omitempty"`
	Blackhole bool   `json:"blackhole,omitempty"`
}

const maxRecordedChanges = 400000

func key(r, p int) int64 { return int64(uint64(uint32(r))<<32 | uint64(uint32(p))) }

// New builds an engine with empty RIBs.
func New(net *model.Network, pol *policy.Engine, val *rpki.Validator) *Engine {
	if val == nil {
		val = rpki.New(nil)
	}
	nr := len(net.Routers)
	np := len(net.PrefixesV)
	e := &Engine{
		Net:  net,
		Pol:  pol,
		RPKI: val,
		Opts: bgp.DecisionOptions{
			AlwaysCompareMED: net.Config.AlwaysCompareMED,
			Multipath:        net.Config.Multipath,
			ECMPMaxPaths:     net.Config.ECMPMaxPaths,
		},
		RouterDown:     map[int]bool{},
		LinkDown:       map[int]bool{},
		SessionDown:    map[[2]int]bool{},
		sessionWasDown: map[[2]int]bool{},
		dirty:          map[int64]struct{}{},
		withheld:       map[string]bool{},
	}
	dc := net.Config.Dampening
	e.Damp = dampening.New(dampening.Config{
		Enabled:        dc.Enabled,
		PenaltyPerFlap: dc.PenaltyPerFlap,
		Suppress:       dc.Suppress,
		Reuse:          dc.Reuse,
		HalfLifeSec:    dc.HalfLifeSec,
		MaxPenalty:     dc.MaxPenalty,
	})
	e.RIB = make([][]*LocRIB, nr)
	e.adj = make([][][]*Route, nr)
	for r := 0; r < nr; r++ {
		e.RIB[r] = make([]*LocRIB, np)
		e.adj[r] = make([][]*Route, len(net.Routers[r].Peers))
		for s := range e.adj[r] {
			e.adj[r][s] = make([]*Route, np)
		}
	}
	e.recomputeIGP()
	e.rebuildLocalIndex()
	return e
}

// ---------------------------------------------------------------------------
// IGP
// ---------------------------------------------------------------------------

func (e *Engine) recomputeIGP() {
	n := len(e.Net.Routers)
	igp := make([][]int, n)
	for i := range igp {
		igp[i] = make([]int, n)
		for j := range igp[i] {
			igp[i][j] = -1
		}
		igp[i][i] = 0
	}
	// Group links by AS; only intra-AS links form the IGP graph.
	type edge struct {
		to, cost int
	}
	adj := make([][]edge, n)
	for li := range e.Net.Links {
		l := &e.Net.Links[li]
		if e.LinkDown[li] || e.RouterDown[l.AIdx] || e.RouterDown[l.BIdx] {
			continue
		}
		if e.Net.Routers[l.AIdx].ASN != e.Net.Routers[l.BIdx].ASN {
			continue
		}
		adj[l.AIdx] = append(adj[l.AIdx], edge{l.BIdx, l.Cost})
		adj[l.BIdx] = append(adj[l.BIdx], edge{l.AIdx, l.Cost})
	}
	// Dijkstra from every router.  AS sizes are small.
	for src := 0; src < n; src++ {
		if e.RouterDown[src] {
			continue
		}
		dist := igp[src]
		visited := make([]bool, n)
		for {
			u, best := -1, -1
			for i := 0; i < n; i++ {
				if !visited[i] && dist[i] >= 0 && (best < 0 || dist[i] < best) {
					u, best = i, dist[i]
				}
			}
			if u < 0 {
				break
			}
			visited[u] = true
			for _, ed := range adj[u] {
				if e.RouterDown[ed.to] {
					continue
				}
				nd := best + ed.cost
				if dist[ed.to] < 0 || nd < dist[ed.to] {
					dist[ed.to] = nd
				}
			}
		}
	}
	e.igp = igp
}

// IGPCost returns the current intra-AS cost from a to b, or -1.
// nextHopCost is the IGP distance from a to the next hop a route actually
// uses: the egress router for iBGP routes, the peer for eBGP routes.
func (e *Engine) nextHopCost(a int, rt *Route) int {
	if rt == nil {
		return -1
	}
	return e.IGPCost(a, rt.Egress)
}

func (e *Engine) IGPCost(a, b int) int {
	if a < 0 || b < 0 || a >= len(e.igp) || b >= len(e.igp) {
		return -1
	}
	if e.Net.Routers[a].ASN != e.Net.Routers[b].ASN {
		// Cross-AS: direct link cost, used for eBGP next hops.
		li := e.Net.LinkBetween(a, b)
		if li < 0 || e.LinkDown[li] {
			return -1
		}
		return e.Net.Links[li].Cost
	}
	return e.igp[a][b]
}

// ---------------------------------------------------------------------------
// Local routes and best path
// ---------------------------------------------------------------------------

func (e *Engine) localRoutes(r, p int) []*Route {
	var out []*Route
	for _, ai := range e.localIdx[r] {
		a := e.Net.Announcements[ai]
		if a.PrefixIdx != p {
			continue
		}
		lp := uint32(e.Net.Config.DefaultLocalPref)
		if a.LocalPref > 0 {
			lp = uint32(a.LocalPref)
		}
		attr := bgp.NewAttr(lp).WithOrigin(a.OriginType).WithMED(uint32(a.MED))
		if len(a.Communities) > 0 {
			attr = attr.AddCommunities(a.Communities)
		}
		if len(a.ASPath) > 0 {
			attr.Segments = []model.ASeg{{Type: model.ASSequence, ASNs: append([]uint32{}, a.ASPath...)}}
			attr.ASLen = len(a.ASPath)
		}
		originAS := e.Net.Routers[r].ASN
		if n := len(a.ASPath); n > 0 {
			originAS = a.ASPath[n-1]
		}
		attr.RPKI = e.RPKI.Validate(e.Net.PrefixesV[p], originAS)
		// Inbound policy for locally originated routes is not applied; an
		// operator uses an export policy for those.
		out = append(out, &Route{Attr: attr, Peer: -1, NextHop: r, Egress: r, Link: -1, Local: true})
	}
	return out
}

// candidates builds the candidate set for one (router,prefix) from its
// local routes and Adj-RIB-In.  It returns the parallel route slice so the
// winner index from bgp.Decide can be mapped back to an actual route.
func (e *Engine) candidates(r, p int) ([]*Route, []*bgp.Candidate, bool) {
	net := e.Net
	if e.RouterDown[r] {
		return nil, nil, false
	}
	var routes []*Route
	var locals []*Route
	locals = e.localRoutes(r, p)
	if len(locals) > 0 {
		routes = append(routes, locals...)
	} else {
		if e.Damp.Enabled() && e.Damp.Suppressed(r, p) {
			return nil, nil, false
		}
		for slot := range net.Routers[r].Peers {
			if rt := e.adj[r][slot][p]; rt != nil {
				routes = append(routes, rt)
			}
		}
	}
	// A route whose exit router is no longer reachable through the IGP cannot
	// be installed: BGP invalidates the next hop.  Dropping it here is what
	// makes a failed link actually remove routes rather than black-hole them.
	// Build a fresh slice: filtering in place would alias the caller's array.
	kept := make([]*Route, 0, len(routes))
	for _, rt := range routes {
		if rt.Peer >= 0 && e.IGPCost(r, rt.Egress) < 0 {
			continue
		}
		kept = append(kept, rt)
	}
	routes = kept
	if len(routes) == 0 {
		return nil, nil, true
	}
	var cands = make([]*bgp.Candidate, 0, len(routes))
	for i, rt := range routes {
		c := &bgp.Candidate{
			Attr:       rt.Attr,
			From:       r,
			IGPTarget:  rt.Egress,
			Peer:       rt.Peer,
			NextHop:    rt.NextHop,
			Egress:     rt.Egress,
			Link:       rt.Link,
			FromEBGP:   rt.FromEBGP,
			NeighborAS: rt.Attr.FirstAS(),
			Source:     "bgp",
			Local:      i < len(locals),
		}
		if rt.Peer < 0 {
			c.Source = "local"
			c.NeighborAS = net.Routers[r].ASN
			c.RouterID = net.Routers[r].ID
		} else {
			c.RouterID = net.Routers[rt.Peer].ID
			if rt.Attr.HasOriginator {
				c.RouterID = rt.Attr.OriginatorID
			}
		}
		if c.NeighborAS == 0 {
			c.NeighborAS = net.Routers[r].ASN
		}
		cands = append(cands, c)
	}
	return routes, cands, true
}

// Explain recomputes the decision for one pair with the full trace enabled.
// Used by the API when the UI asks why a prefix selected a path.
func (e *Engine) Explain(r, p int) *bgp.Decision {
	routes, cands, ok := e.candidates(r, p)
	if !ok || len(routes) == 0 {
		return nil
	}
	opts := e.Opts
	opts.Trace = true
	return bgp.Decide(e.Net, cands, opts)
}

// bestPath recomputes the Loc-RIB for one pair and reports whether the
// selected path changed in a way peers must hear about.
func (e *Engine) bestPath(r, p int) (changed bool) {
	net := e.Net
	old := e.RIB[r][p]

	var routes []*Route
	var locals []*Route
	if !e.RouterDown[r] {
		locals = e.localRoutes(r, p)
	}
	if len(locals) > 0 {
		routes = append(routes, locals...)
	} else if !e.RouterDown[r] {
		suppressed := e.Damp.Enabled() && e.Damp.Suppressed(r, p)
		if !suppressed {
			for slot := range net.Routers[r].Peers {
				if rt := e.adj[r][slot][p]; rt != nil {
					routes = append(routes, rt)
				}
			}
		}
	}

	if len(routes) == 0 {
		if old != nil {
			e.RIB[r][p] = nil
			return true
		}
		return false
	}

	cands := make([]*bgp.Candidate, 0, len(routes))
	for _, rt := range routes {
		c := &bgp.Candidate{
			Attr:       rt.Attr,
			From:       r,
			IGPTarget:  rt.Egress,
			Peer:       rt.Peer,
			NextHop:    rt.NextHop,
			Egress:     rt.Egress,
			Link:       rt.Link,
			FromEBGP:   rt.FromEBGP,
			NeighborAS: rt.Attr.FirstAS(),
			Source:     "bgp",
		}
		if rt.Peer < 0 {
			c.Source = "local"
			c.NeighborAS = net.Routers[r].ASN
			c.RouterID = net.Routers[r].ID
		} else {
			c.RouterID = net.Routers[rt.Peer].ID
			if rt.Attr.HasOriginator {
				c.RouterID = rt.Attr.OriginatorID
			}
		}
		if c.NeighborAS == 0 {
			c.NeighborAS = net.Routers[r].ASN
		}
		cands = append(cands, c)
	}
	opts := e.Opts
	opts.Trace = false
	dec := bgp.Decide(net, cands, opts)
	if dec.Winner < 0 {
		if old != nil {
			e.RIB[r][p] = nil
			return true
		}
		return false
	}
	best := routes[dec.Winner]
	lr := &LocRIB{Best: best, Round: e.round}
	for _, i := range dec.ECMP {
		lr.ECMP = append(lr.ECMP, routes[i])
	}
	if old != nil && old.Best != nil && routeEqual(old.Best, best) {
		// Keep the old trace so the UI still has the decision for an unchanged
		// entry, but update the round stamp.
		return false
	}
	e.RIB[r][p] = lr
	return true
}

func routeEqual(a, b *Route) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Peer == b.Peer && a.Egress == b.Egress && a.NextHop == b.NextHop &&
		a.FromEBGP == b.FromEBGP && a.Attr.EqualsAttrs(b.Attr)
}

// ---------------------------------------------------------------------------
// Advertisement
// ---------------------------------------------------------------------------

// Export computes what r sends to peer for prefix p given its selected route.
// Returns nil for "no advertisement" (withdraw if previously advertised).
func (e *Engine) Export(r, peer, p int, rt *Route) *Route {
	net := e.Net
	if rt == nil {
		return nil
	}
	ra, pa := net.Routers[r], net.Routers[peer]
	if ra.ASN != pa.ASN {
		// ---- eBGP ----
		if rt.Attr.HasAS(pa.ASN) {
			return nil // never send a path that would loop
		}
		attr := rt.Attr.Prepend(ra.ASN, 1).WithLocalPref(0)
		if !rt.Local {
			attr = attr.WithMED(0)
		}
		res := e.Pol.Apply(net, r, peer, policy.Outbound, net.PrefixesV[p], attr)
		if res.Denied {
			return nil
		}
		// The route entered our AS at the receiving border, so that router is
		// the egress for traffic matching it; the BGP next hop is the sender.
		return &Route{Attr: res.Attr, Peer: r, NextHop: r, Egress: peer,
			Link: net.LinkBetween(r, peer), FromEBGP: true, Local: false}
	}

	// ---- iBGP ----
	if rt.Peer == peer {
		return nil
	}
	// RFC 4456: a route is reflected to all clients, and to non-clients only
	// when it was learned from a client.  A route learned from a non-client
	// is never reflected to another non-client.
	peerIsClient := net.IsClient[r][peer]
	fromClient := rt.Local || rt.FromEBGP || (rt.Peer >= 0 && net.IsClient[r][rt.Peer])
	if ra.RR {
		if !peerIsClient && !fromClient {
			return nil // non-client to non-client is not reflected
		}
		if rt.Attr.HasCluster(ra.Cluster) {
			return nil // reflection loop
		}
		originator := ra.ID
		if rt.Peer >= 0 {
			originator = net.Routers[rt.Peer].ID
			if rt.Attr.HasOriginator {
				originator = rt.Attr.OriginatorID
			}
		}
		attr := rt.Attr.WithReflection(ra.Cluster, originator)
		res := e.Pol.Apply(net, r, peer, policy.Outbound, net.PrefixesV[p], attr)
		if res.Denied {
			return nil
		}
		return &Route{Attr: res.Attr, Peer: r, NextHop: rt.Egress, Egress: rt.Egress,
			Link: -1, FromEBGP: false}
	}
	// Plain iBGP: split horizon — only local and eBGP routes are exported.
	if !rt.Local && !rt.FromEBGP {
		return nil
	}
	res := e.Pol.Apply(net, r, peer, policy.Outbound, net.PrefixesV[p], rt.Attr)
	if res.Denied {
		return nil
	}
	return &Route{Attr: res.Attr, Peer: r, NextHop: rt.Egress, Egress: rt.Egress,
		Link: -1, FromEBGP: false}
}

// Import applies loop prevention, RPKI and inbound policy.
func (e *Engine) Import(r, from, p int, rt *Route) *Route {
	net := e.Net
	if rt == nil {
		return nil
	}
	if rt.FromEBGP && rt.Attr.HasAS(net.Routers[r].ASN) {
		return nil
	}
	attr := rt.Attr
	if rt.FromEBGP {
		// eBGP resets LOCAL_PREF to the local default on receipt.
		if attr.LocalPref == 0 {
			attr = attr.WithLocalPref(uint32(net.Config.DefaultLocalPref))
		}
		// Origin validation is an edge function: it runs on eBGP-learned
		// routes only.  iBGP routes keep the state they entered with.
		if e.RPKI.Enabled() {
			attr = e.RPKI.ValidateAttr(net.PrefixesV[p], attr)
		}
		switch net.Config.RPKIMode {
		case "drop":
			if attr.RPKI == model.RPKIInvalid {
				return nil
			}
		case "degrade":
			if attr.RPKI == model.RPKIInvalid {
				attr = attr.WithLocalPref(uint32(net.Config.RPKIDegradeLocalPref))
			}
		}
	}
	res := e.Pol.Apply(net, r, from, policy.Inbound, net.PrefixesV[p], attr)
	if res.Denied {
		return nil
	}
	out := *rt
	out.Attr = res.Attr
	out.ReceivedIn = e.round
	return &out
}

// ---------------------------------------------------------------------------
// Round stepping
// ---------------------------------------------------------------------------

type pendingKey struct{ rx, slot, p int }

// Step advances one round and returns whether any work was done (false means
// the network is converged).
func (e *Engine) Step() bool {
	e.round++
	e.now += int64(e.Net.Config.RoundSeconds)
	e.decayDampening()

	if len(e.dirty) == 0 {
		return false
	}
	// Recompute changed pairs.  Snapshot the dirty set first because
	// recomputation does not itself add entries.
	work := make([]int64, 0, len(e.dirty))
	for k := range e.dirty {
		work = append(work, k)
	}
	sort.Slice(work, func(i, j int) bool { return work[i] < work[j] })

	changedPairs := make([]int64, 0, len(work))
	for _, k := range work {
		r := int(k >> 32)
		p := int(k & 0xffffffff)
		before := e.RIB[r][p]
		after := e.bestPath(r, p)
		_ = after
		if before != e.RIB[r][p] {
			changedPairs = append(changedPairs, k)
		}
	}
	e.dirty = map[int64]struct{}{}
	if len(changedPairs) == 0 {
		return false
	}

	// Compute advertisements for every changed pair.
	pending := map[pendingKey]*Route{}
	for _, k := range changedPairs {
		r := int(k >> 32)
		p := int(k & 0xffffffff)
		var best *Route
		if lr := e.RIB[r][p]; lr != nil {
			best = lr.Best
		}
		for _, peer := range e.Net.Routers[r].Peers {
			if !e.sessionUsable(r, peer) {
				continue
			}
			adv := e.Export(r, peer, p, best)
			pending[pendingKey{peer, e.Net.Routers[peer].PeerSlot[r], p}] = adv
		}
	}

	// Deliver.  Note that "both nil" means "no route before and none now",
	// which is a no-op; but "no route before, a route now" must install even
	// though the previous Adj-RIB-In entry is nil.
	for pk, adv := range pending {
		cur := e.adj[pk.rx][pk.slot][pk.p]
		var filtered *Route
		if adv != nil {
			filtered = e.Import(pk.rx, e.Net.Routers[pk.rx].Peers[pk.slot], pk.p, adv)
		}
		if cur == nil && filtered == nil {
			continue
		}
		if cur != nil && filtered != nil && routeEqual(cur, filtered) {
			continue
		}
		e.adj[pk.rx][pk.slot][pk.p] = filtered
		e.Updates++
		e.dirty[key(pk.rx, pk.p)] = struct{}{}
		if cur != nil && filtered == nil && e.Damp.Enabled() {
			st := e.Damp.Get(pk.rx, pk.p)
			if e.Damp.Flap(st, e.now) {
				// Newly suppressed: recompute without this route next round.
				e.dirty[key(pk.rx, pk.p)] = struct{}{}
			}
		}
		e.record(pk.rx, pk.p, cur, filtered)
	}
	return len(e.dirty) > 0
}

func (e *Engine) decayDampening() {
	if !e.Damp.Enabled() {
		return
	}
	released := e.Damp.DecayAll(float64(e.Net.Config.RoundSeconds), e.now)
	for _, k := range released {
		e.dirty[k] = struct{}{}
	}
}

func (e *Engine) record(rx, p int, old, cur *Route) {
	if len(e.Changes) >= maxRecordedChanges {
		e.truncated = true
		return
	}
	ch := Change{Round: e.round, Router: e.Net.Routers[rx].Name, Prefix: e.Net.PrefixString(p)}
	if cur == nil {
		ch.Withdrawn = true
	} else {
		ch.ASPath = cur.Attr.ASPathString()
		ch.LocalPref = cur.Attr.LocalPref
		ch.MED = cur.Attr.MED
		ch.Origin = cur.Attr.Origin.String()
		ch.RPKI = string(cur.Attr.RPKI)
		ch.FromEBGP = cur.FromEBGP
		if cur.Peer >= 0 {
			ch.Peer = e.Net.Routers[cur.Peer].Name
		}
		ch.NextHop = e.Net.Routers[cur.NextHop].Name

	}
	e.Changes = append(e.Changes, ch)
}

// Converge runs rounds until stable; returns rounds used.
func (e *Engine) Converge(maxRounds int) int {
	if maxRounds <= 0 {
		maxRounds = 200
	}
	for i := 0; i < maxRounds; i++ {
		if !e.Step() {
			return i
		}
	}
	return maxRounds
}

// Seed marks every originated (router,prefix) pair dirty so the first
// converged state is built from the announcements.
func (e *Engine) Seed() {
	for r, anns := range e.localIdx {
		for _, ai := range anns {
			e.dirty[key(r, e.Net.Announcements[ai].PrefixIdx)] = struct{}{}
		}
	}
}

// SeedAll marks every pair dirty; used after policy changes.
func (e *Engine) SeedAll() {
	for r := 0; r < len(e.Net.Routers); r++ {
		for p := 0; p < len(e.Net.PrefixesV); p++ {
			e.dirty[key(r, p)] = struct{}{}
		}
	}
}

// ---------------------------------------------------------------------------
// Fault injection
// ---------------------------------------------------------------------------

// SetFaults installs a fault set and applies its immediate effects: affected
// sessions are dropped, IGP is recomputed, and changed pairs are resynced.
func (e *Engine) SetFaults(routers, links []int) {
	e.RouterDown = map[int]bool{}
	for _, r := range routers {
		e.RouterDown[r] = true
	}
	e.LinkDown = map[int]bool{}
	for _, l := range links {
		e.LinkDown[l] = true
	}
	e.applyFaults()
}

// SetRouterDown / SetLinkDown flip a single fault and apply it.
func (e *Engine) SetRouterDown(r int, down bool) { e.RouterDown[r] = down; e.applyFaults() }
func (e *Engine) SetLinkDown(l int, down bool)   { e.LinkDown[l] = down; e.applyFaults() }

func (e *Engine) sessionUsable(a, b int) bool {
	if a < 0 || b < 0 {
		return true
	}
	if e.RouterDown[a] || e.RouterDown[b] {
		return false
	}
	k := [2]int{a, b}
	if a > b {
		k = [2]int{b, a}
	}
	if e.SessionDown[k] {
		return false
	}
	ra, rb := e.Net.Routers[a], e.Net.Routers[b]
	if ra.ASN != rb.ASN {
		li := e.Net.LinkBetween(a, b)
		return li >= 0 && !e.LinkDown[li]
	}
	// iBGP sessions ride the IGP between the loopbacks.
	return e.IGPCost(a, b) >= 0
}

func (e *Engine) applyFaults() {
	e.recomputeIGP()
	e.Changes = nil
	e.truncated = false

	// Sessions that became unusable lose their Adj-RIB-In on both sides at
	// once: that is the withdrawal every BGP speaker sees when a session
	// drops, and it is the first event of the convergence replay.
	for _, s := range e.Net.Sessions {
		if e.sessionUsable(s.A, s.B) {
			continue
		}
		e.clearSession(s.A, s.B)
		e.clearSession(s.B, s.A)
	}
	// A downed router loses its entire RIB and all Adj-RIB-In.
	for r := range e.RouterDown {
		for p, lr := range e.RIB[r] {
			if lr != nil {
				e.record(r, p, lr.Best, nil)
				e.RIB[r][p] = nil
			}
		}
		for slot := range e.adj[r] {
			for p := range e.adj[r][slot] {
				e.adj[r][slot][p] = nil
			}
		}
	}
	// IGP costs changed, so every installed route has to be re-evaluated (the
	// cheapest exit may have moved) — but only in the next round, through the
	// normal propagation path, so the replay shows the ripple.
	for r := 0; r < len(e.Net.Routers); r++ {
		if e.RouterDown[r] {
			continue
		}
		for p, lr := range e.RIB[r] {
			if lr != nil {
				e.dirty[key(r, p)] = struct{}{}
			}
		}
	}
	// Sessions that came back need an initial table exchange.  Only those
	// sessions do a full dump; everything else converges incrementally.
	for _, s := range e.Net.Sessions {
		if !e.sessionUsable(s.A, s.B) {
			continue
		}
		k := [2]int{s.A, s.B}
		if s.A > s.B {
			k = [2]int{s.B, s.A}
		}
		if !e.sessionWasDown[k] {
			continue
		}
		e.fullExport(s.A, s.B)
		e.fullExport(s.B, s.A)
	}
	e.sessionWasDown = map[[2]int]bool{}
	// Remember which sessions are down now so a later restore is detected.
	for _, s := range e.Net.Sessions {
		if !e.sessionUsable(s.A, s.B) {
			k := [2]int{s.A, s.B}
			if s.A > s.B {
				k = [2]int{s.B, s.A}
			}
			e.sessionWasDown[k] = true
		}
	}
}

// fullExport dumps a's current best paths into b's Adj-RIB-In.
func (e *Engine) fullExport(a, b int) {
	slot := e.Net.Routers[b].PeerSlot[a]
	if slot < 0 || slot >= len(e.adj[b]) {
		return
	}
	for p, lr := range e.RIB[a] {
		var best *Route
		if lr != nil {
			best = lr.Best
		}
		adv := e.Export(a, b, p, best)
		var f *Route
		if adv != nil {
			f = e.Import(b, a, p, adv)
		}
		if routeEqual(e.adj[b][slot][p], f) {
			continue
		}
		e.adj[b][slot][p] = f
		e.dirty[key(b, p)] = struct{}{}
	}
}

func (e *Engine) clearSession(a, b int) {
	slot, ok := e.Net.Routers[a].PeerSlot[b]
	if !ok {
		return
	}
	var touched []int
	for p, rt := range e.adj[a][slot] {
		if rt != nil {
			e.adj[a][slot][p] = nil
			touched = append(touched, p)
		}
	}
	for _, p := range touched {
		e.dirty[key(a, p)] = struct{}{}
		e.record(a, p, &Route{}, nil)
	}
}

// WithdrawOrigin removes a router's announcements for a prefix, as if the
// origin lost the route.  Used by the flap and dampening scenarios.
func (e *Engine) WithdrawOrigin(routerName string, p int) {
	r := e.Net.RouterIndex(routerName)
	if r < 0 {
		return
	}
	key := routerName + "|" + e.Net.PrefixString(p)
	e.withheld[key] = true
	e.dirty[keyOf(r, p)] = struct{}{}
	e.rebuildLocalIndex()
}

// RestoreOrigin undoes WithdrawOrigin.
func (e *Engine) RestoreOrigin(routerName string, p int) {
	r := e.Net.RouterIndex(routerName)
	if r < 0 {
		return
	}
	delete(e.withheld, routerName+"|"+e.Net.PrefixString(p))
	e.dirty[keyOf(r, p)] = struct{}{}
	e.rebuildLocalIndex()
}

func keyOf(r, p int) int64 { return int64(uint64(uint32(r))<<32 | uint64(uint32(p))) }

// rebuildLocalIndex recomputes which announcements are currently live.
func (e *Engine) rebuildLocalIndex() {
	e.localIdx = make([][]int, len(e.Net.Routers))
	for ai, a := range e.Net.Announcements {
		if e.withheld[a.Router+"|"+e.Net.PrefixString(a.PrefixIdx)] {
			continue
		}
		e.localIdx[a.RouterIdx] = append(e.localIdx[a.RouterIdx], ai)
	}
}

// CloneFrom copies the converged state (RIB and Adj-RIB-In) of another engine
// built on the same network.  Scenario runs start from a clone so a fault
// experiment never mutates the baseline.
func (e *Engine) CloneFrom(o *Engine) {
	for r := range e.RIB {
		copy(e.RIB[r], o.RIB[r])
	}
	for r := range e.adj {
		for s := range e.adj[r] {
			copy(e.adj[r][s], o.adj[r][s])
		}
	}
	e.Updates = 0
	e.Changes = nil
	e.round = 0
	e.rebuildLocalIndex()
}

// ---------------------------------------------------------------------------
// Queries
// ---------------------------------------------------------------------------

// Best returns the selected route for (router,prefix).
func (e *Engine) Best(r, p int) *Route {
	if r < 0 || r >= len(e.RIB) || p < 0 || p >= len(e.RIB[r]) {
		return nil
	}
	lr := e.RIB[r][p]
	if lr == nil {
		return nil
	}
	return lr.Best
}

// Decision returns the trace-enabled decision for (router,prefix), or nil when
// the router has no path.  The trace is recomputed on demand: keeping one per
// installed route across a province-scale table would cost far more memory
// than it is worth.
func (e *Engine) Decision(r, p int) *bgp.Decision {
	if r < 0 || r >= len(e.RIB) || p < 0 || p >= len(e.RIB[r]) {
		return nil
	}
	if e.RIB[r][p] == nil {
		return nil
	}
	return e.Explain(r, p)
}

// View is a JSON-friendly route rendering.
type RouteView struct {
	Peer        string   `json:"peer"`
	NextHop     string   `json:"nextHop"`
	Egress      string   `json:"egress"`
	ASPath      string   `json:"asPath"`
	ASLen       int      `json:"asLen"`
	Origin      string   `json:"origin"`
	LocalPref   uint32   `json:"localPref"`
	MED         uint32   `json:"med"`
	Communities []string `json:"communities,omitempty"`
	ClusterList []string `json:"clusterList,omitempty"`
	Originator  string   `json:"originatorId,omitempty"`
	RPKI        string   `json:"rpki"`
	FromEBGP    bool     `json:"fromEBGP"`
	Local       bool     `json:"local,omitempty"`
	IGPCost     int      `json:"igpCost"`
	Blackhole   bool     `json:"blackhole,omitempty"`
}

func ipStr(v uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// View renders a route, resolving indexes to names.
func (e *Engine) View(from int, rt *Route) *RouteView {
	if rt == nil || rt.Attr == nil {
		return nil
	}
	v := &RouteView{
		ASPath:      rt.Attr.ASPathString(),
		ASLen:       rt.Attr.ASLen,
		Origin:      rt.Attr.Origin.String(),
		LocalPref:   rt.Attr.LocalPref,
		MED:         rt.Attr.MED,
		Communities: rt.Attr.CommunityStrings(),
		RPKI:        string(rt.Attr.RPKI),
		FromEBGP:    rt.FromEBGP,
		Local:       rt.Local,
		IGPCost:     e.nextHopCost(from, rt),
	}
	for _, c := range rt.Attr.ClusterList {
		v.ClusterList = append(v.ClusterList, ipStr(c))
	}
	if rt.Attr.HasOriginator {
		v.Originator = ipStr(rt.Attr.OriginatorID)
	}
	if rt.Peer >= 0 {
		v.Peer = e.Net.Routers[rt.Peer].Name
	} else {
		v.Peer = "local"
	}
	v.NextHop = e.Net.Routers[rt.NextHop].Name
	v.Egress = e.Net.Routers[rt.Egress].Name
	// An installed route always has a usable next hop (unreachable ones are
	// rejected when candidates are built), so the installed path is never a
	// black hole.  The replay flags the transient case separately.
	return v
}

// RIBEntry is one prefix in a router's Loc-RIB.
type RIBEntry struct {
	Prefix     string        `json:"prefix"`
	Best       *RouteView    `json:"best,omitempty"`
	ECMP       []*RouteView  `json:"ecmp,omitempty"`
	Decision   *bgp.Decision `json:"decision,omitempty"`
	Blackhole  bool          `json:"blackhole"`
	Suppressed bool          `json:"suppressed,omitempty"`
	Round      int           `json:"round,omitempty"`
}

// RouterRIB returns the Loc-RIB of router r, optionally filtered and paginated.
func (e *Engine) RouterRIB(r int, prefixContains string, offset, limit int) ([]RIBEntry, int) {
	if r < 0 || r >= len(e.RIB) {
		return nil, 0
	}
	var all []RIBEntry
	for p, lr := range e.RIB[r] {
		if lr == nil || lr.Best == nil {
			continue
		}
		ps := e.Net.PrefixString(p)
		if prefixContains != "" && !contains(ps, prefixContains) {
			continue
		}
		entry := RIBEntry{Prefix: ps, Best: e.View(r, lr.Best), Round: lr.Round}
		for _, rt := range lr.ECMP {
			entry.ECMP = append(entry.ECMP, e.View(r, rt))
		}
		entry.Blackhole = entry.Best.Blackhole
		entry.Suppressed = e.Damp.Suppressed(r, p)
		all = append(all, entry)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Prefix < all[j].Prefix })
	total := len(all)
	if offset > 0 {
		if offset >= len(all) {
			return nil, total
		}
		all = all[offset:]
	}
	if limit > 0 && len(all) > limit {
		all = all[:limit]
	}
	return all, total
}

func contains(s, sub string) bool {
	return len(sub) == 0 || len(s) >= len(sub) && indexOf(s, sub) >= 0
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// AdjAt exposes an Adj-RIB-In entry for tests and the replay view.
func (e *Engine) AdjAt(r, slot, p int) *Route { return e.adj[r][slot][p] }
