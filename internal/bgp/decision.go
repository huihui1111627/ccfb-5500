package bgp

import (
	"fmt"

	"bgpsim/internal/model"
)

// Candidate is one path under consideration for a prefix at a router.  The
// simulator builds candidates from the Adj-RIB-In; Decide picks the winner and
// records where every other candidate fell out, which is what the UI renders
// as "why this prefix chose this path".
type Candidate struct {
	Attr       *Attr  `json:"attr"`
	From       int    `json:"from"`      // router performing the decision
	IGPTarget  int    `json:"igpTarget"` // router whose IGP distance drives step 7
	Peer       int    `json:"peer"`      // router the route was received from (-1 local)
	NextHop    int    `json:"nextHop"`   // BGP next-hop router
	Egress     int    `json:"egress"`    // router where traffic leaves this AS
	Link       int    `json:"link"`      // egress link (eBGP), -1 for iBGP
	FromEBGP   bool   `json:"fromEBGP"`
	Local      bool   `json:"local"`      // originated by the router itself (weight)
	NeighborAS uint32 `json:"neighborAS"` // adjacent AS, used for MED grouping
	RouterID   uint32 `json:"routerID"`   // advertising router's BGP ID (or ORIGINATOR_ID)
	Source     string `json:"source"`     // human readable origin of the path

	// IGPCost is filled in by Decide.
	IGPCost int `json:"igpCost"`
}

// Decision process steps, in the order they are applied.
const (
	StepWeight = iota
	StepLocalPref
	StepASPathLen
	StepOrigin
	StepMED
	StepEBGP
	StepIGP
	StepRouterID
	StepClusterList
	StepPeerAddr
)

var stepNames = []string{
	"locally originated (weight)",
	"highest local-preference",
	"shortest AS_PATH",
	"lowest ORIGIN type",
	"lowest MED",
	"eBGP over iBGP",
	"lowest IGP metric to next hop",
	"lowest router ID (ORIGINATOR_ID for reflected routes)",
	"shortest CLUSTER_LIST",
	"lowest peer BGP identifier",
}

// StepInfo describes one stage of the decision process.
type StepInfo struct {
	Index  int    `json:"index"`
	Name   string `json:"name"`
	Detail string `json:"detail"`
	Before int    `json:"before"`
	After  int    `json:"after"`
	Ran    bool   `json:"ran"`
}

// CandidateTrace is a candidate plus its fate.
type CandidateTrace struct {
	Index        int      `json:"index"`
	ASPath       string   `json:"asPath"`
	ASLen        int      `json:"asLen"`
	LocalPref    uint32   `json:"localPref"`
	MED          uint32   `json:"med"`
	Origin       string   `json:"origin"`
	RPKI         string   `json:"rpki"`
	Communities  []string `json:"communities,omitempty"`
	ClusterList  []string `json:"clusterList,omitempty"`
	FromEBGP     bool     `json:"fromEBGP"`
	Local        bool     `json:"local"`
	Peer         string   `json:"peer"`
	NextHop      string   `json:"nextHop"`
	Egress       string   `json:"egress"`
	IGPCost      int      `json:"igpCost"`
	RouterID     uint32   `json:"routerID"`
	Source       string   `json:"source"`
	EliminatedAt int      `json:"eliminatedAt"` // -1 winner, -2 ECMP member, >=0 step index
	Reason       string   `json:"reason"`
	Winner       bool     `json:"winner"`
	ECMP         bool     `json:"ecmp"`
	Text         string   `json:"text"`
}

// Decision is the full, replayable result of the decision process.
type Decision struct {
	Candidates []CandidateTrace `json:"candidates"`
	Winner     int              `json:"winner"` // index into Candidates, -1 if none
	ECMP       []int            `json:"ecmp"`   // indexes into Candidates, best first
	Steps      []StepInfo       `json:"steps"`
}

// StepName returns the human name of a decision step index.
func StepName(i int) string {
	if i < 0 || i >= len(stepNames) {
		return "unknown"
	}
	return stepNames[i]
}

// DecisionOptions controls the vendor-ish knobs of the comparison.
type DecisionOptions struct {
	AlwaysCompareMED bool
	Multipath        bool
	ECMPMaxPaths     int
	// Trace enables the per-candidate explanation and step-by-step record.
	// The simulator leaves it off while converging (millions of decisions)
	// and recomputes a traced decision when the UI asks why a prefix was
	// chosen.
	Trace bool
}

type elim struct {
	step int
	why  string
}

// Decide runs the full BGP best-path algorithm over cands.  Every candidate
// must already have passed loop detection and inbound policy.
func Decide(net *model.Network, cands []*Candidate, opts DecisionOptions) *Decision {
	d := &Decision{Winner: -1}
	for _, c := range cands {
		c.IGPCost = net.IGPCost(c.From, c.IGPTarget)
		if c.IGPCost < 0 {
			c.IGPCost = model.INF
		}
	}
	n := len(cands)
	alive := make([]bool, n)
	for i := range alive {
		alive[i] = true
	}
	elims := make([]*elim, n)
	eliminate := func(i, step int, why string) {
		if alive[i] {
			alive[i] = false
			elims[i] = &elim{step: step, why: why}
		}
	}
	count := func() int {
		k := 0
		for _, a := range alive {
			if a {
				k++
			}
		}
		return k
	}
	// Each step keeps only candidates matching the best value according to
	// key.  A step only runs while more than one candidate survives, matching
	// the real decision process (and keeping the trace short).
	step := func(idx int, detail string, key func(*Candidate) int64, format func(best int64) string) {
		if count() <= 1 {
			// A single candidate needs no comparison, but the UI still wants to
			// show that the decision process considered this step, so record
			// the first one as evaluated with no elimination.
			if opts.Trace && idx == 0 {
				d.Steps = append(d.Steps, StepInfo{Index: idx, Name: stepNames[idx],
					Detail: detail, Before: count(), After: count(), Ran: true})
			}
			return
		}
		before := count()
		best, first := int64(0), true
		for i, c := range cands {
			if !alive[i] {
				continue
			}
			k := key(c)
			if first || k < best {
				best, first = k, false
			}
		}
		for i, c := range cands {
			if alive[i] && key(c) > best {
				eliminate(i, idx, format(best))
			}
		}
		if opts.Trace {
			d.Steps = append(d.Steps, StepInfo{Index: idx, Name: stepNames[idx], Detail: detail,
				Before: before, After: count(), Ran: true})
		}
	}

	// 1. Weight: a locally originated route always wins.
	step(StepWeight, "a locally originated route is preferred over any BGP path", func(c *Candidate) int64 {
		if c.Local {
			return 0
		}
		return 1
	}, func(int64) string { return "learned from BGP, a local route exists" })

	// 2. Local preference.
	step(StepLocalPref, "local-preference is absolute; the highest value wins outright", func(c *Candidate) int64 {
		return int64(^uint32(0) - c.Attr.LocalPref)
	}, func(best int64) string {
		return fmt.Sprintf("local-preference is lower than the best (%d)", ^uint32(best))
	})

	// 3. AS_PATH length.
	step(StepASPathLen, "shortest AS_PATH; an AS_SET counts as one hop", func(c *Candidate) int64 {
		return int64(c.Attr.ASLen)
	}, func(best int64) string { return fmt.Sprintf("AS_PATH length > %d", best) })

	// 4. Origin.
	step(StepOrigin, "IGP < EGP < INCOMPLETE", func(c *Candidate) int64 {
		return int64(c.Attr.Origin)
	}, func(best int64) string {
		return fmt.Sprintf("ORIGIN is worse than %s", model.OriginType(best))
	})

	// 5. MED.  Compared only among routes from the same neighbouring AS unless
	// always-compare-med is configured.
	medDetail := "lowest MED, compared only among paths from the same neighbouring AS"
	if opts.AlwaysCompareMED {
		medDetail = "lowest MED compared across all neighbouring ASes (always-compare-med)"
	}
	if count() > 1 {
		before := count()
		if opts.AlwaysCompareMED {
			best, first := uint32(0), true
			for i, c := range cands {
				if !alive[i] {
					continue
				}
				if first || c.Attr.MED < best {
					best, first = c.Attr.MED, false
				}
			}
			for i, c := range cands {
				if alive[i] && c.Attr.MED > best {
					eliminate(i, StepMED, fmt.Sprintf("MED %d > %d", c.Attr.MED, best))
				}
			}
		} else {
			groupMin := map[uint32]uint32{}
			for i, c := range cands {
				if !alive[i] {
					continue
				}
				if m, ok := groupMin[c.NeighborAS]; !ok || c.Attr.MED < m {
					groupMin[c.NeighborAS] = c.Attr.MED
				}
			}
			for i, c := range cands {
				if alive[i] && c.Attr.MED > groupMin[c.NeighborAS] {
					eliminate(i, StepMED, fmt.Sprintf("MED %d > %d from the same neighbouring AS %d",
						c.Attr.MED, groupMin[c.NeighborAS], c.NeighborAS))
				}
			}
		}
		if opts.Trace {
			d.Steps = append(d.Steps, StepInfo{Index: StepMED, Name: stepNames[StepMED], Detail: medDetail,
				Before: before, After: count(), Ran: true})
		}
	}

	// 6. eBGP over iBGP.
	step(StepEBGP, "prefer an eBGP-learned path over an iBGP-learned path", func(c *Candidate) int64 {
		if c.FromEBGP || c.Local {
			return 0
		}
		return 1
	}, func(int64) string { return "iBGP path while an eBGP path exists" })

	// 7. Lowest IGP metric to the next hop.  Survivors after this step form the
	// multipath set; the remaining tie-breaks choose the single best path to
	// advertise but do not remove multipath members.
	step(StepIGP, "lowest IGP metric to the BGP next hop; survivors form the multipath set", func(c *Candidate) int64 {
		return int64(c.IGPCost)
	}, func(best int64) string { return fmt.Sprintf("IGP cost to next hop > %d", best) })

	pool := make([]int, 0, count())
	for i := range cands {
		if alive[i] {
			pool = append(pool, i)
		}
	}
	// mpPool is the multipath set: every path still standing after step 7 is
	// equal up to the IGP metric, so all of them may carry traffic.
	mpPool := append([]int(nil), pool...)

	// Remaining tie-breaks pick the best path to install and advertise.  They
	// are applied to the pool in order; ties at the end are broken by peer ID.
	tie := func(idx int, key func(*Candidate) int64) {
		if len(pool) <= 1 {
			return
		}
		before := len(pool)
		best, first := int64(0), true
		for _, i := range pool {
			if k := key(cands[i]); first || k < best {
				best, first = k, false
			}
		}
		kept := pool[:0]
		for _, i := range pool {
			if key(cands[i]) == best {
				kept = append(kept, i)
			} else {
				eliminate(i, idx, tiebreakReason(idx, cands[i]))
			}
		}
		pool = kept
		if opts.Trace {
			d.Steps = append(d.Steps, StepInfo{Index: idx, Name: stepNames[idx],
				Detail: tieDetail(idx), Before: before, After: len(pool), Ran: true})
		}
	}
	// Step 8 compares the BGP identifier unsigned, so it needs an explicit
	// comparator (int64 would treat IDs above 127.255.255.255 as negative).
	bestOf := func(key func(*Candidate) uint32) {
		if len(pool) <= 1 {
			return
		}
		before := len(pool)
		best := uint32(0)
		for k, i := range pool {
			if v := key(cands[i]); k == 0 || v < best {
				best = v
			}
		}
		kept := pool[:0]
		for _, i := range pool {
			if key(cands[i]) == best {
				kept = append(kept, i)
			} else {
				eliminate(i, StepRouterID, fmt.Sprintf("router ID %s is higher than %s", ipString(key(cands[i])), ipString(best)))
			}
		}
		pool = kept
		if opts.Trace {
			d.Steps = append(d.Steps, StepInfo{Index: StepRouterID, Name: stepNames[StepRouterID],
				Detail: tieDetail(StepRouterID), Before: before, After: len(pool), Ran: true})
		}
	}
	bestOf(func(c *Candidate) uint32 {
		if c.Peer < 0 {
			return net.Routers[c.From].ID
		}
		return c.RouterID
	})
	tie(StepClusterList, func(c *Candidate) int64 { return int64(len(c.Attr.ClusterList)) })
	tie(StepPeerAddr, func(c *Candidate) int64 { return int64(net.Routers[c.Peer].ID) })

	winner := -1
	if len(pool) > 0 {
		winner = pool[0]
	}

	// Build the ECMP group.  The winner always leads the group; other
	// members are the remaining step-7 survivors, capped by ecmpMaxPaths.
	// The cap is applied to the winner race too, so a router never installs
	// more next hops than configured.
	var ecmpSet []int
	if winner >= 0 {
		max := opts.ECMPMaxPaths
		if max <= 0 {
			max = 8
		}
		ecmpSet = append(ecmpSet, winner)
		if opts.Multipath {
			for _, i := range mpPool {
				if i == winner {
					continue
				}
				if len(ecmpSet) >= max {
					break
				}
				ecmpSet = append(ecmpSet, i)
			}
		}
		// Multipath overflow is a note, not an elimination: these paths are
		// usable but the configured group size is smaller.
		for _, i := range mpPool {
			if opts.Multipath && len(ecmpSet) >= max && !containsInt(ecmpSet, i) {
				if elims[i] == nil {
					elims[i] = &elim{step: StepIGP, why: fmt.Sprintf("ECMP group is full (%d paths)", max)}
				}
			}
		}
	}

	d.Winner = winner
	ecmp := map[int]bool{}
	if opts.Multipath && len(ecmpSet) > 1 {
		for _, i := range ecmpSet {
			ecmp[i] = true
		}
	}
	d.ECMP = ecmpSet

	if !opts.Trace {
		return d
	}
	for i, c := range cands {
		tr := CandidateTrace{
			Index:       i,
			ASPath:      c.Attr.ASPathString(),
			ASLen:       c.Attr.ASLen,
			LocalPref:   c.Attr.LocalPref,
			MED:         c.Attr.MED,
			Origin:      c.Attr.Origin.String(),
			RPKI:        string(c.Attr.RPKI),
			Communities: c.Attr.CommunityStrings(),
			FromEBGP:    c.FromEBGP,
			Local:       c.Local,
			Peer:        "local",
			NextHop:     net.Routers[c.NextHop].Name,
			Egress:      net.Routers[c.Egress].Name,
			IGPCost:     c.IGPCost,
			RouterID:    c.RouterID,
			Source:      c.Source,
			Winner:      i == winner,
			ECMP:        ecmp[i],
		}
		for _, cl := range c.Attr.ClusterList {
			tr.ClusterList = append(tr.ClusterList, ipString(cl))
		}
		if c.Peer >= 0 {
			tr.Peer = net.Routers[c.Peer].Name
		}
		if c.IGPCost == model.INF {
			tr.IGPCost = -1
		}
		tr.Text = fmt.Sprintf("LP %d, AS_PATH len %d (%s), %s, MED %d",
			tr.LocalPref, tr.ASLen, pathOrLocal(c.Attr), tr.Origin, tr.MED)
		switch {
		case tr.Winner:
			tr.Reason = "best path"
			tr.EliminatedAt = -1
		case tr.ECMP:
			tr.Reason = "equal-cost multipath member"
			tr.EliminatedAt = -2
		case elims[i] != nil:
			tr.EliminatedAt = elims[i].step
			tr.Reason = elims[i].why
		default:
			tr.EliminatedAt = StepIGP
			tr.Reason = "not selected"
		}
		d.Candidates = append(d.Candidates, tr)
	}
	return d
}

func tieDetail(idx int) string {
	switch idx {
	case StepRouterID:
		return "lowest BGP identifier of the advertising router (ORIGINATOR_ID when present)"
	case StepClusterList:
		return "shortest CLUSTER_LIST (route-reflector loop avoidance)"
	default:
		return "lowest BGP identifier of the peer (last-resort tie-break)"
	}
}

func tiebreakReason(idx int, c *Candidate) string {
	switch idx {
	case StepRouterID:
		return fmt.Sprintf("router ID %s is higher than the best", ipString(c.RouterID))
	case StepClusterList:
		return fmt.Sprintf("CLUSTER_LIST length %d is longer than the best", len(c.Attr.ClusterList))
	default:
		return "peer BGP identifier is higher than the best"
	}
}

func containsInt(s []int, v int) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func pathOrLocal(a *Attr) string {
	if s := a.ASPathString(); s != "" {
		return s
	}
	return "local"
}

func ipString(v uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}
