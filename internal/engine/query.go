package engine

import (
	"sort"

	"github.com/edu-net/bgpsim/internal/bgpsim"
)

// RIBEntryView 是 Adj-RIB-In 单条候选路由的对外视图。
type RIBEntryView struct {
	Source      string   `json:"source"`
	PeerType    string   `json:"peer_type"`
	NextHop     string   `json:"next_hop"`
	IGPNextHop  string   `json:"igp_next_hop"`
	IGPCost     int      `json:"igp_cost"`
	LocalPref   uint32   `json:"local_pref"`
	MED         uint32   `json:"med"`
	Origin      string   `json:"origin"`
	ASPath      []uint32 `json:"as_path"`
	Communities []uint32 `json:"communities,omitempty"`
	RPKI        string   `json:"rpki"`
	Suppressed  bool     `json:"suppressed"`
	Penalty     float64  `json:"penalty,omitempty"`
}

// PrefixDetail 是某台路由器上某条前缀的完整选路详情。
type PrefixDetail struct {
	Prefix     string               `json:"prefix"`
	Candidates []RIBEntryView       `json:"candidates"`
	Trace      bgpsim.DecisionTrace `json:"trace"`
	Winner     string               `json:"winner"`
	ECMP       []string             `json:"ecmp"`
}

// Nodes 返回全部节点（稳定顺序）。
func (e *Engine) Nodes() []*bgpsim.Node {
	out := append([]*bgpsim.Node(nil), e.cfg.Topology.Nodes...)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Links 返回全部链路。
func (e *Engine) Links() []*bgpsim.Link {
	out := append([]*bgpsim.Link(nil), e.links...)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// LocalAS 返回本地 AS 号。
func (e *Engine) LocalAS() uint32 { return e.localAS }

// RIB 返回某台路由器当前全部前缀的选路视图。
func (e *Engine) RIB(nodeID string) ([]RouteView, bool) {
	rib := e.ribs[nodeID]
	if rib == nil {
		return nil, false
	}
	return e.routerViews(nodeID), true
}

// PrefixDetail 重新对某台路由器某前缀的当前候选跑一遍完整选路，
// 返回带逐级解释的详情（页面“为什么选这条”）。
func (e *Engine) PrefixDetail(nodeID, prefix string) (*PrefixDetail, bool) {
	rib := e.ribs[nodeID]
	if rib == nil {
		return nil, false
	}
	candidates := rib.usable(prefix)
	if len(candidates) == 0 {
		// 即使全部被抑制，也把抑制中的候选带出来用于展示。
		if bySrc := rib.in[prefix]; len(bySrc) > 0 {
			for _, r := range bySrc {
				candidates = append(candidates, r)
			}
		} else {
			return &PrefixDetail{Prefix: prefix}, true
		}
	}
	detail := &PrefixDetail{Prefix: prefix}
	srcs := make([]string, 0, len(candidates))
	seen := map[string]bool{}
	for _, r := range candidates {
		if seen[r.Key()] {
			continue
		}
		seen[r.Key()] = true
		srcs = append(srcs, r.ReceivedFrom)
		detail.Candidates = append(detail.Candidates, RIBEntryView{
			Source:      r.ReceivedFrom,
			PeerType:    r.PeerType.String(),
			NextHop:     r.NextHop,
			IGPNextHop:  r.IGPNextHop,
			IGPCost:     r.IGPCost,
			LocalPref:   r.Attrs.LocalPref,
			MED:         r.Attrs.MED,
			Origin:      r.Attrs.Origin.String(),
			ASPath:      append([]uint32(nil), r.Attrs.ASPath...),
			Communities: append([]uint32(nil), r.Attrs.Communities...),
			RPKI:        r.RPKI.String(),
			Suppressed:  r.Suppressed,
			Penalty:     r.Penalty,
		})
	}
	sort.Slice(detail.Candidates, func(i, j int) bool {
		return detail.Candidates[i].Source < detail.Candidates[j].Source
	})
	// 用未抑制的候选跑选路；全被抑制时结果为空但仍返回各阶段空轨迹。
	usable := make([]*bgpsim.Route, 0, len(candidates))
	for _, r := range candidates {
		if !r.Suppressed {
			usable = append(usable, r)
		}
	}
	if len(usable) > 0 {
		res := bgpsim.SelectBestWithTrace(prefix, usable, e.RouterID, e.cfg.Selection)
		detail.Trace = res.Trace
		if res.Primary != nil {
			detail.Winner = res.Primary.ReceivedFrom
			for _, p := range res.ECMP {
				detail.ECMP = append(detail.ECMP, p.ReceivedFrom)
			}
		}
	}
	return detail, true
}

// AllPrefixes 返回全网出现过的全部前缀（排序），供路由表页过滤。
func (e *Engine) AllPrefixes() []string {
	set := map[string]bool{}
	for _, rib := range e.ribs {
		for p := range rib.in {
			set[p] = true
		}
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// EdgeRouters 返回本地 AS 中拥有 eBGP 会话的边缘路由器。
func (e *Engine) EdgeRouters() []string {
	set := map[string]bool{}
	for id, peers := range e.bgpPeers {
		if e.nodes[id].ASN != e.localAS {
			continue
		}
		for peer := range peers {
			if e.nodes[peer].ASN != e.localAS {
				set[id] = true
				break
			}
		}
	}
	out := make([]string, 0, len(set))
	for id := range set {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// UpstreamPeers 返回某边缘路由器的 eBGP 对端（上游）节点。
func (e *Engine) UpstreamPeers(edgeID string) []string {
	var out []string
	for peer := range e.bgpPeers[edgeID] {
		if e.nodes[peer].ASN != e.localAS {
			out = append(out, peer)
		}
	}
	sort.Strings(out)
	return out
}
