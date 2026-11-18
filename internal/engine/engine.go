// Package engine 实现事件驱动的逐轮 BGP 仿真：策略处理、RPKI、阻尼、
// 路由反射、故障注入以及收敛过程快照与回放。
package engine

import (
	"fmt"
	"sort"

	"github.com/edu-net/bgpsim/internal/bgpsim"
	"github.com/edu-net/bgpsim/internal/damping"
	"github.com/edu-net/bgpsim/internal/policy"
	"github.com/edu-net/bgpsim/internal/rpki"
)

// RouterPolicy 绑定一台路由器入/出方向的 route-map 名称。
type RouterPolicy struct {
	NodeID    string `json:"node_id"`
	ImportMap string `json:"import_map,omitempty"`
	ExportMap string `json:"export_map,omitempty"`
}

// Config 是一次仿真运行的全部可调参数。
type Config struct {
	Topology       bgpsim.Topology         `json:"topology"`
	Policies       policy.PolicySet        `json:"policies"`
	RouterPolicies []RouterPolicy          `json:"router_policies,omitempty"`
	Selection      bgpsim.SelectionOptions `json:"selection"`
	RPKIAction     rpki.InvalidAction      `json:"rpki_action"`
	Damping        damping.Config          `json:"damping"`
	// TimeStepSec 是每个仿真轮对应的虚拟秒数，驱动阻尼衰减。
	TimeStepSec float64 `json:"time_step_sec"`
}

// ribEntry 是一台路由器 Adj-RIB-In 中按 (前缀, 来源) 保存的路由。
type ribEntry struct {
	route *bgpsim.Route
}

// rib 保存一台路由器全部学到的路由、当前最优选择与决策解释。
type rib struct {
	// in[prefix][sourceNodeID] = 路由
	in map[string]map[string]*bgpsim.Route
	// best[prefix] = 当前 Loc-RIB 最优选择（含 ECMP）
	best map[string]*bgpsim.SelectionResult
	// dirty 记录本路由自上次重算以来发生过增删改、需要重新选路的前缀。
	dirty map[string]bool
}

func newRIB() *rib {
	return &rib{
		in:    map[string]map[string]*bgpsim.Route{},
		best:  map[string]*bgpsim.SelectionResult{},
		dirty: map[string]bool{},
	}
}

// usable 返回某前缀当前未被抑制的全部候选路由，顺序稳定。
func (r *rib) usable(prefix string) []*bgpsim.Route {
	bySrc := r.in[prefix]
	if len(bySrc) == 0 {
		return nil
	}
	srcs := make([]string, 0, len(bySrc))
	for src := range bySrc {
		srcs = append(srcs, src)
	}
	sort.Strings(srcs)
	var out []*bgpsim.Route
	for _, src := range srcs {
		rt := bySrc[src]
		if !rt.Suppressed {
			out = append(out, rt)
		}
	}
	return out
}

// Engine 是仿真运行时。
type Engine struct {
	cfg      Config
	localAS  uint32
	nodes    map[string]*bgpsim.Node
	links    []*bgpsim.Link
	adjLinks map[string][]*bgpsim.Link // nodeID -> 关联链路

	// iBGP/eBGP 会话：bgpPeers[node] 为对端节点 ID 集合。
	bgpPeers map[string]map[string]bool
	// rrClients[rrID] 为该反射器的客户端集合。
	rrClients map[string]map[string]bool
	// rrOf[clientID] 为该客户端所属反射器列表。
	rrOf map[string][]string

	ribs map[string]*rib

	compiler *policy.Compiler
	rpki     *rpki.Validator
	dampers  map[string]*damping.Tracker // 每台路由器一个阻尼跟踪器

	// 轮次与虚拟时钟。
	round int
	now   float64

	// externalInjected 标记外部路由是否已注入，避免 Run/RunUntilIdle 重复注入。
	externalInjected bool

	// 待处理消息队列，一轮内全部派发完再统一重算。
	queue []*Message

	// IGP 最短路径缓存：拓扑不变时，同一节点的 Dijkstra 结果在多轮/多路由间复用。
	topoVersion int
	igpCache    map[string]*igpCacheEntry

	// snapshotsEnabled 为 false 时不保留逐轮全量快照，供大规模批跑降低内存与 GC。
	snapshotsEnabled bool

	// 每轮结束时的全量快照，用于回放。
	snapshots []*Snapshot

	// 统计与告警。
	stats Stats
}

// igpCacheEntry 缓存一个源点的 Dijkstra 结果及其对应的拓扑版本。
type igpCacheEntry struct {
	version int64
	dist    map[string]int64
	nextHop map[string]string
}

// New 构造并初始化引擎：推导 BGP 会话、编译策略、初始化 RIB。
func New(cfg Config) (*Engine, error) {
	if cfg.Selection.MaxPaths == 0 {
		cfg.Selection = bgpsim.DefaultSelectionOptions()
	}
	if cfg.TimeStepSec <= 0 {
		cfg.TimeStepSec = 1
	}
	if cfg.RPKIAction == "" {
		cfg.RPKIAction = rpki.InvalidDrop
	}
	compiler, err := policy.NewCompiler(&cfg.Policies)
	if err != nil {
		return nil, fmt.Errorf("compile policies: %w", err)
	}
	e := &Engine{
		cfg:              cfg,
		localAS:          cfg.Topology.LocalAS,
		nodes:            map[string]*bgpsim.Node{},
		adjLinks:         map[string][]*bgpsim.Link{},
		bgpPeers:         map[string]map[string]bool{},
		rrClients:        map[string]map[string]bool{},
		rrOf:             map[string][]string{},
		ribs:             map[string]*rib{},
		compiler:         compiler,
		rpki:             rpki.NewValidator(cfg.Topology.ROAs),
		dampers:          map[string]*damping.Tracker{},
		igpCache:         map[string]*igpCacheEntry{},
		snapshotsEnabled: true,
	}
	for _, n := range cfg.Topology.Nodes {
		if _, dup := e.nodes[n.ID]; dup {
			return nil, fmt.Errorf("duplicate node id %q", n.ID)
		}
		e.nodes[n.ID] = n
		e.bgpPeers[n.ID] = map[string]bool{}
		e.ribs[n.ID] = newRIB()
		if n.ASN == e.localAS {
			e.dampers[n.ID] = damping.NewTracker(cfg.Damping)
		}
	}
	for _, l := range cfg.Topology.Links {
		if e.nodes[l.A] == nil || e.nodes[l.B] == nil {
			return nil, fmt.Errorf("link %q references unknown node", l.ID)
		}
		e.links = append(e.links, l)
		e.adjLinks[l.A] = append(e.adjLinks[l.A], l)
		e.adjLinks[l.B] = append(e.adjLinks[l.B], l)
	}
	if err := e.buildBGPSessions(); err != nil {
		return nil, err
	}
	return e, nil
}

// buildBGPSessions 依据链路与 RR 客户端关系推导全部 BGP 会话。
func (e *Engine) buildBGPSessions() error {
	// eBGP：跨 AS 链路上的两个节点建立 eBGP 会话。
	for _, l := range e.links {
		na, nb := e.nodes[l.A], e.nodes[l.B]
		if na.ASN != nb.ASN {
			e.bgpPeers[na.ID][nb.ID] = true
			e.bgpPeers[nb.ID][na.ID] = true
		}
	}
	// 收集 RR 客户端关系。
	for _, n := range e.cfg.Topology.Nodes {
		if n.ASN != e.localAS {
			continue
		}
		for _, rrID := range n.RRClientOf {
			rr := e.nodes[rrID]
			if rr == nil {
				return fmt.Errorf("node %q references unknown route reflector %q", n.ID, rrID)
			}
			if e.rrClients[rrID] == nil {
				e.rrClients[rrID] = map[string]bool{}
			}
			e.rrClients[rrID][n.ID] = true
			e.rrOf[n.ID] = append(e.rrOf[n.ID], rrID)
		}
	}
	// iBGP：
	//  - RR 与其全部客户端之间
	//  - RR 之间全互联
	//  - 既不是 RR 也没有 RR 的“普通”节点之间全互联
	var rrs, plain []string
	for id, n := range e.nodes {
		if n.ASN != e.localAS {
			continue
		}
		if _, isRR := e.rrClients[id]; isRR {
			rrs = append(rrs, id)
		} else if len(e.rrOf[id]) == 0 {
			plain = append(plain, id)
		}
	}
	sort.Strings(rrs)
	sort.Strings(plain)
	addSession := func(a, b string) {
		e.bgpPeers[a][b] = true
		e.bgpPeers[b][a] = true
	}
	for _, rr := range rrs {
		for client := range e.rrClients[rr] {
			addSession(rr, client)
		}
	}
	for i := 0; i < len(rrs); i++ {
		for j := i + 1; j < len(rrs); j++ {
			addSession(rrs[i], rrs[j])
		}
	}
	for i := 0; i < len(plain); i++ {
		for j := i + 1; j < len(plain); j++ {
			addSession(plain[i], plain[j])
		}
	}
	return nil
}

// RouterID 对外暴露节点 ID -> RouterID 解析。
func (e *Engine) RouterID(nodeID string) string {
	if n := e.nodes[nodeID]; n != nil {
		return n.RouterID
	}
	return ""
}

// isRR 判断节点是否为路由反射器。
func (e *Engine) isRR(nodeID string) bool {
	_, ok := e.rrClients[nodeID]
	return ok
}

// linkUp 判断链路当前是否可用（两端节点也要在线）。
func (e *Engine) linkUp(l *bgpsim.Link) bool {
	return l.Up && e.nodes[l.A].Up && e.nodes[l.B].Up
}

// nodeReachable 判断两节点间是否存在在线的 BGP 会话路径（用于消息派发）。
// BGP 会话本身依赖链路：eBGP 靠直连链路，iBGP 靠 IGP 连通性。
func (e *Engine) sessionUp(a, b string) bool {
	if !e.nodes[a].Up || !e.nodes[b].Up {
		return false
	}
	na, nb := e.nodes[a], e.nodes[b]
	if na.ASN != nb.ASN {
		// eBGP：必须有一条在线直连链路。
		for _, l := range e.adjLinks[a] {
			if peer, ok := l.PeerOf(a); ok && peer == b && e.linkUp(l) {
				return true
			}
		}
		return false
	}
	// iBGP：两端在 IGP 内仍连通即可（TCP 会话承载于 IGP）。
	return e.igpReachable(a, b)
}

// policyOf 返回某节点入向 route-map 名称。
func (e *Engine) importMapOf(nodeID string) string {
	for _, rp := range e.cfg.RouterPolicies {
		if rp.NodeID == nodeID {
			return rp.ImportMap
		}
	}
	return ""
}

func (e *Engine) exportMapOf(nodeID string) string {
	for _, rp := range e.cfg.RouterPolicies {
		if rp.NodeID == nodeID {
			return rp.ExportMap
		}
	}
	return ""
}
