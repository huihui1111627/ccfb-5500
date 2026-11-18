package engine

import "sort"

// Stats 汇总一次仿真运行的关键指标。
type Stats struct {
	Rounds           int `json:"rounds"`
	Messages         int `json:"messages"`
	BestPathChanges  int `json:"best_path_changes"`
	PolicyDenied     int `json:"policy_denied"`
	PolicyErrors     int `json:"policy_errors"`
	RPKIInvalid      int `json:"rpki_invalid"`
	RPKIDropped      int `json:"rpki_dropped"`
	RRLoopBlocked    int `json:"rr_loop_blocked"`
	LoopsDetected    int `json:"loops_detected"`
	Blackholes       int `json:"blackholes"`
	ConvergedInRound int `json:"converged_in_round"`
}

// RouteView 是快照中单台路由器单条前缀的选路视图。
type RouteView struct {
	Prefix         string   `json:"prefix"`
	PrimaryFrom    string   `json:"primary_from"`
	PrimaryNextHop string   `json:"primary_next_hop"`
	IGPNextHop     string   `json:"igp_next_hop"`
	IGPCost        int      `json:"igp_cost"`
	ECMPFrom       []string `json:"ecmp_from,omitempty"`
	LocalPref      uint32   `json:"local_pref"`
	ASPath         []uint32 `json:"as_path"`
	Origin         string   `json:"origin"`
	MED            uint32   `json:"med"`
	RPKI           string   `json:"rpki"`
	Suppressed     bool     `json:"suppressed"`
}

// RouterSnapshot 是一台路由器在某一轮的 RIB 视图。
type RouterSnapshot struct {
	NodeID string      `json:"node_id"`
	Up     bool        `json:"up"`
	Routes []RouteView `json:"routes"`
}

// Snapshot 是一轮结束时的全网状态，用于逐轮回放。
type Snapshot struct {
	Round   int              `json:"round"`
	TimeSec float64          `json:"time_sec"`
	Routers []RouterSnapshot `json:"routers"`
	// UpLinks 记录本时刻各链路在线状态，供回放还原断链。
	UpLinks map[string]bool `json:"up_links"`
	Stats   Stats           `json:"stats"`
	// Dampened 记录本路由翻动抑制状态。
	Dampened []dampingSnapshot `json:"dampened,omitempty"`
}

type dampingSnapshot struct {
	NodeID     string  `json:"node_id"`
	Key        string  `json:"key"`
	Penalty    float64 `json:"penalty"`
	Suppressed bool    `json:"suppressed"`
}

// ensureInjected 幂等地注入全部外部路由。
func (e *Engine) ensureInjected() error {
	if e.externalInjected {
		return nil
	}
	if err := e.InjectExternal(); err != nil {
		return err
	}
	e.externalInjected = true
	return nil
}

// Run 从初始外部路由开始跑到收敛（队列清空）或达到 maxRounds 上限。
// maxRounds<=0 时使用一个足够大的保护性上限。
func (e *Engine) Run(maxRounds int) (*Stats, error) {
	if err := e.ensureInjected(); err != nil {
		return nil, err
	}
	if maxRounds <= 0 {
		maxRounds = 200
	}
	for e.round < maxRounds {
		processed := e.step()
		e.snapshot()
		if processed == 0 && len(e.queue) == 0 {
			e.stats.ConvergedInRound = e.round
			break
		}
	}
	e.detectProblems()
	e.stats.Rounds = e.round
	return &e.stats, nil
}

// step 执行一个仿真轮：派发当前队列中的全部消息，再统一重算受影响路由器。
// 返回本轮处理的消息数。
func (e *Engine) step() int {
	e.round++
	e.now += e.cfg.TimeStepSec
	msgs := e.queue
	e.queue = nil
	// 稳定化消息顺序：同轮内按 (to, from, prefix, type) 排序，保证可复现。
	sort.SliceStable(msgs, func(i, j int) bool { return msgLess(msgs[i], msgs[j]) })

	affected := map[string]bool{}
	for _, m := range msgs {
		// 外部 AS 节点只作为路由来源/终点，不运行本地 AS 的选路与传播。
		if to := e.nodes[m.To]; to != nil && to.ASN != e.localAS {
			continue
		}
		// 撤回用于拆除失效路由：即使会话已因故障断开，也必须在本端生效，
		// 否则旧路由会残留成黑洞。更新消息则要求会话仍然在线。
		if m.Type == MsgUpdate && !e.sessionUp(m.From, m.To) {
			continue
		}
		e.stats.Messages++
		switch m.Type {
		case MsgUpdate:
			if e.receiveUpdate(m.To, m) {
				affected[m.To] = true
			}
		case MsgWithdraw:
			e.receiveWithdraw(m.To, m)
			affected[m.To] = true
		}
	}
	// 阻尼时间推进：解除抑制的路由需要让所在路由器重算。
	for nodeID, tracker := range e.dampers {
		for _, key := range tracker.Tick(e.now) {
			e.unsuppress(nodeID, key)
			affected[nodeID] = true
		}
	}
	nodeIDs := make([]string, 0, len(affected))
	for id := range affected {
		nodeIDs = append(nodeIDs, id)
	}
	sort.Strings(nodeIDs)
	for _, id := range nodeIDs {
		e.recompute(id)
	}
	return len(msgs)
}

// unsuppress 在阻尼释放后把对应路由的 Suppressed 标志清掉。
func (e *Engine) unsuppress(nodeID, key string) {
	rib := e.ribs[nodeID]
	for prefix, bySrc := range rib.in {
		for src, r := range bySrc {
			if dampingKey(prefix, src) == key {
				r.Suppressed = false
				r.Penalty = 0
				rib.dirty[prefix] = true
			}
		}
	}
}

// msgLess 定义同轮消息的确定性顺序。
func msgLess(a, b *Message) bool {
	if a.To != b.To {
		return a.To < b.To
	}
	if a.From != b.From {
		return a.From < b.From
	}
	if a.Prefix != b.Prefix {
		return a.Prefix < b.Prefix
	}
	return a.Type < b.Type
}

// snapshot 抓取当前全网 RIB 快照。
func (e *Engine) snapshot() {
	if !e.snapshotsEnabled {
		return
	}
	snap := &Snapshot{Round: e.round, TimeSec: e.now, Stats: e.stats, UpLinks: map[string]bool{}}
	for _, l := range e.links {
		snap.UpLinks[l.ID] = l.Up
	}
	nodeIDs := make([]string, 0, len(e.nodes))
	for id := range e.nodes {
		nodeIDs = append(nodeIDs, id)
	}
	sort.Strings(nodeIDs)
	for _, id := range nodeIDs {
		n := e.nodes[id]
		rs := RouterSnapshot{NodeID: id, Up: n.Up}
		if n.Up && n.ASN == e.localAS {
			rs.Routes = e.routerViews(id)
		}
		snap.Routers = append(snap.Routers, rs)
	}
	for nodeID, tracker := range e.dampers {
		for _, d := range tracker.SnapshotAt(e.now) {
			snap.Dampened = append(snap.Dampened, dampingSnapshot{
				NodeID: nodeID, Key: d.Key, Penalty: d.Penalty, Suppressed: d.Suppressed,
			})
		}
	}
	e.snapshots = append(e.snapshots, snap)
}

// routerViews 导出一台路由器当前全部前缀的选路视图，按前缀排序。
func (e *Engine) routerViews(nodeID string) []RouteView {
	rib := e.ribs[nodeID]
	prefixes := make([]string, 0, len(rib.best))
	for p, res := range rib.best {
		if res != nil && res.Primary != nil {
			prefixes = append(prefixes, p)
		}
	}
	sort.Strings(prefixes)
	views := make([]RouteView, 0, len(prefixes))
	for _, p := range prefixes {
		res := rib.best[p]
		r := res.Primary
		v := RouteView{
			Prefix:         p,
			PrimaryFrom:    r.ReceivedFrom,
			PrimaryNextHop: r.NextHop,
			IGPNextHop:     r.IGPNextHop,
			IGPCost:        r.IGPCost,
			LocalPref:      r.Attrs.LocalPref,
			ASPath:         append([]uint32(nil), r.Attrs.ASPath...),
			Origin:         r.Attrs.Origin.String(),
			MED:            r.Attrs.MED,
			RPKI:           r.RPKI.String(),
			Suppressed:     r.Suppressed,
		}
		for _, ec := range res.ECMP {
			v.ECMPFrom = append(v.ECMPFrom, ec.ReceivedFrom)
		}
		views = append(views, v)
	}
	return views
}

// Snapshots 返回全部历史快照（回放用）。
func (e *Engine) Snapshots() []*Snapshot { return e.snapshots }

// SetSnapshotsEnabled 开关逐轮全量快照。大规模批跑不需要回放时可关闭以降低 GC。
func (e *Engine) SetSnapshotsEnabled(on bool) { e.snapshotsEnabled = on }

// Stats 返回当前统计。
func (e *Engine) Stats() Stats { return e.stats }

// FailLink 把一条链路置为故障，并让两端通过该链路的 BGP 会话撤回路由。
func (e *Engine) FailLink(linkID string) error {
	for _, l := range e.links {
		if l.ID != linkID {
			continue
		}
		l.Up = false
		e.invalidateIGPCache()
		e.tearDownSessions(l.A, l.B)
		return nil
	}
	return errNotFound("link", linkID)
}

// RestoreLink 恢复一条链路。
func (e *Engine) RestoreLink(linkID string) error {
	for _, l := range e.links {
		if l.ID == linkID {
			l.Up = true
			e.invalidateIGPCache()
			e.reEstablishSessions(l.A, l.B)
			return nil
		}
	}
	return errNotFound("link", linkID)
}

// FailRouter 关停一台路由器：下线节点并拆除它的全部 BGP 会话。
func (e *Engine) FailRouter(nodeID string) error {
	n := e.nodes[nodeID]
	if n == nil {
		return errNotFound("node", nodeID)
	}
	n.Up = false
	e.invalidateIGPCache()
	for peerID := range e.bgpPeers[nodeID] {
		e.withdrawAllFrom(nodeID, peerID)
	}
	return nil
}

// RestoreRouter 重新上线一台路由器并重建会话。
func (e *Engine) RestoreRouter(nodeID string) error {
	n := e.nodes[nodeID]
	if n == nil {
		return errNotFound("node", nodeID)
	}
	n.Up = true
	e.invalidateIGPCache()
	for peerID := range e.bgpPeers[nodeID] {
		e.reEstablishSessions(nodeID, peerID)
	}
	return nil
}

// tearDownSessions 处理链路中断导致的会话拆除：双向撤回经该会话学到的路由。
func (e *Engine) tearDownSessions(a, b string) {
	e.withdrawAllFrom(b, a)
	e.withdrawAllFrom(a, b)
}

// withdrawAllFrom 让 receiver 撤掉它从 neighbor 学到的全部前缀。
func (e *Engine) withdrawAllFrom(neighbor, receiver string) {
	rib := e.ribs[receiver]
	if rib == nil {
		return
	}
	for prefix, bySrc := range rib.in {
		if _, ok := bySrc[neighbor]; ok {
			e.enqueue(&Message{Type: MsgWithdraw, Prefix: prefix, From: neighbor, To: receiver,
				PeerType: e.peerType(neighbor, receiver)})
		}
	}
}

// reEstablishSessions 在会话恢复时重新通告双方当前最优路由。
func (e *Engine) reEstablishSessions(a, b string) {
	e.readvertise(a, b)
	e.readvertise(b, a)
}

// readvertise 让 sender 把自己当前全部最优路由重新发给 receiver。
func (e *Engine) readvertise(sender, receiver string) {
	if !e.nodes[sender].Up || !e.nodes[receiver].Up {
		return
	}
	rib := e.ribs[sender]
	prefixes := make([]string, 0, len(rib.best))
	for p, res := range rib.best {
		if res != nil && res.Primary != nil {
			prefixes = append(prefixes, p)
		}
	}
	sort.Strings(prefixes)
	for _, p := range prefixes {
		out := e.buildOutgoing(sender, receiver, rib.best[p].Primary)
		if out == nil {
			continue
		}
		decision, err := e.compiler.Apply(e.exportMapOf(sender), out)
		if err != nil || !decision.Permit {
			continue
		}
		e.enqueue(&Message{Type: MsgUpdate, Prefix: p, From: sender, To: receiver,
			PeerType: e.peerType(sender, receiver), Route: out})
	}
}

// Step 对外暴露单轮执行，供网页“逐轮回放/单步推进”使用。
func (e *Engine) Step() int {
	processed := e.step()
	e.snapshot()
	if processed == 0 && len(e.queue) == 0 {
		e.stats.ConvergedInRound = e.round
	}
	return processed
}

// Pending 返回当前队列里待处理的消息数。
func (e *Engine) Pending() int { return len(e.queue) }

// RunUntilIdle 从当前状态一直跑到队列清空，返回执行的轮数。
func (e *Engine) RunUntilIdle(maxRounds int) (int, error) {
	if err := e.ensureInjected(); err != nil {
		return 0, err
	}
	if maxRounds <= 0 {
		maxRounds = 200
	}
	start := e.round
	for e.round-start < maxRounds {
		processed := e.step()
		e.snapshot()
		if processed == 0 && len(e.queue) == 0 {
			e.stats.ConvergedInRound = e.round
			break
		}
	}
	e.detectProblems()
	e.stats.Rounds = e.round
	return e.round - start, nil
}

type notFoundErr struct{ kind, id string }

func (e *notFoundErr) Error() string    { return e.kind + " not found: " + e.id }
func errNotFound(kind, id string) error { return &notFoundErr{kind, id} }
