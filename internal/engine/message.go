package engine

import (
	"fmt"
	"sort"

	"github.com/edu-net/bgpsim/internal/bgpsim"
	"github.com/edu-net/bgpsim/internal/rpki"
)

// MsgType 区分路由更新与撤回。
type MsgType uint8

const (
	MsgUpdate MsgType = iota
	MsgWithdraw
)

// Message 是两个 BGP 邻居之间传递的一条更新或撤回。
type Message struct {
	Type     MsgType
	Prefix   string
	From     string // 发送方节点 ID
	To       string // 接收方节点 ID
	PeerType bgpsim.PeerType
	Route    *bgpsim.Route // update 时携带，withdraw 时为 nil
}

func (m *Message) String() string {
	verb := "UPDATE"
	if m.Type == MsgWithdraw {
		verb = "WITHDRAW"
	}
	return fmt.Sprintf("%s %s %s->%s", verb, m.Prefix, m.From, m.To)
}

// enqueue 把消息放进当前轮的待处理队列。
func (e *Engine) enqueue(m *Message) { e.queue = append(e.queue, m) }

// InjectExternal 把外部路由在对应边缘路由器上作为 eBGP 学到的路由注入。
func (e *Engine) InjectExternal() error {
	for _, ext := range e.cfg.Topology.External {
		edge := e.nodes[ext.RouterID]
		if edge == nil || edge.ASN != e.localAS {
			return fmt.Errorf("external route for %q references unknown local router %q",
				ext.Prefix, ext.RouterID)
		}
		origin, err := bgpsim.ParseOrigin(ext.Origin)
		if err != nil {
			return err
		}
		lp := ext.LocalPref
		if lp == 0 {
			lp = bgpsim.DefaultLocalPref
		}
		r := &bgpsim.Route{
			Prefix:       ext.Prefix,
			ReceivedFrom: ext.PeerID,
			NextHop:      ext.NextHop,
			PeerType:     bgpsim.PeerEBGP,
			RPKI:         bgpsim.RPKINone,
			Attrs: bgpsim.Attributes{
				LocalPref:   lp,
				MED:         ext.MED,
				Origin:      origin,
				ASPath:      append([]uint32(nil), ext.ASPath...),
				Communities: append([]uint32(nil), ext.Communities...),
			},
		}
		e.enqueue(&Message{
			Type:     MsgUpdate,
			Prefix:   ext.Prefix,
			From:     ext.PeerID,
			To:       ext.RouterID,
			PeerType: bgpsim.PeerEBGP,
			Route:    r,
		})
	}
	return nil
}

// receiveUpdate 处理一台路由器收到的更新：入向策略、RPKI、阻尼、写入 Adj-RIB-In。
// 返回 false 表示该路由被策略/RPKI 丢弃（不写 RIB）。
func (e *Engine) receiveUpdate(nodeID string, msg *Message) bool {
	r := msg.Route.Clone()
	r.PeerType = msg.PeerType
	r.ReceivedFrom = msg.From

	// eBGP 水平分割：收到的 AS 路径里若已含本地 AS 号，说明是环路，丢弃。
	if msg.PeerType == bgpsim.PeerEBGP {
		for _, asn := range r.Attrs.ASPath {
			if asn == e.localAS {
				e.stats.RRLoopBlocked++
				return false
			}
		}
	}

	// 入向路由策略。
	decision, err := e.compiler.Apply(e.importMapOf(nodeID), r)
	if err != nil {
		e.stats.PolicyErrors++
		return false
	}
	if !decision.Permit {
		e.stats.PolicyDenied++
		return false
	}

	// RPKI 起源校验（只在本地 AS 边界做一次，结果随路由传播）。
	if r.RPKI == bgpsim.RPKINone && msg.PeerType == bgpsim.PeerEBGP {
		originAS := uint32(0)
		if len(r.Attrs.ASPath) > 0 {
			originAS = r.Attrs.ASPath[len(r.Attrs.ASPath)-1]
		}
		state, err := e.rpki.Validate(r.Prefix, originAS)
		if err == nil {
			r.RPKI = state
		}
		if state == bgpsim.RPKIInvalid {
			e.stats.RPKIInvalid++
			if e.cfg.RPKIAction == rpki.InvalidDrop {
				e.stats.RPKIDropped++
				return false
			}
			// 降级：压到极低本地优先级，让合法路径胜出。
			r.Attrs.LocalPref = rpki.InvalidLocalPref
		}
	}

	// 阻尼：收到更新先查该来源当前状态。
	key := dampingKey(r.Prefix, r.ReceivedFrom)
	tracker := e.dampers[nodeID]
	if tracker != nil {
		penalty, suppressed := tracker.Penalty(key, e.now)
		r.Penalty = penalty
		r.Suppressed = suppressed
	}

	// 下一跳解析。
	e.resolveNextHop(nodeID, r)

	rib := e.ribs[nodeID]
	if rib.in[r.Prefix] == nil {
		rib.in[r.Prefix] = map[string]*bgpsim.Route{}
	}
	rib.in[r.Prefix][r.ReceivedFrom] = r
	rib.dirty[r.Prefix] = true
	return true
}

// receiveWithdraw 处理撤回：记一次翻动惩罚，再从 Adj-RIB-In 删除。
func (e *Engine) receiveWithdraw(nodeID string, msg *Message) {
	rib := e.ribs[nodeID]
	bySrc := rib.in[msg.Prefix]
	old := bySrc[msg.From]
	if old == nil {
		return
	}
	if tracker := e.dampers[nodeID]; tracker != nil {
		key := dampingKey(msg.Prefix, msg.From)
		penalty, suppressed := tracker.Flap(key, e.now)
		_ = penalty
		_ = suppressed
	}
	delete(bySrc, msg.From)
	rib.dirty[msg.Prefix] = true
	if len(bySrc) == 0 {
		delete(rib.in, msg.Prefix)
	}
}

// dampingKey 与 damping 包中 routeKey 的拼法保持一致。
func dampingKey(prefix, from string) string {
	return prefix + "|" + from
}

// recompute 只对自上次重算以来发生变化的脏前缀重新做最优选择，
// 并为发生变化的前缀生成向邻居的更新/撤回消息。
func (e *Engine) recompute(nodeID string) {
	rib := e.ribs[nodeID]
	if len(rib.dirty) == 0 {
		return
	}
	prefixes := make([]string, 0, len(rib.dirty))
	for p := range rib.dirty {
		prefixes = append(prefixes, p)
	}
	rib.dirty = map[string]bool{}
	sortStrings(prefixes)

	for _, prefix := range prefixes {
		candidates := rib.usable(prefix)
		var result *bgpsim.SelectionResult
		if len(candidates) > 0 {
			result = bgpsim.SelectBest(prefix, candidates, e.RouterID, e.cfg.Selection)
		}
		old := rib.best[prefix]
		if result == nil {
			delete(rib.best, prefix)
		} else {
			rib.best[prefix] = result
		}
		if !bestChanged(old, result) {
			continue
		}
		e.stats.BestPathChanges++
		e.propagate(nodeID, prefix, old, result)
	}
}

// bestChanged 判断两次选路结果的主路由（或 ECMP 集合）是否不同。
func bestChanged(old, new *bgpsim.SelectionResult) bool {
	oldKey, oldECMP := resultKeys(old)
	newKey, newECMP := resultKeys(new)
	if oldKey != newKey {
		return true
	}
	if len(oldECMP) != len(newECMP) {
		return true
	}
	for i := range oldECMP {
		if oldECMP[i] != newECMP[i] {
			return true
		}
	}
	return false
}

// resultKeys 提取选路结果的主路由 key 与稳定排序后的 ECMP key 列表。
// 无可用路由时主 key 为空串。
func resultKeys(r *bgpsim.SelectionResult) (string, []string) {
	if r == nil || r.Primary == nil {
		return "", nil
	}
	keys := make([]string, 0, len(r.ECMP))
	for _, p := range r.ECMP {
		keys = append(keys, p.Key())
	}
	return r.Primary.Key(), keys
}

func sortStrings(s []string) { sort.Strings(s) }
