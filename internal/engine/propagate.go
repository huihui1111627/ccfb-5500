package engine

import (
	"github.com/edu-net/bgpsim/internal/bgpsim"
)

// propagate 依据 nodeID 上某前缀新旧最优路由的变化，向各 BGP 邻居发出
// 更新或撤回。完整实现 RFC 4456 的反射规则与防环检查。
func (e *Engine) propagate(nodeID, prefix string, old, new *bgpsim.SelectionResult) {
	// 旧路由存在但新结果为空：向所有邻居撤回。
	if new == nil || new.Primary == nil {
		if old != nil && old.Primary != nil {
			e.fanoutWithdraw(nodeID, prefix, old.Primary)
		}
		return
	}
	// 新最优路由：按邻居逐个判断是否应通告。
	for peerID := range e.bgpPeers[nodeID] {
		// 不向外部 AS 泛洪本地选路结果：外部节点只作为路由来源，
		// 否则它们会把路由回注，污染本地 RIB。
		if peer := e.nodes[peerID]; peer != nil && peer.ASN != e.localAS {
			continue
		}
		if !e.sessionUp(nodeID, peerID) {
			continue
		}
		out := e.buildOutgoing(nodeID, peerID, new.Primary)
		if out == nil {
			// 反射防环或水平分割要求不通告；若此前发过，补一条撤回。
			if old != nil && old.Primary != nil {
				e.enqueue(&Message{Type: MsgWithdraw, Prefix: prefix, From: nodeID, To: peerID,
					PeerType: e.peerType(nodeID, peerID)})
			}
			continue
		}
		// 出向策略：在准备发出的副本上执行。
		decision, err := e.compiler.Apply(e.exportMapOf(nodeID), out)
		if err != nil {
			e.stats.PolicyErrors++
			continue
		}
		if !decision.Permit {
			// 出向被 deny：若旧路由曾通告则撤回。
			if old != nil && old.Primary != nil {
				e.enqueue(&Message{Type: MsgWithdraw, Prefix: prefix, From: nodeID, To: peerID,
					PeerType: e.peerType(nodeID, peerID)})
			}
			continue
		}
		e.enqueue(&Message{Type: MsgUpdate, Prefix: prefix, From: nodeID, To: peerID,
			PeerType: e.peerType(nodeID, peerID), Route: out})
	}
}

// fanoutWithdraw 在最优路由消失时向所有仍在线的会话邻居撤回。
func (e *Engine) fanoutWithdraw(nodeID, prefix string, old *bgpsim.Route) {
	for peerID := range e.bgpPeers[nodeID] {
		if !e.sessionUp(nodeID, peerID) {
			continue
		}
		// 反射场景下原本就不会收到该路由的邻居无需撤回。
		if e.isRR(nodeID) && !e.shouldReflect(nodeID, peerID, old) {
			continue
		}
		e.enqueue(&Message{Type: MsgWithdraw, Prefix: prefix, From: nodeID, To: peerID,
			PeerType: e.peerType(nodeID, peerID)})
	}
}

// peerType 判断两个节点之间的会话类型。
func (e *Engine) peerType(a, b string) bgpsim.PeerType {
	if e.nodes[a].ASN != e.nodes[b].ASN {
		return bgpsim.PeerEBGP
	}
	return bgpsim.PeerIBGP
}

// buildOutgoing 按 RFC 4456/4271 生成发给 peerID 的路由副本；
// 返回 nil 表示该邻居不应收到此路由（防环/水平分割）。
func (e *Engine) buildOutgoing(nodeID, peerID string, best *bgpsim.Route) *bgpsim.Route {
	peerKind := e.peerType(nodeID, peerID)
	out := best.Clone()

	if peerKind == bgpsim.PeerEBGP {
		// eBGP 通告：下一跳改为本设备，AS 路径由出向策略负责前置本地 ASN。
		out.NextHop = e.nodes[nodeID].RouterID
		out.IGPNextHop = ""
		out.IGPCost = 0
		// eBGP 对外不携带反射器相关属性。
		out.OriginatorID = ""
		out.ClusterList = nil
		return out
	}

	// iBGP 通告，需要区分普通路由器与反射器。
	if !e.isRR(nodeID) {
		// 普通 iBGP 路由器只把自己本地（eBGP）学到的路由通告给 iBGP 邻居，
		// iBGP 学到的不再转发——经典 iBGP 水平分割。
		if best.PeerType != bgpsim.PeerEBGP {
			return nil
		}
		// next-hop-self：用本设备节点 ID 作为下一跳，内部按 IGP 解析。
		out.NextHop = nodeID
		out.OriginatorID = nodeID
		out.ClusterList = nil
		return out
	}

	// 路由反射器：先做 RFC 4456 防环检查，再决定反射范围。
	if !e.shouldReflect(nodeID, peerID, best) {
		return nil
	}
	// 反射时默认保留原下一跳与原有路径属性；OriginatorID/ClusterList 维护如下：
	if best.PeerType == bgpsim.PeerEBGP {
		// 客户端从 eBGP 学到、RR 第一次反射：以边缘路由器为 Originator。
		if out.OriginatorID == "" {
			out.OriginatorID = best.ReceivedFrom
		}
	} else {
		if out.OriginatorID == "" {
			out.OriginatorID = best.ReceivedFrom
		}
	}
	// RR 把自己的 Cluster-ID（用 RouterID）追加进 Cluster-List。
	clusterID := e.nodes[nodeID].RouterID
	already := false
	for _, c := range out.ClusterList {
		if c == clusterID {
			already = true
		}
	}
	if !already {
		out.ClusterList = append(out.ClusterList, clusterID)
	}
	return out
}

// shouldReflect 实现反射器的接收侧/发送侧防环与客户端/非客户端规则。
func (e *Engine) shouldReflect(rrID, peerID string, r *bgpsim.Route) bool {
	// 接收侧防环（RFC 4456）：
	//  1) OriginatorID 等于本设备 RouterID —— 自己发出的路由绕回来了，丢弃。
	//  2) Cluster-List 中已含本反射器 Cluster-ID —— 环路，丢弃。
	myCluster := e.nodes[rrID].RouterID
	if r.OriginatorID == myCluster {
		e.stats.RRLoopBlocked++
		return false
	}
	for _, c := range r.ClusterList {
		if c == myCluster {
			e.stats.RRLoopBlocked++
			return false
		}
	}
	fromClient := e.rrClients[rrID][r.ReceivedFrom]
	toClient := e.rrClients[rrID][peerID]
	// 发送侧规则（RFC 4456 Section 9）：
	//  - 来自客户端：反射给所有客户端与非客户端
	//  - 来自非客户端：只反射给客户端
	//  - 来自 eBGP：视同来自客户端，反射给全部 iBGP 邻居
	if r.PeerType == bgpsim.PeerEBGP {
		return true
	}
	if fromClient {
		return true
	}
	// 来自非客户端（含其他 RR）：仅能发给本 RR 的客户端。
	return toClient
}
