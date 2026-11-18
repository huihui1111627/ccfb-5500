package engine

import (
	"container/heap"
	"math"

	"github.com/edu-net/bgpsim/internal/bgpsim"
)

// igpItem 是 Dijkstra 优先队列元素。
type igpItem struct {
	node string
	cost int64
	idx  int
}

type igpHeap []*igpItem

func (h igpHeap) Len() int            { return len(h) }
func (h igpHeap) Less(i, j int) bool  { return h[i].cost < h[j].cost }
func (h igpHeap) Swap(i, j int)       { h[i], h[j] = h[j], h[i]; h[i].idx = i; h[j].idx = j }
func (h *igpHeap) Push(x interface{}) { it := x.(*igpItem); it.idx = len(*h); *h = append(*h, it) }
func (h *igpHeap) Pop() interface{} {
	old := *h
	n := len(old)
	it := old[n-1]
	*h = old[:n-1]
	return it
}

// igpShortestPaths 返回 root 的 IGP 最短路径，带按拓扑版本失效的缓存。
// 选路阶段对同一节点的大量路由复用同一份 Dijkstra 结果。
func (e *Engine) igpShortestPaths(root string) (map[string]int64, map[string]string) {
	if c, ok := e.igpCache[root]; ok && int64(e.topoVersion) == c.version {
		return c.dist, c.nextHop
	}
	dist, nextHop := e.computeIGPShortestPaths(root)
	e.igpCache[root] = &igpCacheEntry{
		version: int64(e.topoVersion), dist: dist, nextHop: nextHop,
	}
	return dist, nextHop
}

// invalidateIGPCache 在链路/节点状态变化时清空缓存。
func (e *Engine) invalidateIGPCache() {
	e.topoVersion++
	e.igpCache = map[string]*igpCacheEntry{}
}

// computeIGPShortestPaths 以 root 为源点，在本地 AS 的在线 IGP 链路（IGPCost>0）上
// 跑 Dijkstra，返回每个可达节点的最小开销与第一跳（IGP 下一跳节点 ID）。
// 等开销路径取第一跳节点 ID 最小者，保证仿真结果确定可复现。
func (e *Engine) computeIGPShortestPaths(root string) (dist map[string]int64, nextHop map[string]string) {
	dist = map[string]int64{root: 0}
	nextHop = map[string]string{}
	h := &igpHeap{{node: root, cost: 0}}
	heap.Init(h)

	linkCost := func(l *bgpsim.Link) int64 {
		if l.IGPCost <= 0 {
			return 1 // 防御：未配置开销的内部链路按 1 处理
		}
		return int64(l.IGPCost)
	}

	for h.Len() > 0 {
		cur := heap.Pop(h).(*igpItem)
		if cur.cost > dist[cur.node] {
			continue
		}
		for _, l := range e.adjLinks[cur.node] {
			if !e.linkUp(l) {
				continue
			}
			peer, ok := l.PeerOf(cur.node)
			if !ok || e.nodes[peer].ASN != e.localAS {
				continue // IGP 只在本地 AS 内
			}
			nd := cur.cost + linkCost(l)
			old, known := dist[peer]
			if known && nd > old {
				continue
			}
			// 本节点到达 peer 的第一跳：root 直连时是 peer 本身，否则继承当前节点的第一跳。
			firstHop := peer
			if cur.node != root {
				firstHop = nextHop[cur.node]
			}
			if !known || nd < old {
				dist[peer] = nd
				nextHop[peer] = firstHop
				heap.Push(h, &igpItem{node: peer, cost: nd})
			} else if nd == old && firstHop < nextHop[peer] {
				// 等开销：保留字典序最小的第一跳，纯为确定性。
				nextHop[peer] = firstHop
			}
		}
	}
	return dist, nextHop
}

// igpReachable 判断本地 AS 内两节点当前是否 IGP 连通。
func (e *Engine) igpReachable(a, b string) bool {
	if a == b {
		return true
	}
	dist, _ := e.igpShortestPaths(a)
	_, ok := dist[b]
	return ok
}

// resolveNextHop 为一条在 nodeID 上收到的路由解析 IGP 开销与 IGP 下一跳。
// eBGP 路由的 BGP 下一跳是直连对端：开销取直连链路，下一跳即对端。
// iBGP 路由的下一跳是边缘路由器（next-hop-self），查 IGP 最短路径。
func (e *Engine) resolveNextHop(nodeID string, r *bgpsim.Route) {
	if r.PeerType == bgpsim.PeerEBGP {
		for _, l := range e.adjLinks[nodeID] {
			if peer, ok := l.PeerOf(nodeID); ok && peer == r.ReceivedFrom {
				c := l.IGPCost
				if c <= 0 {
					c = 1
				}
				r.IGPCost = c
				r.IGPNextHop = r.ReceivedFrom
				return
			}
		}
		r.IGPCost = 1
		r.IGPNextHop = r.ReceivedFrom
		return
	}
	// iBGP：NextHop 字段存的是边缘路由器节点 ID（见传播规则 next-hop-self）。
	target := r.NextHop
	dist, nh := e.igpShortestPaths(nodeID)
	if d, ok := dist[target]; ok {
		r.IGPCost = int(d)
		r.IGPNextHop = nh[target]
		return
	}
	// 下一跳不可达：该路由不可用，给一个极大开销并留空 IGP 下一跳，
	// 选路阶段会自然输给可达路由；若全部不可达则形成黑洞并被检查器抓到。
	r.IGPCost = math.MaxInt32
	r.IGPNextHop = ""
}
