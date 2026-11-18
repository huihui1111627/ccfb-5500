package engine

import (
	"sort"

	"github.com/edu-net/bgpsim/internal/bgpsim"
)

// detectProblems 在收敛后做全网检查：统计路由环与黑洞。
//
// 路由环：沿每台路由器对某前缀的 IGP 下一跳逐跳追踪，若在到达对该前缀
// 执行 eBGP 转发的边缘路由器之前重复访问某台路由器，则存在转发环路。
//
// 黑洞：某台本地路由器有该前缀的 BGP 路由，但 BGP 下一跳 IGP 不可达
// （IGPNextHop 为空），流量到此无处可送。
func (e *Engine) detectProblems() {
	e.stats.LoopsDetected = 0
	e.stats.Blackholes = 0

	// 收集全部出现过的前缀。
	prefixSet := map[string]bool{}
	for nodeID, rib := range e.ribs {
		if e.nodes[nodeID].ASN != e.localAS || !e.nodes[nodeID].Up {
			continue
		}
		for p, res := range rib.best {
			if res != nil && res.Primary != nil {
				prefixSet[p] = true
			}
		}
	}
	prefixes := make([]string, 0, len(prefixSet))
	for p := range prefixSet {
		prefixes = append(prefixes, p)
	}
	sort.Strings(prefixes)

	for _, prefix := range prefixes {
		for nodeID := range e.ribs {
			n := e.nodes[nodeID]
			if n.ASN != e.localAS || !n.Up {
				continue
			}
			res := e.ribs[nodeID].best[prefix]
			if res == nil || res.Primary == nil {
				continue
			}
			r := res.Primary
			if r.PeerType == bgpsim.PeerEBGP {
				continue // 边缘路由器直接转发给 eBGP 对端，离开本地 AS
			}
			if r.IGPNextHop == "" {
				e.stats.Blackholes++
				continue
			}
			if e.hasForwardingLoop(nodeID, prefix) {
				e.stats.LoopsDetected++
			}
		}
	}
}

// hasForwardingLoop 从 start 起沿 IGP 下一跳追踪指定前缀的转发路径。
func (e *Engine) hasForwardingLoop(start, prefix string) bool {
	seen := map[string]bool{}
	cur := start
	for {
		if seen[cur] {
			return true
		}
		seen[cur] = true
		res := e.ribs[cur].best[prefix]
		if res == nil || res.Primary == nil {
			return false // 路径终止（可能被别处计为黑洞）
		}
		r := res.Primary
		if r.PeerType == bgpsim.PeerEBGP {
			return false // 到达边缘，正常转出本地 AS
		}
		next := r.IGPNextHop
		if next == "" || !e.nodes[next].Up {
			return false // 黑洞场景单独计数，这里不算环
		}
		cur = next
	}
}

// CheckProblems 对外触发一次全网检查并返回统计（网页场景按钮使用）。
func (e *Engine) CheckProblems() Stats {
	e.detectProblems()
	return e.stats
}
