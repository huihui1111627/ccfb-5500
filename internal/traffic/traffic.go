// Package traffic 依据流量矩阵和仿真选路结果，把前缀流量分摊到各上游出口，
// 计算每条上游链路的预计利用率。
package traffic

import (
	"sort"

	"github.com/edu-net/bgpsim/internal/engine"
)

// FlowRecord 是按前缀统计的一条流量矩阵记录（单位：Mbps）。
type FlowRecord struct {
	Prefix string  `json:"prefix"`
	Volume float64 `json:"volume_mbps"`
}

// LinkLoad 是一条上游链路（边缘路由器 <-> 上游对端）的预计负载。
type LinkLoad struct {
	EdgeID      string  `json:"edge_id"`
	UpstreamID  string  `json:"upstream_id"`
	LinkID      string  `json:"link_id,omitempty"`
	LoadMbps    float64 `json:"load_mbps"`
	Capacity    float64 `json:"capacity_mbps"`
	Utilization float64 `json:"utilization"` // 0~1
	Prefixes    int     `json:"prefixes"`
}

// Matrix 是导入的完整流量矩阵。
type Matrix struct {
	// DefaultCapacityMbps 是每条上游链路的额定带宽（统一值，可被 LinkCapacity 覆盖）。
	DefaultCapacityMbps float64            `json:"default_capacity_mbps"`
	LinkCapacity        map[string]float64 `json:"link_capacity_mbps,omitempty"` // key: edgeID|upstreamID
	Flows               []FlowRecord       `json:"flows"`
}

// linkKey 生成链路标识。
func linkKey(edge, upstream string) string { return edge + "|" + upstream }

// Compute 按引擎当前选路结果计算全部上游链路负载与利用率。
// 统计口径：每条前缀的流量在该前缀在本 AS 的全部 ECMP 出口间均摊
// （与五元组哈希在大流上的统计期望一致），不按内部路由器数量重复计算。
func Compute(e *engine.Engine, m *Matrix) []LinkLoad {
	capDefault := m.DefaultCapacityMbps
	if capDefault <= 0 {
		capDefault = 10000
	}
	loads := map[string]*LinkLoad{}
	get := func(edge, upstream, linkID string) *LinkLoad {
		k := linkKey(edge, upstream)
		if l, ok := loads[k]; ok {
			return l
		}
		cap := capDefault
		if c, ok := m.LinkCapacity[k]; ok && c > 0 {
			cap = c
		}
		l := &LinkLoad{EdgeID: edge, UpstreamID: upstream, LinkID: linkID, Capacity: cap}
		loads[k] = l
		return l
	}

	for _, flow := range m.Flows {
		exits := PrefixEgress(e, flow.Prefix)
		if len(exits) == 0 {
			continue
		}
		share := flow.Volume / float64(len(exits))
		for _, eg := range exits {
			l := get(eg.EdgeID, eg.UpstreamID, eg.LinkID)
			l.LoadMbps += share
			l.Prefixes++
		}
	}

	out := make([]LinkLoad, 0, len(loads))
	for _, l := range loads {
		if l.Capacity > 0 {
			l.Utilization = l.LoadMbps / l.Capacity
		}
		out = append(out, *l)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].EdgeID != out[j].EdgeID {
			return out[i].EdgeID < out[j].EdgeID
		}
		return out[i].UpstreamID < out[j].UpstreamID
	})
	return out
}

// Egress 描述一条前缀最终转出本地 AS 的一个出口。
type Egress struct {
	EdgeID     string `json:"edge_id"`
	UpstreamID string `json:"upstream_id"`
	LinkID     string `json:"link_id"`
}

// PrefixEgress 计算一条前缀在本 AS 的全部 eBGP 出口（考虑 ECMP）。
// 口径：逐台检查边缘路由器——只有当该边缘对这条前缀选出的最优路由是
// eBGP 学到的（流量确实在此转出本地 AS），才计为一个出口。
// 不依赖核心/汇聚等中转设备的 RIB：纯 iBGP 反射网络里核心层可能不持有
// 该前缀的 BGP 路由，沿 IGP 下一跳追踪会在核心处中断。
func PrefixEgress(e *engine.Engine, prefix string) []Egress {
	egressSet := map[string]Egress{}
	for _, edgeID := range e.EdgeRouters() {
		detail, ok := e.PrefixDetail(edgeID, prefix)
		if !ok || detail.Winner == "" {
			continue
		}
		// 该边缘的胜出路由必须确实是 eBGP（否则它也是内部中转，不是出口）。
		if !egressFromEBGP(detail, detail.Winner) {
			continue
		}
		// 展开该边缘上这条前缀的全部 eBGP 等价出口（ECMP）。
		for _, src := range ebgpSources(detail) {
			egressSet[linkKey(edgeID, src)] = Egress{
				EdgeID:     edgeID,
				UpstreamID: src,
				LinkID:     findLinkID(e, edgeID, src),
			}
		}
	}
	out := make([]Egress, 0, len(egressSet))
	for _, v := range egressSet {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool {
		return linkKey(out[i].EdgeID, out[i].UpstreamID) < linkKey(out[j].EdgeID, out[j].UpstreamID)
	})
	return out
}

// egressFromEBGP 判断指定来源是否为该前缀的 eBGP 候选。
func egressFromEBGP(detail *engine.PrefixDetail, source string) bool {
	for _, c := range detail.Candidates {
		if c.Source == source && c.PeerType == "eBGP" {
			return true
		}
	}
	return false
}

// ebgpSources 返回选路结果 ECMP 集合中的全部 eBGP 来源；
// 若 ECMP 信息缺失则退化为胜出路由来源。
func ebgpSources(detail *engine.PrefixDetail) []string {
	var out []string
	seen := map[string]bool{}
	srcs := detail.ECMP
	if len(srcs) == 0 {
		srcs = []string{detail.Winner}
	}
	for _, src := range srcs {
		if egressFromEBGP(detail, src) && !seen[src] {
			seen[src] = true
			out = append(out, src)
		}
	}
	if len(out) == 0 && detail.Winner != "" {
		out = []string{detail.Winner}
	}
	sort.Strings(out)
	return out
}

// findLinkID 找两节点间的链路 ID。
func findLinkID(e *engine.Engine, a, b string) string {
	for _, l := range e.Links() {
		if (l.A == a && l.B == b) || (l.A == b && l.B == a) {
			return l.ID
		}
	}
	return ""
}
