// Package gen 生成大规模仿真场景：分层校园网拓扑、三家上游运营商、
// 数万条外部前缀、ROA 与按前缀的流量矩阵。
package gen

import (
	"fmt"
	"math/rand"
	"sort"

	"github.com/edu-net/bgpsim/internal/bgpsim"
	"github.com/edu-net/bgpsim/internal/damping"
	"github.com/edu-net/bgpsim/internal/engine"
	"github.com/edu-net/bgpsim/internal/policy"
	"github.com/edu-net/bgpsim/internal/rpki"
	"github.com/edu-net/bgpsim/internal/traffic"
)

// Params 控制生成网络的规模与随机种子。
type Params struct {
	Seed           int64   `json:"seed"`
	LocalAS        uint32  `json:"local_as"`
	CoreCount      int     `json:"core_count"`
	RRCount        int     `json:"rr_count"`
	AggCount       int     `json:"agg_count"`
	EdgeCount      int     `json:"edge_count"`
	CampusesPerAgg int     `json:"campuses_per_agg"` // 每台聚合下挂的校园接入路由器数
	PrefixCount    int     `json:"prefix_count"`
	UpstreamCount  int     `json:"upstream_count"` // 上游运营商数量（需求为 3）
	MaxPaths       int     `json:"max_paths"`
	LinkCapacity   float64 `json:"link_capacity_mbps"`
}

// DefaultParams 返回贴近需求的默认规模。
func DefaultParams() Params {
	return Params{
		Seed:           42,
		LocalAS:        65000,
		CoreCount:      4,
		RRCount:        2,
		AggCount:       6,
		EdgeCount:      3,
		CampusesPerAgg: 5, // 6*5=30 所校园接入路由器，满足“几十所高校”
		PrefixCount:    30000,
		UpstreamCount:  3,
		MaxPaths:       2,
		LinkCapacity:   10000,
	}
}

// Scenario 是一次生成的完整可运行场景。
type Scenario struct {
	Config engine.Config  `json:"config"`
	Matrix traffic.Matrix `json:"matrix"`
}

// Generate 按参数确定性地生成场景。
func Generate(p Params) (*Scenario, error) {
	if p.UpstreamCount <= 0 {
		p.UpstreamCount = 3
	}
	if p.MaxPaths <= 0 {
		p.MaxPaths = 2
	}
	rng := rand.New(rand.NewSource(p.Seed))
	var nodes []*bgpsim.Node
	var links []*bgpsim.Link

	// 全局递增的 RouterID 末段，保证每个节点 ID 唯一且字典序可比较。
	ridCounter := 0
	routerIDs := map[string]string{}
	idToRouterID := func(id string) string {
		if rid, ok := routerIDs[id]; ok {
			return rid
		}
		ridCounter++
		rid := fmt.Sprintf("10.255.0.%d", ridCounter)
		routerIDs[id] = rid
		return rid
	}

	// 布局坐标辅助：分层纵向排列，便于网页直接画。
	addNode := func(id, name string, asn uint32, role bgpsim.NodeRole, x, y float64, rrOf ...string) *bgpsim.Node {
		n := &bgpsim.Node{
			ID: id, Name: name, ASN: asn, Role: role,
			RouterID: idToRouterID(id), X: x, Y: y, Up: true,
			RRClientOf: rrOf,
		}
		nodes = append(nodes, n)
		return n
	}
	linkID := 0
	addLink := func(a, b string, cost int) {
		linkID++
		links = append(links, &bgpsim.Link{
			ID: fmt.Sprintf("L%03d", linkID), A: a, B: b, IGPCost: cost, Up: true,
		})
	}

	// 1) 核心层。
	var cores []string
	for i := 0; i < p.CoreCount; i++ {
		id := fmt.Sprintf("core%d", i+1)
		addNode(id, fmt.Sprintf("核心-%d", i+1), p.LocalAS, bgpsim.RoleCore,
			float64(i)*220+80, 80)
		cores = append(cores, id)
	}
	// 核心全互联。
	for i := 0; i < len(cores); i++ {
		for j := i + 1; j < len(cores); j++ {
			addLink(cores[i], cores[j], 5)
		}
	}

	// 2) 路由反射器（与核心合置或独立）。
	var rrs []string
	for i := 0; i < p.RRCount; i++ {
		id := fmt.Sprintf("rr%d", i+1)
		addNode(id, fmt.Sprintf("反射器-%d", i+1), p.LocalAS, bgpsim.RoleRR,
			float64(i)*300+150, 220)
		rrs = append(rrs, id)
		addLink(id, cores[i%len(cores)], 3)
	}
	// RR 之间通过核心连通（iBGP 全互联由引擎推导）。

	// 3) 聚合层，双归属到两台核心，并作为 RR 客户端。
	var aggs []string
	for i := 0; i < p.AggCount; i++ {
		id := fmt.Sprintf("agg%d", i+1)
		rr := rrs[i%len(rrs)]
		addNode(id, fmt.Sprintf("汇聚-%d", i+1), p.LocalAS, bgpsim.RoleAgg,
			float64(i)*150+60, 380, rr)
		aggs = append(aggs, id)
		addLink(id, cores[i%len(cores)], 10)
		addLink(id, cores[(i+1)%len(cores)], 10)
	}

	// 4) 校园接入层：每台聚合下挂若干高校路由器。
	var campuses []string
	campusIdx := 0
	for ai, agg := range aggs {
		for c := 0; c < p.CampusesPerAgg; c++ {
			campusIdx++
			id := fmt.Sprintf("campus%d", campusIdx)
			rr := rrs[ai%len(rrs)]
			addNode(id, fmt.Sprintf("高校-%02d", campusIdx), p.LocalAS, bgpsim.RoleAgg,
				float64(c)*120+40+float64(ai)*20, 540+float64(c%2)*40, rr)
			campuses = append(campuses, id)
			addLink(id, agg, 20)
		}
	}

	// 5) 边缘路由器：双归属核心，作为 RR 客户端。
	var edges []string
	for i := 0; i < p.EdgeCount; i++ {
		id := fmt.Sprintf("edge%d", i+1)
		rr := rrs[i%len(rrs)]
		addNode(id, fmt.Sprintf("出口-%d", i+1), p.LocalAS, bgpsim.RoleEdge,
			float64(i)*260+120, 700, rr)
		edges = append(edges, id)
		addLink(id, cores[i%len(cores)], 8)
		addLink(id, cores[(i+1)%len(cores)], 8)
	}

	// 6) 三家上游运营商外部节点，每个边缘都与三家对接（全交叉）。
	var upstreams []string
	upASBase := uint32(65100)
	for u := 0; u < p.UpstreamCount; u++ {
		id := fmt.Sprintf("isp%d", u+1)
		addNode(id, fmt.Sprintf("运营商-%d", u+1), upASBase+uint32(u),
			bgpsim.RoleExternal, float64(u)*260+120, 860)
		upstreams = append(upstreams, id)
	}
	for _, edge := range edges {
		for _, isp := range upstreams {
			addLink(edge, isp, 0) // eBGP 链路，IGPCost=0
		}
	}

	// 7) 外部前缀：在各边缘 x 上游对接处注入，前缀来源 AS 分散。
	var external []bgpsim.ExternalRoute
	var roas []bgpsim.ROA
	flowMap := map[string]float64{}
	linkCaps := map[string]float64{}
	for _, edge := range edges {
		for _, isp := range upstreams {
			k := edge + "|" + isp
			linkCaps[k] = p.LinkCapacity
		}
	}
	// 把前缀均匀分到 9 个边缘×上游组合，每个前缀至少在两条上行有路径，
	// 以便演示最优选择与 ECMP。
	for i := 0; i < p.PrefixCount; i++ {
		prefix := fmt.Sprintf("203.0.%d.%d/32", (i/254)%254, (i%254)+1)
		if i >= 254*254 {
			// 超出第三段容量后切到 198.18 段，保证仍为合法 IPv4。
			prefix = fmt.Sprintf("198.18.%d.%d/32", (i/254)%254, (i%254)+1)
		}
		originAS := upASBase + uint32(rng.Intn(p.UpstreamCount))
		// 该前缀出现在 2~3 个上游上，经不同边缘学到，形成多候选。
		upCount := 2 + rng.Intn(2)
		chosenISPs := rng.Perm(p.UpstreamCount)
		for j := 0; j < upCount && j < len(chosenISPs); j++ {
			isp := upstreams[chosenISPs[j]]
			// 每个上游经一个边缘注入（轮转选择边缘）。
			edge := edges[(i+j)%len(edges)]
			med := uint32(10 + rng.Intn(90))
			lp := uint32(bgpsim.DefaultLocalPref)
			external = append(external, bgpsim.ExternalRoute{
				Prefix:    prefix,
				RouterID:  edge,
				PeerID:    isp,
				NextHop:   idToRouterID(isp),
				LocalPref: lp,
				MED:       med,
				Origin:    "igp",
				ASPath:    []uint32{originAS},
			})
		}
		// 约 95% 的前缀有合法 ROA；少量无 ROA（notfound）；再注入少量坏 ROA 制造 invalid。
		switch {
		case i%50 == 0:
			// 故意给错误起源 ASN，制造 RPKI invalid。
			roas = append(roas, bgpsim.ROA{ASN: originAS + 100, Prefix: prefix, MaxLen: 32})
		case i%10 != 0:
			roas = append(roas, bgpsim.ROA{ASN: originAS, Prefix: prefix, MaxLen: 32})
		}
		// 流量矩阵：对数正态式的重尾分布，制造热点链路。
		base := rng.Float64() * rng.Float64() * 500
		flowMap[prefix] = base + 1
	}

	// 排序保证输出确定。
	sort.Slice(external, func(i, j int) bool {
		if external[i].Prefix != external[j].Prefix {
			return external[i].Prefix < external[j].Prefix
		}
		return external[i].RouterID < external[j].RouterID
	})

	var flows []traffic.FlowRecord
	for prefix, vol := range flowMap {
		flows = append(flows, traffic.FlowRecord{Prefix: prefix, Volume: vol})
	}
	sort.Slice(flows, func(i, j int) bool { return flows[i].Prefix < flows[j].Prefix })

	cfg := engine.Config{
		Topology: bgpsim.Topology{
			LocalAS:  p.LocalAS,
			Nodes:    nodes,
			Links:    links,
			External: external,
			ROAs:     roas,
		},
		Policies: policy.PolicySet{},
		Selection: bgpsim.SelectionOptions{
			MaxPaths: p.MaxPaths,
		},
		RPKIAction:  rpki.InvalidDowngrade,
		Damping:     damping.DefaultConfig(),
		TimeStepSec: 1,
	}
	matrix := traffic.Matrix{
		DefaultCapacityMbps: p.LinkCapacity,
		LinkCapacity:        linkCaps,
		Flows:               flows,
	}
	return &Scenario{Config: cfg, Matrix: matrix}, nil
}
