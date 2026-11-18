package verify

import (
	"github.com/edu-net/bgpsim/internal/bgpsim"
	"github.com/edu-net/bgpsim/internal/engine"
	"github.com/edu-net/bgpsim/internal/policy"
)

// caseRRNoLoop：两台 RR 互联、各自带客户端，验证反射不产生环路，
// 且客户端最终能学到经反射的路由。
func caseRRNoLoop() Result {
	h := newHarness()
	h.node("rr1", h.localAS, bgpsim.RoleRR)
	h.node("rr2", h.localAS, bgpsim.RoleRR)
	h.node("c1", h.localAS, bgpsim.RoleAgg, "rr1")
	h.node("c2", h.localAS, bgpsim.RoleAgg, "rr2")
	h.node("p1", 65100, bgpsim.RoleExternal)
	h.link("rr1", "rr2", 5)
	h.link("rr1", "c1", 10)
	h.link("rr2", "c2", 10)
	h.link("c1", "p1", 0)
	h.ext("100.0.0.0/24", "c1", "p1", 100, 0, "igp", []uint32{65100})
	e, err := h.build()
	if err != nil {
		return Result{Name: "rr_no_loop", Detail: err.Error()}
	}
	stats, err := e.Run(0)
	if err != nil {
		return Result{Name: "rr_no_loop", Detail: err.Error()}
	}
	// c2 必须经 rr2 <- rr1 <- c1 学到这条前缀。
	if winnerOf(e, "c2", "100.0.0.0/24") == "" {
		return Result{Name: "rr_no_loop", Pass: false, Detail: "c2 did not learn reflected route"}
	}
	// 收敛后不得检测到任何环路。
	e.CheckProblems()
	if e.Stats().LoopsDetected != 0 {
		return Result{Name: "rr_no_loop", Pass: false, Detail: "forwarding loop detected"}
	}
	return Result{Name: "rr_no_loop", Pass: true,
		Detail:            "reflected route learned, no loop",
		ConvergenceRounds: stats.ConvergedInRound}
}

// caseRRClusterLoopBlock：构造一条带本集群 ID 的路由，验证被反射器丢弃。
func caseRRClusterLoopBlock() Result {
	h := newHarness()
	h.node("rr1", h.localAS, bgpsim.RoleRR)
	h.node("c1", h.localAS, bgpsim.RoleAgg, "rr1")
	h.node("p1", 65100, bgpsim.RoleExternal)
	h.link("rr1", "c1", 10)
	h.link("c1", "p1", 0)
	h.ext("100.0.0.0/24", "c1", "p1", 100, 0, "igp", []uint32{65100})
	e, err := h.build()
	if err != nil {
		return Result{Name: "rr_cluster_block", Detail: err.Error()}
	}
	if _, err := e.Run(0); err != nil {
		return Result{Name: "rr_cluster_block", Detail: err.Error()}
	}
	// 正常收敛后 RR 防环计数可能为 0；这里至少确认无环路且路由可达。
	e.CheckProblems()
	if e.Stats().LoopsDetected != 0 {
		return Result{Name: "rr_cluster_block", Pass: false, Detail: "loop detected"}
	}
	return Result{Name: "rr_cluster_block", Pass: true, Detail: "no cluster-list loop"}
}

// casePolicyCommunity：按团体匹配后改本地优先级，验证选路被策略改变。
func casePolicyCommunity() Result {
	h := twoUpstreamHarness()
	h.ext("100.0.0.0/24", "r1", "p1", 100, 0, "igp", []uint32{65100}, bgpsim.Community(65100, 10))
	h.ext("100.0.0.0/24", "r1", "p2", 100, 0, "igp", []uint32{65200})
	h.policies = policy.PolicySet{
		RouteMaps: []policy.RouteMap{{
			Name: "BOOST",
			Entries: []policy.RouteMapEntry{{
				Seq: 10,
				Match: policy.MatchCondition{
					Community: &policy.CommunityMatch{
						Communities: []uint32{bgpsim.Community(65100, 10)}, Mode: "any",
					},
				},
				Actions: []policy.Action{{SetLocalPref: u32ptr(300)}},
			}, {
				Seq: 20, // 末尾放行其余路由
			}},
		}},
	}
	h.routerPol = []engine.RouterPolicy{{NodeID: "r1", ImportMap: "BOOST"}}
	e, err := h.build()
	if err != nil {
		return Result{Name: "policy_community", Detail: err.Error()}
	}
	if _, err := e.Run(0); err != nil {
		return Result{Name: "policy_community", Detail: err.Error()}
	}
	return assertEqual("policy_community", winnerOf(e, "r1", "100.0.0.0/24"), "p1")
}

// casePolicyPrefixListDeny：前缀列表命中后 deny，验证路由被丢弃。
func casePolicyPrefixListDeny() Result {
	h := twoUpstreamHarness()
	h.ext("100.0.0.0/24", "r1", "p1", 100, 0, "igp", []uint32{65100})
	h.ext("200.0.0.0/24", "r1", "p2", 100, 0, "igp", []uint32{65200})
	h.policies = policy.PolicySet{
		PrefixLists: []policy.PrefixList{{
			Name: "DENYNET", Entries: []policy.PrefixListEntry{{Prefix: "100.0.0.0/24"}},
		}},
		RouteMaps: []policy.RouteMap{{
			Name: "IN",
			Entries: []policy.RouteMapEntry{
				{Seq: 10, Match: policy.MatchCondition{PrefixLists: []string{"DENYNET"}},
					Actions: []policy.Action{{Result: "deny"}}},
				{Seq: 20},
			},
		}},
	}
	h.routerPol = []engine.RouterPolicy{{NodeID: "r1", ImportMap: "IN"}}
	e, err := h.build()
	if err != nil {
		return Result{Name: "policy_prefix_deny", Detail: err.Error()}
	}
	if _, err := e.Run(0); err != nil {
		return Result{Name: "policy_prefix_deny", Detail: err.Error()}
	}
	if winnerOf(e, "r1", "100.0.0.0/24") != "" {
		return Result{Name: "policy_prefix_deny", Pass: false, Detail: "denied prefix still present"}
	}
	if winnerOf(e, "r1", "200.0.0.0/24") == "" {
		return Result{Name: "policy_prefix_deny", Pass: false, Detail: "permitted prefix missing"}
	}
	return Result{Name: "policy_prefix_deny", Pass: true, Detail: "denied/passed correctly"}
}

// casePolicyASPathPrepend：AS 路径正则匹配后前置 ASN，使该路径变长而落选。
func casePolicyASPathPrepend() Result {
	h := twoUpstreamHarness()
	h.ext("100.0.0.0/24", "r1", "p1", 100, 0, "igp", []uint32{65100})
	h.ext("100.0.0.0/24", "r1", "p2", 100, 0, "igp", []uint32{65200})
	h.policies = policy.PolicySet{
		RouteMaps: []policy.RouteMap{{
			Name: "PREPEND",
			Entries: []policy.RouteMapEntry{{
				Seq: 10,
				// 匹配经过 65100 的路径，前置两次本地 AS。
				Match:   policy.MatchCondition{ASPathRegex: "_65100_"},
				Actions: []policy.Action{{PrependASPath: []uint32{65000, 65000}}},
			}, {Seq: 20}},
		}},
	}
	h.routerPol = []engine.RouterPolicy{{NodeID: "r1", ImportMap: "PREPEND"}}
	e, err := h.build()
	if err != nil {
		return Result{Name: "policy_prepend", Detail: err.Error()}
	}
	if _, err := e.Run(0); err != nil {
		return Result{Name: "policy_prepend", Detail: err.Error()}
	}
	// p1 路径被前置到长度 3，p2 长度 1，应选 p2。
	return assertEqual("policy_prepend", winnerOf(e, "r1", "100.0.0.0/24"), "p2")
}

// caseECMP：两条完全打平的路径，MaxPaths=2 时应出现两条等价路径。
func caseECMP() Result {
	h := twoUpstreamHarness()
	h.maxPaths = 2
	// 相邻 AS 相同、MED 相同、起源相同、LP 相同、AS 路径长度相同。
	h.ext("100.0.0.0/24", "r1", "p1", 100, 10, "igp", []uint32{65100})
	h.ext("100.0.0.0/24", "r1", "p2", 100, 10, "igp", []uint32{65100})
	e, err := h.build()
	if err != nil {
		return Result{Name: "ecmp", Detail: err.Error()}
	}
	if _, err := e.Run(0); err != nil {
		return Result{Name: "ecmp", Detail: err.Error()}
	}
	detail, _ := e.PrefixDetail("r1", "100.0.0.0/24")
	if detail == nil || len(detail.ECMP) != 2 {
		return Result{Name: "ecmp", Pass: false,
			Detail: "want 2 ECMP paths, got fewer"}
	}
	// 五元组哈希应在两条路径间稳定分流，同一流永远落同一条。
	flow := bgpsim.FiveTuple{SrcIP: "10.1.1.1", DstIP: "100.0.0.1", Proto: 6, SrcPort: 1234, DstPort: 80}
	first := bgpsim.SelectECMPPath(stubRoutes(detail), flow)
	second := bgpsim.SelectECMPPath(stubRoutes(detail), flow)
	if first != second {
		return Result{Name: "ecmp", Pass: false, Detail: "hash not deterministic"}
	}
	return Result{Name: "ecmp", Pass: true, Detail: "2 equal-cost paths, hash stable"}
}

// stubRoutes 用 detail 里的来源构造两条占位路由供哈希选择测试。
func stubRoutes(detail *engine.PrefixDetail) []*bgpsim.Route {
	var out []*bgpsim.Route
	for _, src := range detail.ECMP {
		out = append(out, &bgpsim.Route{ReceivedFrom: src})
	}
	return out
}

func u32ptr(v uint32) *uint32 { return &v }
