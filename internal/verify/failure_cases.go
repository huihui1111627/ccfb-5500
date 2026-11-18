package verify

import (
	"github.com/edu-net/bgpsim/internal/bgpsim"
	"github.com/edu-net/bgpsim/internal/damping"
)

// caseDampingSuppress：直接对阻尼跟踪器制造连续翻动，验证超过抑制阈值后压住，
// 再随半衰期衰减到重用阈值以下释放。
func caseDampingSuppress() Result {
	cfg := damping.Config{
		Reuse: 750, Suppress: 2000, HalfLifeSec: 900,
		FlapPenalty: 1000, MaxSuppressSec: 3600,
	}
	tr := damping.NewTracker(cfg)
	key := "100.0.0.0/24|p1"
	suppressed := false
	// 连续三次翻动（每次 +1000），第三次后惩罚 3000 > 2000，应抑制。
	for i := 0; i < 3; i++ {
		_, suppressed = tr.Flap(key, float64(i+1))
	}
	if !suppressed {
		return Result{Name: "damping_suppress", Pass: false, Detail: "route not suppressed after 3 flaps"}
	}
	// 推进足够长时间（远大于多个半衰期），惩罚应衰减到重用阈值以下并释放。
	released := tr.Tick(900 * 20)
	found := false
	for _, k := range released {
		if k == key {
			found = true
		}
	}
	if !found {
		return Result{Name: "damping_suppress", Pass: false, Detail: "route not released after decay"}
	}
	penalty, stillSuppressed := tr.Penalty(key, 900*20)
	if stillSuppressed || penalty >= cfg.Reuse {
		return Result{Name: "damping_suppress", Pass: false, Detail: "penalty did not decay below reuse"}
	}
	return Result{Name: "damping_suppress", Pass: true, Detail: "suppressed then released by decay"}
}

// caseLinkFailureConvergence：断掉边缘到上游的链路后，流量应切到另一条上游，
// 且全网无环路、无黑洞，并统计收敛轮数。
func caseLinkFailureConvergence() Result {
	h := twoUpstreamHarness()
	h.maxPaths = 1
	h.ext("100.0.0.0/24", "r1", "p1", 100, 0, "igp", []uint32{65100})
	h.ext("100.0.0.0/24", "r1", "p2", 100, 0, "igp", []uint32{65200})
	e, err := h.build()
	if err != nil {
		return Result{Name: "link_failure", Detail: err.Error()}
	}
	if _, err := e.Run(0); err != nil {
		return Result{Name: "link_failure", Detail: err.Error()}
	}
	before := winnerOf(e, "r1", "100.0.0.0/24")

	// 找到 r1-p1 链路并断开。
	var linkID string
	for _, l := range e.Links() {
		if (l.A == "r1" && l.B == "p1") || (l.A == "p1" && l.B == "r1") {
			linkID = l.ID
		}
	}
	if err := e.FailLink(linkID); err != nil {
		return Result{Name: "link_failure", Detail: err.Error()}
	}
	rounds, err := e.RunUntilIdle(0)
	if err != nil {
		return Result{Name: "link_failure", Detail: err.Error()}
	}
	after := winnerOf(e, "r1", "100.0.0.0/24")
	stats := e.CheckProblems()
	if after == "" || after == before {
		return Result{Name: "link_failure", Pass: false,
			Detail: "traffic did not fail over to backup upstream"}
	}
	if stats.LoopsDetected != 0 || stats.Blackholes != 0 {
		return Result{Name: "link_failure", Pass: false,
			Detail: "loop or blackhole after failure"}
	}
	return Result{Name: "link_failure", Pass: true,
		Detail:            "failover completed cleanly",
		ConvergenceRounds: rounds}
}

// caseRouterFailure：关停一台边缘路由器，验证经它的前缀全部切换或撤销，
// 且不产生环路/黑洞。
func caseRouterFailure() Result {
	h := newHarness()
	h.node("r1", h.localAS, bgpsim.RoleEdge)
	h.node("r2", h.localAS, bgpsim.RoleEdge)
	h.node("r3", h.localAS, bgpsim.RoleCore)
	h.node("p1", 65100, bgpsim.RoleExternal)
	h.node("p2", 65200, bgpsim.RoleExternal)
	h.link("r3", "r1", 10)
	h.link("r3", "r2", 10)
	h.link("r1", "p1", 0)
	h.link("r2", "p2", 0)
	h.ext("100.0.0.0/24", "r1", "p1", 100, 0, "igp", []uint32{65100})
	h.ext("100.0.0.0/24", "r2", "p2", 100, 0, "igp", []uint32{65200})
	e, err := h.build()
	if err != nil {
		return Result{Name: "router_failure", Detail: err.Error()}
	}
	if _, err := e.Run(0); err != nil {
		return Result{Name: "router_failure", Detail: err.Error()}
	}
	if err := e.FailRouter("r1"); err != nil {
		return Result{Name: "router_failure", Detail: err.Error()}
	}
	rounds, err := e.RunUntilIdle(0)
	if err != nil {
		return Result{Name: "router_failure", Detail: err.Error()}
	}
	stats := e.CheckProblems()
	// r3 上该前缀应切到 r2 方向。
	views, _ := e.RIB("r3")
	got := ""
	for _, v := range views {
		if v.Prefix == "100.0.0.0/24" {
			got = v.IGPNextHop
		}
	}
	if got != "r2" {
		return Result{Name: "router_failure", Pass: false, Detail: "did not fail over to r2"}
	}
	if stats.LoopsDetected != 0 {
		return Result{Name: "router_failure", Pass: false, Detail: "loop detected"}
	}
	return Result{Name: "router_failure", Pass: true,
		Detail: "r1 down, traffic via r2", ConvergenceRounds: rounds}
}

// caseNoBlackholeOnWithdraw：单上游场景断开后前缀应彻底消失而不是残留黑洞。
func caseNoBlackholeOnWithdraw() Result {
	h := twoUpstreamHarness()
	h.ext("100.0.0.0/24", "r1", "p1", 100, 0, "igp", []uint32{65100})
	e, err := h.build()
	if err != nil {
		return Result{Name: "withdraw_no_blackhole", Detail: err.Error()}
	}
	if _, err := e.Run(0); err != nil {
		return Result{Name: "withdraw_no_blackhole", Detail: err.Error()}
	}
	var linkID string
	for _, l := range e.Links() {
		if (l.A == "r1" && l.B == "p1") || (l.A == "p1" && l.B == "r1") {
			linkID = l.ID
		}
	}
	if err := e.FailLink(linkID); err != nil {
		return Result{Name: "withdraw_no_blackhole", Detail: err.Error()}
	}
	if _, err := e.RunUntilIdle(0); err != nil {
		return Result{Name: "withdraw_no_blackhole", Detail: err.Error()}
	}
	stats := e.CheckProblems()
	if winnerOf(e, "r1", "100.0.0.0/24") != "" {
		return Result{Name: "withdraw_no_blackhole", Pass: false, Detail: "stale route remains"}
	}
	if stats.Blackholes != 0 {
		return Result{Name: "withdraw_no_blackhole", Pass: false, Detail: "blackhole counted"}
	}
	return Result{Name: "withdraw_no_blackhole", Pass: true, Detail: "clean withdrawal"}
}
