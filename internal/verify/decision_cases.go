package verify

import (
	"github.com/edu-net/bgpsim/internal/bgpsim"
	"github.com/edu-net/bgpsim/internal/rpki"
)

// twoUpstreamHarness 构造一台边缘路由器 r1，经两条 eBGP 链路连两个上游 p1/p2，
// 同一条前缀 100.0.0.0/24 从两个上游各注入一条，供逐级选路对比。
func twoUpstreamHarness() *harness {
	h := newHarness()
	h.node("r1", h.localAS, bgpsim.RoleEdge)
	h.node("p1", 65100, bgpsim.RoleExternal)
	h.node("p2", 65200, bgpsim.RoleExternal)
	h.link("r1", "p1", 0)
	h.link("r1", "p2", 0)
	return h
}

// DecisionCases 返回按协议顺序手工计算的选路用例。
func DecisionCases() []func() Result {
	return []func() Result{
		caseLocalPref,
		caseASPath,
		caseOrigin,
		caseMED,
		caseEBGPOverIBGP,
		caseIGPCost,
		caseRouterID,
	}
}

// 1. 本地优先级高者胜：p2 给 200，应选 p2。
func caseLocalPref() Result {
	h := twoUpstreamHarness()
	h.ext("100.0.0.0/24", "r1", "p1", 100, 0, "igp", []uint32{65100})
	h.ext("100.0.0.0/24", "r1", "p2", 200, 0, "igp", []uint32{65200})
	e, err := h.build()
	if err != nil {
		return Result{Name: "local_pref", Detail: err.Error()}
	}
	if _, err := e.Run(0); err != nil {
		return Result{Name: "local_pref", Detail: err.Error()}
	}
	r := assertEqual("local_pref", winnerOf(e, "r1", "100.0.0.0/24"), "p2")
	r.ConvergenceRounds = e.Stats().ConvergedInRound
	return r
}

// 2. AS 路径短者胜：本地优先级相同，p1 路径长度 1，p2 长度 3，应选 p1。
func caseASPath() Result {
	h := twoUpstreamHarness()
	h.ext("100.0.0.0/24", "r1", "p1", 100, 0, "igp", []uint32{65100})
	h.ext("100.0.0.0/24", "r1", "p2", 100, 0, "igp", []uint32{65200, 65300, 65400})
	e, err := h.build()
	if err != nil {
		return Result{Name: "as_path", Detail: err.Error()}
	}
	if _, err := e.Run(0); err != nil {
		return Result{Name: "as_path", Detail: err.Error()}
	}
	return assertEqual("as_path", winnerOf(e, "r1", "100.0.0.0/24"), "p1")
}

// 3. 起源类型 IGP 优于 incomplete：前序属性相同，应选 p1。
func caseOrigin() Result {
	h := twoUpstreamHarness()
	h.ext("100.0.0.0/24", "r1", "p1", 100, 0, "igp", []uint32{65100})
	h.ext("100.0.0.0/24", "r1", "p2", 100, 0, "incomplete", []uint32{65200})
	e, err := h.build()
	if err != nil {
		return Result{Name: "origin", Detail: err.Error()}
	}
	if _, err := e.Run(0); err != nil {
		return Result{Name: "origin", Detail: err.Error()}
	}
	return assertEqual("origin", winnerOf(e, "r1", "100.0.0.0/24"), "p1")
}

// 4. MED 低者胜：相邻 AS 相同（都经 AS 65100），MED 10 优于 MED 50。
func caseMED() Result {
	h := twoUpstreamHarness()
	// 让两个上游都用相同相邻 ASN 65100，满足 MED 比较前提。
	h.ext("100.0.0.0/24", "r1", "p1", 100, 10, "igp", []uint32{65100})
	h.ext("100.0.0.0/24", "r1", "p2", 100, 50, "igp", []uint32{65100})
	e, err := h.build()
	if err != nil {
		return Result{Name: "med", Detail: err.Error()}
	}
	if _, err := e.Run(0); err != nil {
		return Result{Name: "med", Detail: err.Error()}
	}
	return assertEqual("med", winnerOf(e, "r1", "100.0.0.0/24"), "p1")
}

// 5. eBGP 优于 iBGP：在内部路由器 r2 上，一条 eBGP、一条 iBGP，其他属性打平。
func caseEBGPOverIBGP() Result {
	h := newHarness()
	h.node("r1", h.localAS, bgpsim.RoleEdge)
	h.node("r2", h.localAS, bgpsim.RoleEdge)
	h.node("p1", 65100, bgpsim.RoleExternal)
	h.link("r1", "r2", 10)
	h.link("r2", "p1", 0)
	// r1 与 r2 普通 iBGP 全互联（无 RR）。
	h.ext("100.0.0.0/24", "r1", "p1", 100, 0, "igp", []uint32{65100})
	// 再让 r2 自己从 p1 收到一条 eBGP，属性完全一致。
	h.ext("100.0.0.0/24", "r2", "p1", 100, 0, "igp", []uint32{65100})
	e, err := h.build()
	if err != nil {
		return Result{Name: "ebgp_over_ibgp", Detail: err.Error()}
	}
	if _, err := e.Run(0); err != nil {
		return Result{Name: "ebgp_over_ibgp", Detail: err.Error()}
	}
	// r2 上：本地 eBGP（来自 p1）应优于从 r1 学到的 iBGP。
	return assertEqual("ebgp_over_ibgp", winnerOf(e, "r2", "100.0.0.0/24"), "p1")
}

// 6. IGP 开销低者胜：r2 从两个上游方向学到 iBGP 路由，下一跳 IGP 开销不同。
func caseIGPCost() Result {
	h := newHarness()
	// r3 是观察点，r1/r2 是两条到上游的边缘，链路开销不同。
	h.node("r1", h.localAS, bgpsim.RoleEdge)
	h.node("r2", h.localAS, bgpsim.RoleEdge)
	h.node("r3", h.localAS, bgpsim.RoleCore)
	h.node("p1", 65100, bgpsim.RoleExternal)
	h.node("p2", 65200, bgpsim.RoleExternal)
	h.link("r3", "r1", 5)  // 近
	h.link("r3", "r2", 50) // 远
	h.link("r1", "p1", 0)
	h.link("r2", "p2", 0)
	// 两条外部路由属性完全打平，仅靠 r3 到下一跳的 IGP 开销区分。
	h.ext("100.0.0.0/24", "r1", "p1", 100, 0, "igp", []uint32{65100})
	h.ext("100.0.0.0/24", "r2", "p2", 100, 0, "igp", []uint32{65100})
	e, err := h.build()
	if err != nil {
		return Result{Name: "igp_cost", Detail: err.Error()}
	}
	if _, err := e.Run(0); err != nil {
		return Result{Name: "igp_cost", Detail: err.Error()}
	}
	// r3 应选 IGP 开销更小的 r1 方向（下一跳 r1）。
	detail, _ := e.PrefixDetail("r3", "100.0.0.0/24")
	if detail == nil || len(detail.Candidates) == 0 {
		return Result{Name: "igp_cost", Pass: false, Detail: "no candidates on r3"}
	}
	// 胜出路由的 IGP 下一跳应是 r1。
	views, _ := e.RIB("r3")
	got := ""
	for _, v := range views {
		if v.Prefix == "100.0.0.0/24" {
			got = v.IGPNextHop
		}
	}
	return assertEqual("igp_cost", got, "r1")
}

// 7. 路由器 ID 小者胜：所有属性与 IGP 开销打平，按宣告者 RouterID 决胜负。
func caseRouterID() Result {
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
	h.ext("100.0.0.0/24", "r2", "p2", 100, 0, "igp", []uint32{65100})
	e, err := h.build()
	if err != nil {
		return Result{Name: "router_id", Detail: err.Error()}
	}
	if _, err := e.Run(0); err != nil {
		return Result{Name: "router_id", Detail: err.Error()}
	}
	// r1 的 RouterID 10.0.0.1 小于 r2 的 10.0.0.2，r3 应选 r1 方向。
	views, _ := e.RIB("r3")
	got := ""
	for _, v := range views {
		if v.Prefix == "100.0.0.0/24" {
			got = v.IGPNextHop
		}
	}
	return assertEqual("router_id", got, "r1")
}

// RPKI invalid 在用 drop 动作时必须被丢弃。
func caseRPKIDrop() Result {
	h := twoUpstreamHarness()
	h.ext("100.0.0.0/24", "r1", "p1", 100, 0, "igp", []uint32{65100})
	// ROA 只授权 65999，实际起源 65100 → invalid。
	h.roas = append(h.roas, bgpsim.ROA{ASN: 65999, Prefix: "100.0.0.0/24", MaxLen: 24})
	h.rpkiAct = rpki.InvalidDrop
	e, err := h.build()
	if err != nil {
		return Result{Name: "rpki_drop", Detail: err.Error()}
	}
	if _, err := e.Run(0); err != nil {
		return Result{Name: "rpki_drop", Detail: err.Error()}
	}
	if winnerOf(e, "r1", "100.0.0.0/24") != "" {
		return Result{Name: "rpki_drop", Pass: false, Detail: "invalid route was not dropped"}
	}
	return Result{Name: "rpki_drop", Pass: true, Detail: "invalid route dropped"}
}

// RPKI invalid 在用 downgrade 动作时保留但本地优先级被压低。
func caseRPKIDowngrade() Result {
	h := twoUpstreamHarness()
	// p1 invalid，p2 valid；降级后 p1 LP=10，p2 保持 100，应选 p2。
	h.ext("100.0.0.0/24", "r1", "p1", 100, 0, "igp", []uint32{65100})
	h.ext("100.0.0.0/24", "r1", "p2", 100, 0, "igp", []uint32{65200})
	h.roas = append(h.roas,
		bgpsim.ROA{ASN: 65999, Prefix: "100.0.0.0/24", MaxLen: 24}, // 让 p1 invalid
		bgpsim.ROA{ASN: 65200, Prefix: "100.0.0.0/24", MaxLen: 24}, // p2 valid
	)
	h.rpkiAct = rpki.InvalidDowngrade
	e, err := h.build()
	if err != nil {
		return Result{Name: "rpki_downgrade", Detail: err.Error()}
	}
	if _, err := e.Run(0); err != nil {
		return Result{Name: "rpki_downgrade", Detail: err.Error()}
	}
	return assertEqual("rpki_downgrade", winnerOf(e, "r1", "100.0.0.0/24"), "p2")
}
