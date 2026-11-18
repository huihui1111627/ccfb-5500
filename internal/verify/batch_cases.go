package verify

import (
	"github.com/edu-net/bgpsim/internal/bgpsim"
	"github.com/edu-net/bgpsim/internal/engine"
	"github.com/edu-net/bgpsim/internal/gen"
	"github.com/edu-net/bgpsim/internal/policy"
	"github.com/edu-net/bgpsim/internal/rpki"
)

// BatchReport 汇总一批故障/策略变更场景的结果。
type BatchReport struct {
	Scenarios []BatchScenario `json:"scenarios"`
	// 全部场景均无环、无黑洞时为 true。
	AllClean bool `json:"all_clean"`
}

// BatchScenario 是单个批跑场景的结论。
type BatchScenario struct {
	Name              string `json:"name"`
	ConvergenceRounds int    `json:"convergence_rounds"`
	Loops             int    `json:"loops"`
	Blackholes        int    `json:"blackholes"`
	Pass              bool   `json:"pass"`
	Detail            string `json:"detail"`
}

// batchParams 用较小但带 RR、多边缘、三上游的固定场景做批跑，保证快速确定。
func batchParams() gen.Params {
	p := gen.DefaultParams()
	p.CoreCount = 3
	p.RRCount = 2
	p.AggCount = 3
	p.EdgeCount = 3
	p.CampusesPerAgg = 3
	p.PrefixCount = 800
	return p
}

// RunBatchScenarios 跑一批断链与策略变更场景，逐条检查无环无黑洞并统计收敛轮数。
func RunBatchScenarios() BatchReport {
	report := BatchReport{AllClean: true}
	add := func(s BatchScenario) {
		if !s.Pass || s.Loops != 0 || s.Blackholes != 0 {
			report.AllClean = false
		}
		report.Scenarios = append(report.Scenarios, s)
	}

	// ---- 第一批：逐台边缘路由器故障 ----
	for i := 1; i <= 3; i++ {
		sc, _ := gen.Generate(batchParams())
		e, err := engine.New(sc.Config)
		if err != nil {
			add(BatchScenario{Name: "router-down-edge" + itoa(i), Pass: false, Detail: err.Error()})
			continue
		}
		e.SetSnapshotsEnabled(false)
		if _, err := e.Run(0); err != nil {
			add(BatchScenario{Name: "router-down-edge" + itoa(i), Pass: false, Detail: err.Error()})
			continue
		}
		nodeID := "edge" + itoa(i)
		if err := e.FailRouter(nodeID); err != nil {
			add(BatchScenario{Name: "router-down-" + nodeID, Pass: false, Detail: err.Error()})
			continue
		}
		rounds, err := e.RunUntilIdle(0)
		if err != nil {
			add(BatchScenario{Name: "router-down-" + nodeID, Pass: false, Detail: err.Error()})
			continue
		}
		st := e.CheckProblems()
		add(BatchScenario{
			Name: "router-down-" + nodeID, ConvergenceRounds: rounds,
			Loops: st.LoopsDetected, Blackholes: st.Blackholes,
			Pass:   st.LoopsDetected == 0 && st.Blackholes == 0,
			Detail: "edge router failed over",
		})
	}

	// ---- 第二批：逐条断开边缘到上游的 eBGP 链路 ----
	sc, _ := gen.Generate(batchParams())
	base, _ := engine.New(sc.Config)
	base.SetSnapshotsEnabled(false)
	base.Run(0)
	ebgpLinks := []string{}
	for _, l := range base.Links() {
		// 跨 AS 链路即 eBGP 对接链路。
		if isCrossAS(base, l) {
			ebgpLinks = append(ebgpLinks, l.ID)
		}
	}
	// 限制批跑数量，取前 6 条覆盖三个边缘。
	if len(ebgpLinks) > 6 {
		ebgpLinks = ebgpLinks[:6]
	}
	for idx, linkID := range ebgpLinks {
		s2, _ := gen.Generate(batchParams())
		e, _ := engine.New(s2.Config)
		e.SetSnapshotsEnabled(false)
		e.Run(0)
		if err := e.FailLink(linkID); err != nil {
			add(BatchScenario{Name: "link-down", Pass: false, Detail: err.Error()})
			continue
		}
		rounds, _ := e.RunUntilIdle(0)
		st := e.CheckProblems()
		add(BatchScenario{
			Name: "link-down-" + itoa(idx+1) + "-" + linkID, ConvergenceRounds: rounds,
			Loops: st.LoopsDetected, Blackholes: st.Blackholes,
			Pass:   st.LoopsDetected == 0 && st.Blackholes == 0,
			Detail: "eBGP link withdrawn, traffic failed over",
		})
	}

	// ---- 第三批：策略变更（改本地优先级 / 前置 AS 路径 / deny） ----
	policyVariants := []struct {
		name  string
		build func(cfg *engine.Config)
	}{
		{
			name: "policy-localpref",
			build: func(cfg *engine.Config) {
				lp := uint32(400)
				cfg.Policies.RouteMaps = append(cfg.Policies.RouteMaps, policy.RouteMap{
					Name: "BATCH",
					Entries: []policy.RouteMapEntry{{
						Seq:     10,
						Match:   policy.MatchCondition{ASPathRegex: "_65101_"},
						Actions: []policy.Action{{SetLocalPref: &lp}},
					}, {Seq: 20}},
				})
				cfg.RouterPolicies = append(cfg.RouterPolicies,
					engine.RouterPolicy{NodeID: "edge1", ImportMap: "BATCH"})
			},
		},
		{
			name: "policy-prepend",
			build: func(cfg *engine.Config) {
				cfg.Policies.RouteMaps = append(cfg.Policies.RouteMaps, policy.RouteMap{
					Name: "BATCH",
					Entries: []policy.RouteMapEntry{{
						Seq:     10,
						Match:   policy.MatchCondition{ASPathRegex: "_65102_"},
						Actions: []policy.Action{{PrependASPath: []uint32{65000, 65000, 65000}}},
					}, {Seq: 20}},
				})
				cfg.RouterPolicies = append(cfg.RouterPolicies,
					engine.RouterPolicy{NodeID: "edge2", ImportMap: "BATCH"})
			},
		},
		{
			name: "policy-deny",
			build: func(cfg *engine.Config) {
				cfg.Policies.PrefixLists = append(cfg.Policies.PrefixLists, policy.PrefixList{
					Name: "BATCHPL",
					Entries: []policy.PrefixListEntry{
						{Prefix: "203.0.0.0/10", GE: 32},
					},
				})
				cfg.Policies.RouteMaps = append(cfg.Policies.RouteMaps, policy.RouteMap{
					Name: "BATCH",
					Entries: []policy.RouteMapEntry{
						{Seq: 10, Match: policy.MatchCondition{PrefixLists: []string{"BATCHPL"}},
							Actions: []policy.Action{{Result: "deny"}}},
						{Seq: 20},
					},
				})
				cfg.RouterPolicies = append(cfg.RouterPolicies,
					engine.RouterPolicy{NodeID: "edge1", ImportMap: "BATCH"})
			},
		},
	}
	for _, variant := range policyVariants {
		s3, _ := gen.Generate(batchParams())
		variant.build(&s3.Config)
		e, err := engine.New(s3.Config)
		if err != nil {
			add(BatchScenario{Name: variant.name, Pass: false, Detail: err.Error()})
			continue
		}
		e.SetSnapshotsEnabled(false)
		st, err := e.Run(0)
		if err != nil {
			add(BatchScenario{Name: variant.name, Pass: false, Detail: err.Error()})
			continue
		}
		check := e.CheckProblems()
		pass := check.LoopsDetected == 0 && check.Blackholes == 0
		add(BatchScenario{
			Name: variant.name, ConvergenceRounds: st.ConvergedInRound,
			Loops: check.LoopsDetected, Blackholes: check.Blackholes,
			Pass: pass, Detail: "policy applied and converged",
		})
	}

	return report
}

// isCrossAS 判断链路两端是否属于不同 AS（即 eBGP 链路）。
func isCrossAS(e *engine.Engine, l *bgpsim.Link) bool {
	var aAS, bAS uint32
	for _, n := range e.Nodes() {
		if n.ID == l.A {
			aAS = n.ASN
		}
		if n.ID == l.B {
			bAS = n.ASN
		}
	}
	return aAS != bAS
}

// itoa 避免在热路径外引入 strconv 的轻量整数转字符串。
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var b [20]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		b[pos] = '-'
	}
	return string(b[pos:])
}

var _ = rpki.InvalidDrop
