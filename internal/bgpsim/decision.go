package bgpsim

import (
	"fmt"
	"sort"
)

// StageName 列出决策过程各阶段（顺序即 BGP 最优路径选择顺序）。
const (
	StageValid     = "valid"          // 过滤掉抑制、RPKI 丢弃等不可用路由
	StageLocalPref = "local_pref"     // 1. 本地优先级，高者胜
	StageASPath    = "as_path"        // 2. AS 路径长度，短者胜
	StageOrigin    = "origin"         // 3. 起源类型，IGP<EGP<incomplete
	StageMED       = "med"            // 4. MED，低者胜（相邻 AS 相同才比较）
	StageEBGP      = "ebgp_over_ibgp" // 5. eBGP 优于 iBGP
	StageIGPCost   = "igp_cost"       // 6. 到下一跳的 IGP 开销，低者胜
	StageRouterID  = "router_id"      // 7. 宣告者路由器 ID，小者胜
)

// StageTrace 记录一个比较阶段结束后候选集合的变化。
type StageTrace struct {
	Stage      string            `json:"stage"`
	Rule       string            `json:"rule"`
	Surviving  []string          `json:"surviving"`
	Eliminated map[string]string `json:"eliminated"` // key -> 淘汰原因
}

// DecisionTrace 是一条前缀完整的选路解释，供页面展示。
type DecisionTrace struct {
	Prefix     string       `json:"prefix"`
	Stages     []StageTrace `json:"stages"`
	WinnerKey  string       `json:"winner_key"`
	WinnerFrom string       `json:"winner_received_from"`
	ECMPKeys   []string     `json:"ecmp_keys,omitempty"` // 第 6 步后仍打平的等价路径
}

// SelectionOptions 控制选路细节。
type SelectionOptions struct {
	// AlwaysCompareMED 为 true 时忽略“相邻 AS 相同才比 MED”的限制。
	AlwaysCompareMED bool
	// MaxPaths 是等价路径最大条数（1 表示不做 ECMP）。
	MaxPaths int
}

// DefaultSelectionOptions 返回行业惯例默认值。
func DefaultSelectionOptions() SelectionOptions {
	return SelectionOptions{MaxPaths: 1}
}

// SelectionResult 是一次选路的结果。
type SelectionResult struct {
	Primary *Route
	ECMP    []*Route // 含 Primary，按 RouterID 排序后的等价路径（受 MaxPaths 截断）
	Trace   DecisionTrace
}

type candidate struct {
	route *Route
	key   string
	rid   string
}

// SelectBest 按 RFC 4271 + 厂商惯例的完整顺序选出最优路由（不构建决策轨迹，
// 零额外 map/slice 分配，供引擎在大规模运行期使用）。
func SelectBest(prefix string, routes []*Route, routerIDOf func(nodeID string) string,
	opts SelectionOptions) *SelectionResult {
	return selectBest(prefix, routes, routerIDOf, opts, false)
}

// SelectBestWithTrace 与 SelectBest 规则完全一致，但额外构建逐级决策解释，
// 供页面“为什么选这条”按需调用。
func SelectBestWithTrace(prefix string, routes []*Route, routerIDOf func(nodeID string) string,
	opts SelectionOptions) *SelectionResult {
	return selectBest(prefix, routes, routerIDOf, opts, true)
}

func selectBest(prefix string, routes []*Route, routerIDOf func(nodeID string) string,
	opts SelectionOptions, withTrace bool) *SelectionResult {

	var trace DecisionTrace
	if withTrace {
		trace = DecisionTrace{Prefix: prefix}
	}
	addStage := func(stage, rule string, kept []candidate, dropped map[string]string) {
		if !withTrace {
			return
		}
		t := StageTrace{Stage: stage, Rule: rule, Eliminated: dropped}
		for _, c := range kept {
			t.Surviving = append(t.Surviving, c.key)
		}
		trace.Stages = append(trace.Stages, t)
	}

	// 阶段 0：只保留可用路由。
	var live []candidate
	var filtered map[string]string
	if withTrace {
		filtered = map[string]string{}
	}
	for _, r := range routes {
		if r.Suppressed {
			if withTrace {
				filtered[r.Key()] = "route flap damping suppressed"
			}
			continue
		}
		rid := routerIDOf(r.ReceivedFrom)
		if rid == "" {
			rid = r.ReceivedFrom // 外部节点没有 RouterID 时退化为节点 ID，保证可比较
		}
		live = append(live, candidate{route: r, key: r.Key(), rid: rid})
	}
	addStage(StageValid, "drop suppressed/unusable routes", live, filtered)
	if len(live) == 0 {
		return &SelectionResult{Trace: trace}
	}

	// reduce 执行一个“越小越好/越大越好”的通用比较阶段。
	reduce := func(stage, rule string, value func(*Route) int, higher bool) {
		if len(live) <= 1 {
			addStage(stage, rule, live, nil)
			return
		}
		best := value(live[0].route)
		for _, c := range live[1:] {
			v := value(c.route)
			if higher && v > best || !higher && v < best {
				best = v
			}
		}
		var kept []candidate
		var dropped map[string]string
		if withTrace {
			dropped = map[string]string{}
		}
		for _, c := range live {
			v := value(c.route)
			if v == best {
				kept = append(kept, c)
			} else if withTrace {
				verb := "lower"
				if higher {
					verb = "higher"
				}
				dropped[c.key] = fmt.Sprintf("%s=%d, winner has %s value %d",
					stage, v, verb, best)
			}
		}
		addStage(stage, rule, kept, dropped)
		live = kept
	}

	// 1. 本地优先级，高者胜。
	reduce(StageLocalPref, "highest local preference wins",
		func(r *Route) int { return int(r.Attrs.LocalPref) }, true)

	// 2. AS 路径长度，短者胜。
	reduce(StageASPath, "shortest AS path length wins",
		func(r *Route) int { return r.Attrs.ASPathLen() }, false)

	// 3. 起源类型：IGP(0) < EGP(1) < incomplete(2)。
	reduce(StageOrigin, "lowest origin code wins (igp<egp<incomplete)",
		func(r *Route) int { return int(r.Attrs.Origin) }, false)

	// 4. MED：默认仅在左起第一个 AS（相邻 AS）相同时才比较。
	medStage := func() {
		if len(live) <= 1 {
			addStage(StageMED, "lowest MED wins (only compared when neighboring AS matches)", live, nil)
			return
		}
		neighborAS := func(r *Route) (uint32, bool) {
			if len(r.Attrs.ASPath) == 0 {
				return 0, false
			}
			return r.Attrs.ASPath[0], true
		}
		base := live[0].route
		baseAS, baseOK := neighborAS(base)
		comparable := true
		if !opts.AlwaysCompareMED {
			for _, c := range live[1:] {
				as, ok := neighborAS(c.route)
				if ok != baseOK || ok && as != baseAS {
					comparable = false
					break
				}
			}
		}
		if !comparable {
			addStage(StageMED, "MED not compared: neighboring AS differs", live, nil)
			return
		}
		reduce(StageMED, "lowest MED wins",
			func(r *Route) int { return int(r.Attrs.MED) }, false)
	}
	medStage()

	// 5. eBGP 优于 iBGP。
	reduce(StageEBGP, "eBGP route preferred over iBGP route",
		func(r *Route) int {
			if r.PeerType == PeerEBGP {
				return 1
			}
			return 0
		}, true)

	// 6. 到 BGP 下一跳的 IGP 开销，低者胜。
	reduce(StageIGPCost, "lowest IGP cost to BGP next-hop wins",
		func(r *Route) int { return r.IGPCost }, false)

	// 到这里仍打平的就是等价路径候选（ECMP）。
	ecmpCandidates := append([]candidate(nil), live...)
	sort.SliceStable(ecmpCandidates, func(i, j int) bool {
		return ecmpCandidates[i].rid < ecmpCandidates[j].rid
	})

	// 7. 路由器 ID，小者胜——保证单条最优路由确定且可复现。
	if len(live) > 1 {
		var dropped map[string]string
		if withTrace {
			dropped = map[string]string{}
		}
		bestRID := live[0].rid
		for _, c := range live[1:] {
			if c.rid < bestRID {
				bestRID = c.rid
			}
		}
		var kept []candidate
		for _, c := range live {
			if c.rid == bestRID {
				kept = append(kept, c)
			} else if withTrace {
				dropped[c.key] = fmt.Sprintf("router_id=%s, winner router_id=%s", c.rid, bestRID)
			}
		}
		addStage(StageRouterID, "lowest advertising router-id wins", kept, dropped)
		live = kept
	} else {
		addStage(StageRouterID, "single candidate, router-id tiebreak not needed", live, nil)
	}

	if len(live) == 0 {
		return &SelectionResult{Trace: trace}
	}
	primary := live[0].route
	if withTrace {
		trace.WinnerKey = live[0].key
		trace.WinnerFrom = primary.ReceivedFrom
		for _, c := range ecmpCandidates {
			trace.ECMPKeys = append(trace.ECMPKeys, c.key)
		}
	}

	maxPaths := opts.MaxPaths
	if maxPaths < 1 {
		maxPaths = 1
	}
	res := &SelectionResult{Primary: primary, Trace: trace}
	for i, c := range ecmpCandidates {
		if i >= maxPaths {
			break
		}
		res.ECMP = append(res.ECMP, c.route)
	}
	return res
}
