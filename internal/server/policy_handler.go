package server

import (
	"encoding/json"
	"net/http"

	"github.com/edu-net/bgpsim/internal/bgpsim"
	"github.com/edu-net/bgpsim/internal/engine"
	"github.com/edu-net/bgpsim/internal/policy"
)

// policyApplyRequest 是前端提交的一条 route-map 节点。
type policyApplyRequest struct {
	Name         string   `json:"name"`
	Seq          int      `json:"seq"`
	Router       string   `json:"router"`
	Result       string   `json:"result"`
	Prefixes     []string `json:"prefixes"`
	Community    *string  `json:"community"`
	ASPathRegexp *string  `json:"as_path_regexp"`
	SetLocalPref *uint32  `json:"set_local_pref"`
	Prepend      []uint32 `json:"prepend"`
	AddCommunity *string  `json:"add_community"`
}

// handlePolicyApply 把前端编辑的策略写入场景配置，重建引擎并跑到收敛。
// 策略变更属于“改配置”，按设备实际工作流需要重建 BGP 会话，因此这里重建引擎。
func (s *Server) handlePolicyApply(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, errMissing("POST"))
		return
	}
	var req policyApplyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	s.sess.mu.Lock()
	if s.sess.scenario == nil {
		s.sess.mu.Unlock()
		writeErr(w, http.StatusConflict, errMissing("loaded scenario"))
		return
	}
	cfg := &s.sess.scenario.Config

	// 1) 若提供前缀，构造/复用一个同名前缀列表。
	cond := policy.MatchCondition{}
	if len(req.Prefixes) > 0 {
		plName := req.Name + "-PL"
		entries := make([]policy.PrefixListEntry, 0, len(req.Prefixes))
		for _, p := range req.Prefixes {
			entries = append(entries, policy.PrefixListEntry{Prefix: p})
		}
		upsertPrefixList(&cfg.Policies, policy.PrefixList{Name: plName, Entries: entries})
		cond.PrefixLists = []string{plName}
	}
	if req.Community != nil && *req.Community != "" {
		c, err := bgpsim.ParseCommunity(*req.Community)
		if err != nil {
			s.sess.mu.Unlock()
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		cond.Community = &policy.CommunityMatch{Communities: []uint32{c}, Mode: "any"}
	}
	if req.ASPathRegexp != nil && *req.ASPathRegexp != "" {
		cond.ASPathRegex = *req.ASPathRegexp
	}

	// 2) 构造动作。
	act := policy.Action{Result: req.Result}
	act.SetLocalPref = req.SetLocalPref
	if len(req.Prepend) > 0 {
		act.PrependASPath = req.Prepend
	}
	if req.AddCommunity != nil && *req.AddCommunity != "" {
		c, err := bgpsim.ParseCommunity(*req.AddCommunity)
		if err != nil {
			s.sess.mu.Unlock()
			writeErr(w, http.StatusBadRequest, err)
			return
		}
		act.AddCommunities = []uint32{c}
	}

	// 3) 写入/更新 route-map（同名同序号覆盖），并保证末尾有兜底放行节点。
	entry := policy.RouteMapEntry{Seq: req.Seq, Match: cond, Actions: []policy.Action{act}}
	upsertRouteMapEntry(&cfg.Policies, req.Name, entry)
	ensureFallbackPermit(&cfg.Policies, req.Name, req.Seq)

	// 4) 绑定到指定边缘路由器的入向策略。
	if req.Router != "" {
		bindImportMap(&cfg.RouterPolicies, req.Router, req.Name)
	}

	// 5) 用新配置重建引擎并跑到收敛。
	eng, err := engine.New(*cfg)
	if err != nil {
		s.sess.mu.Unlock()
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	s.sess.engine = eng
	s.sess.mu.Unlock()

	stats, err := eng.Run(0)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, map[string]interface{}{
		"applied":         true,
		"route_map":       req.Name,
		"converged_round": stats.ConvergedInRound,
		"stats":           stats,
	})
}

func upsertPrefixList(ps *policy.PolicySet, pl policy.PrefixList) {
	for i := range ps.PrefixLists {
		if ps.PrefixLists[i].Name == pl.Name {
			ps.PrefixLists[i] = pl
			return
		}
	}
	ps.PrefixLists = append(ps.PrefixLists, pl)
}

func upsertRouteMapEntry(ps *policy.PolicySet, name string, entry policy.RouteMapEntry) {
	for i := range ps.RouteMaps {
		if ps.RouteMaps[i].Name != name {
			continue
		}
		for j, e := range ps.RouteMaps[i].Entries {
			if e.Seq == entry.Seq {
				ps.RouteMaps[i].Entries[j] = entry
				return
			}
		}
		ps.RouteMaps[i].Entries = append(ps.RouteMaps[i].Entries, entry)
		return
	}
	ps.RouteMaps = append(ps.RouteMaps, policy.RouteMap{Name: name, Entries: []policy.RouteMapEntry{entry}})
}

// ensureFallbackPermit 保证 route-map 末尾存在一个大序号空匹配放行节点，
// 避免自定义节点之后的路由被隐式 deny 全部丢弃。
func ensureFallbackPermit(ps *policy.PolicySet, name string, lastSeq int) {
	for i := range ps.RouteMaps {
		if ps.RouteMaps[i].Name != name {
			continue
		}
		maxSeq := lastSeq
		for _, e := range ps.RouteMaps[i].Entries {
			if e.Seq > maxSeq {
				maxSeq = e.Seq
			}
		}
		for _, e := range ps.RouteMaps[i].Entries {
			if e.Seq > lastSeq && len(e.Actions) == 0 {
				return // 已有兜底节点
			}
		}
		ps.RouteMaps[i].Entries = append(ps.RouteMaps[i].Entries,
			policy.RouteMapEntry{Seq: maxSeq + 10})
		return
	}
}

func bindImportMap(bindings *[]engine.RouterPolicy, nodeID, mapName string) {
	for i := range *bindings {
		if (*bindings)[i].NodeID == nodeID {
			(*bindings)[i].ImportMap = mapName
			return
		}
	}
	*bindings = append(*bindings, engine.RouterPolicy{NodeID: nodeID, ImportMap: mapName})
}
