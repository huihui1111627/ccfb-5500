package server

import (
	"encoding/json"
	"net/http"

	"github.com/edu-net/bgpsim/internal/traffic"
)

func (s *Server) handleTopology(w http.ResponseWriter, r *http.Request) {
	eng, ok := s.requireEngine(w)
	if !ok {
		return
	}
	s.sess.mu.Lock()
	topo := s.sess.scenario.Config.Topology
	resp := map[string]interface{}{
		"local_as":  eng.LocalAS(),
		"nodes":     eng.Nodes(),
		"links":     eng.Links(),
		"roas":      topo.ROAs,
		"upstreams": eng.EdgeRouters(),
	}
	s.sess.mu.Unlock()
	writeJSON(w, resp)
}

func (s *Server) handleRIB(w http.ResponseWriter, r *http.Request) {
	eng, ok := s.requireEngine(w)
	if !ok {
		return
	}
	node := r.URL.Query().Get("node")
	if node == "" {
		writeErr(w, http.StatusBadRequest, errMissing("node"))
		return
	}
	s.sess.mu.Lock()
	views, found := eng.RIB(node)
	s.sess.mu.Unlock()
	if !found {
		writeErr(w, http.StatusNotFound, errMissing("node "+node))
		return
	}
	writeJSON(w, map[string]interface{}{"node": node, "routes": views, "count": len(views)})
}

func (s *Server) handlePrefixes(w http.ResponseWriter, r *http.Request) {
	eng, ok := s.requireEngine(w)
	if !ok {
		return
	}
	s.sess.mu.Lock()
	prefixes := eng.AllPrefixes()
	s.sess.mu.Unlock()
	writeJSON(w, map[string]interface{}{"prefixes": prefixes, "count": len(prefixes)})
}

func (s *Server) handlePrefixDetail(w http.ResponseWriter, r *http.Request) {
	eng, ok := s.requireEngine(w)
	if !ok {
		return
	}
	node, prefix := r.URL.Query().Get("node"), r.URL.Query().Get("prefix")
	if node == "" || prefix == "" {
		writeErr(w, http.StatusBadRequest, errMissing("node and prefix"))
		return
	}
	s.sess.mu.Lock()
	detail, found := eng.PrefixDetail(node, prefix)
	s.sess.mu.Unlock()
	if !found {
		writeErr(w, http.StatusNotFound, errMissing("node "+node))
		return
	}
	writeJSON(w, detail)
}

// handleDecision 是前缀选路解释的别名端点，语义同 /api/prefix。
func (s *Server) handleDecision(w http.ResponseWriter, r *http.Request) {
	s.handlePrefixDetail(w, r)
}

func (s *Server) handleSnapshots(w http.ResponseWriter, r *http.Request) {
	eng, ok := s.requireEngine(w)
	if !ok {
		return
	}
	s.sess.mu.Lock()
	snaps := eng.Snapshots()
	s.sess.mu.Unlock()
	writeJSON(w, map[string]interface{}{"snapshots": snaps, "rounds": len(snaps)})
}

func (s *Server) handleStep(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, errMissing("POST"))
		return
	}
	eng, ok := s.requireEngine(w)
	if !ok {
		return
	}
	s.sess.mu.Lock()
	processed := eng.Step()
	stats := eng.Stats()
	s.sess.mu.Unlock()
	writeJSON(w, map[string]interface{}{
		"processed_messages": processed,
		"pending":            eng.Pending(),
		"round":              stats.Rounds,
		"converged_round":    stats.ConvergedInRound,
	})
}

func (s *Server) handleRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, errMissing("POST"))
		return
	}
	eng, ok := s.requireEngine(w)
	if !ok {
		return
	}
	s.sess.mu.Lock()
	rounds, err := eng.RunUntilIdle(0)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	stats := eng.Stats()
	s.sess.mu.Unlock()
	writeJSON(w, map[string]interface{}{
		"rounds_run":      rounds,
		"converged_round": stats.ConvergedInRound,
		"stats":           stats,
	})
}

func (s *Server) handleFailLink(w http.ResponseWriter, r *http.Request) {
	s.fault(w, r, true, false)
}

func (s *Server) handleRestoreLink(w http.ResponseWriter, r *http.Request) {
	s.fault(w, r, true, true)
}

func (s *Server) handleFailRouter(w http.ResponseWriter, r *http.Request) {
	s.fault(w, r, false, false)
}

func (s *Server) handleRestoreRouter(w http.ResponseWriter, r *http.Request) {
	s.fault(w, r, false, true)
}

// fault 统一处理链路/路由器的故障与恢复。
func (s *Server) fault(w http.ResponseWriter, r *http.Request, isLink, restore bool) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, errMissing("POST"))
		return
	}
	var body struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.ID == "" {
		writeErr(w, http.StatusBadRequest, errMissing("id in JSON body"))
		return
	}
	eng, ok := s.requireEngine(w)
	if !ok {
		return
	}
	s.sess.mu.Lock()
	var err error
	switch {
	case isLink && !restore:
		err = eng.FailLink(body.ID)
	case isLink && restore:
		err = eng.RestoreLink(body.ID)
	case !isLink && !restore:
		err = eng.FailRouter(body.ID)
	default:
		err = eng.RestoreRouter(body.ID)
	}
	pending := eng.Pending()
	s.sess.mu.Unlock()
	if err != nil {
		writeErr(w, http.StatusNotFound, err)
		return
	}
	writeJSON(w, map[string]interface{}{"applied": true, "pending_messages": pending})
}

func (s *Server) handleProblems(w http.ResponseWriter, r *http.Request) {
	eng, ok := s.requireEngine(w)
	if !ok {
		return
	}
	s.sess.mu.Lock()
	stats := eng.CheckProblems()
	s.sess.mu.Unlock()
	writeJSON(w, map[string]interface{}{
		"loops_detected":  stats.LoopsDetected,
		"blackholes":      stats.Blackholes,
		"rr_loop_blocked": stats.RRLoopBlocked,
	})
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	eng, ok := s.requireEngine(w)
	if !ok {
		return
	}
	s.sess.mu.Lock()
	stats := eng.Stats()
	s.sess.mu.Unlock()
	writeJSON(w, stats)
}

func (s *Server) handleTraffic(w http.ResponseWriter, r *http.Request) {
	eng, ok := s.requireEngine(w)
	if !ok {
		return
	}
	s.sess.mu.Lock()
	matrix := s.sess.matrix
	if matrix == nil {
		s.sess.mu.Unlock()
		writeErr(w, http.StatusConflict, errMissing("traffic matrix"))
		return
	}
	loads := traffic.Compute(eng, matrix)
	s.sess.mu.Unlock()
	writeJSON(w, map[string]interface{}{"link_loads": loads})
}

func (s *Server) handleDamping(w http.ResponseWriter, r *http.Request) {
	eng, ok := s.requireEngine(w)
	if !ok {
		return
	}
	s.sess.mu.Lock()
	var snaps []struct {
		Round int `json:"round"`
	}
	_ = snaps
	// 阻尼状态内嵌在每轮快照里，这里返回最新一轮。
	all := eng.Snapshots()
	var latest interface{}
	if n := len(all); n > 0 {
		latest = all[n-1].Dampened
	}
	s.sess.mu.Unlock()
	writeJSON(w, map[string]interface{}{"dampened": latest})
}

func (s *Server) handlePolicies(w http.ResponseWriter, r *http.Request) {
	eng, ok := s.requireEngine(w)
	if !ok {
		return
	}
	s.sess.mu.Lock()
	ps := s.sess.scenario.Config.Policies
	rp := s.sess.scenario.Config.RouterPolicies
	s.sess.mu.Unlock()
	_ = eng
	writeJSON(w, map[string]interface{}{
		"prefix_lists":    ps.PrefixLists,
		"route_maps":      ps.RouteMaps,
		"router_policies": rp,
	})
}

type stringErr string

func (e stringErr) Error() string  { return string(e) }
func errMissing(what string) error { return stringErr("missing or invalid: " + what) }
