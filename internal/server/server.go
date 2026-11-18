// Package server 提供仿真平台的 HTTP API 与静态网页托管。
package server

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"sync"

	"github.com/edu-net/bgpsim/internal/engine"
	"github.com/edu-net/bgpsim/internal/gen"
	"github.com/edu-net/bgpsim/internal/traffic"
)

//go:embed all:web
var webFS embed.FS

// Session 持有一次网页仿真会话的全部运行态。
type Session struct {
	mu       sync.Mutex
	engine   *engine.Engine
	matrix   *traffic.Matrix
	scenario *gen.Scenario
}

// Server 是 HTTP 处理器集合，当前单会话即可满足平台演示与验证。
type Server struct {
	sess *Session
}

// New 构造服务器，预置一个生成的大规模场景。
func New() *Server {
	return &Server{sess: &Session{}}
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func writeErr(w http.ResponseWriter, status int, err error) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

// Routes 注册全部 HTTP 路由。
func (s *Server) Routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/health", s.handleHealth)
	mux.HandleFunc("/api/scenario/generate", s.handleGenerate)
	mux.HandleFunc("/api/topology", s.handleTopology)
	mux.HandleFunc("/api/rib", s.handleRIB)
	mux.HandleFunc("/api/prefix", s.handlePrefixDetail)
	mux.HandleFunc("/api/prefixes", s.handlePrefixes)
	mux.HandleFunc("/api/decision", s.handleDecision)
	mux.HandleFunc("/api/snapshots", s.handleSnapshots)
	mux.HandleFunc("/api/step", s.handleStep)
	mux.HandleFunc("/api/run", s.handleRun)
	mux.HandleFunc("/api/fail/link", s.handleFailLink)
	mux.HandleFunc("/api/fail/router", s.handleFailRouter)
	mux.HandleFunc("/api/restore/link", s.handleRestoreLink)
	mux.HandleFunc("/api/restore/router", s.handleRestoreRouter)
	mux.HandleFunc("/api/problems", s.handleProblems)
	mux.HandleFunc("/api/stats", s.handleStats)
	mux.HandleFunc("/api/traffic", s.handleTraffic)
	mux.HandleFunc("/api/damping", s.handleDamping)
	mux.HandleFunc("/api/policies", s.handlePolicies)
	mux.HandleFunc("/api/policy/apply", s.handlePolicyApply)

	// 静态网页：嵌入的 web 目录作为站点根，未知路径回退到 index.html（单页应用）。
	webRoot, err := fs.Sub(webFS, "web")
	if err == nil {
		fileServer := http.FileServer(http.FS(webRoot))
		mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, err := fs.Stat(webRoot, r.URL.Path[1:]); err != nil && r.URL.Path != "/" {
				// 资源不存在时回退首页，由前端路由处理。
				r.URL.Path = "/"
			}
			fileServer.ServeHTTP(w, r)
		}))
	}
	return mux
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	ready := false
	s.sess.mu.Lock()
	ready = s.sess.engine != nil
	s.sess.mu.Unlock()
	writeJSON(w, map[string]interface{}{"status": "ok", "scenario_loaded": ready})
}

// handleGenerate 生成并加载一个新场景，可选 query: scale=small|large。
func (s *Server) handleGenerate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, fmt.Errorf("POST only"))
		return
	}
	params := gen.DefaultParams()
	if r.URL.Query().Get("scale") == "small" {
		params.CoreCount = 2
		params.RRCount = 1
		params.AggCount = 2
		params.EdgeCount = 2
		params.CampusesPerAgg = 2
		params.PrefixCount = 200
	}
	scenario, err := gen.Generate(params)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	eng, err := engine.New(scenario.Config)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	s.sess.mu.Lock()
	s.sess.engine = eng
	s.sess.matrix = &scenario.Matrix
	s.sess.scenario = scenario
	s.sess.mu.Unlock()
	writeJSON(w, map[string]interface{}{
		"nodes":       len(eng.Nodes()),
		"links":       len(eng.Links()),
		"prefixes":    len(scenario.Config.Topology.External),
		"roas":        len(scenario.Config.Topology.ROAs),
		"local_as":    eng.LocalAS(),
		"max_paths":   scenario.Config.Selection.MaxPaths,
		"rpki_action": string(scenario.Config.RPKIAction),
	})
}

// requireEngine 取已加载引擎，未加载时返回错误。
func (s *Server) requireEngine(w http.ResponseWriter) (*engine.Engine, bool) {
	s.sess.mu.Lock()
	defer s.sess.mu.Unlock()
	if s.sess.engine == nil {
		writeErr(w, http.StatusConflict, fmt.Errorf("no scenario loaded, call /api/scenario/generate first"))
		return nil, false
	}
	return s.sess.engine, true
}
