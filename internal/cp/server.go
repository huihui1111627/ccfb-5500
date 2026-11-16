package cp

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"edgeops/internal/api"
	"edgeops/internal/clock"
)

//go:embed console/index.html
var consoleHTML []byte

type Config struct {
	Addr              string
	DataDir           string
	ReconcileInterval time.Duration
	SnapshotInterval  time.Duration
	NodeOfflineAfter  time.Duration
	ProxyTransport    http.RoundTripper // optional, simulator injects the fault net
}

type Server struct {
	cfg    Config
	clk    clock.Clock
	Store  *Store
	mux    *http.ServeMux
	http   *http.Server
	proxy  *http.Client
	stopCh chan struct{}
}

func NewServer(cfg Config, clk clock.Clock) (*Server, error) {
	st, err := NewStore(clk, cfg.DataDir)
	if err != nil {
		return nil, err
	}
	if cfg.ReconcileInterval == 0 {
		cfg.ReconcileInterval = 500 * time.Millisecond
	}
	if cfg.SnapshotInterval == 0 {
		cfg.SnapshotInterval = 500 * time.Millisecond
	}
	if cfg.NodeOfflineAfter == 0 {
		cfg.NodeOfflineAfter = 5 * time.Second
	}
	s := &Server{
		cfg:    cfg,
		clk:    clk,
		Store:  st,
		mux:    http.NewServeMux(),
		stopCh: make(chan struct{}),
		proxy: &http.Client{
			Timeout:   4 * time.Second,
			Transport: cfg.ProxyTransport,
		},
	}
	if cfg.ProxyTransport == nil {
		s.proxy.Transport = http.DefaultTransport
	}
	s.routes()
	return s, nil
}

func (s *Server) routes() {
	s.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(consoleHTML)
	})
	s.mux.HandleFunc("POST /api/agent/register", s.handleRegister)
	s.mux.HandleFunc("POST /api/agent/heartbeat", s.handleHeartbeat)
	s.mux.HandleFunc("GET /api/agent/desired", s.handleDesired)
	s.mux.HandleFunc("GET /api/nodes", s.handleNodes)
	s.mux.HandleFunc("GET /api/workloads", s.handleWorkloads)
	s.mux.HandleFunc("POST /api/workloads", s.handlePutWorkload)
	s.mux.HandleFunc("GET /api/workloads/progress", s.handleProgress)
	s.mux.HandleFunc("GET /api/releases", s.handleReleases)
	s.mux.HandleFunc("POST /api/releases", s.handleCreateRelease)
	s.mux.HandleFunc("GET /api/releases/{id}", s.handleGetRelease)
	s.mux.HandleFunc("GET /api/events", s.handleEventsSSE)
	s.mux.HandleFunc("GET /api/events/list", s.handleEventsList)
	s.mux.HandleFunc("GET /api/quotas", s.handleQuotas)
	s.mux.HandleFunc("POST /api/quotas", s.handlePutQuota)
	s.mux.HandleFunc("GET /api/recommendations", s.handleRecommendations)
	s.mux.HandleFunc("GET /api/nodes/{id}/logs", s.handleNodeLogs)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, err error) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

func decode(w http.ResponseWriter, r *http.Request, v any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	if err := dec.Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return err
	}
	return nil
}

// ---- agent protocol ----

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req api.RegisterRequest
	if decode(w, r, &req) != nil {
		return
	}
	if req.NodeID == "" || req.StoreID == "" {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("node_id 和 store_id 必填"))
		return
	}
	replaced := s.Store.Register(req)
	s.Store.Reconcile()
	s.Store.changed()
	writeJSON(w, map[string]any{"ok": true, "replaced": replaced})
}

func (s *Server) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	var h api.Heartbeat
	if decode(w, r, &h) != nil {
		return
	}
	s.Store.Heartbeat(h)
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) handleDesired(w http.ResponseWriter, r *http.Request) {
	nodeID := r.URL.Query().Get("node_id")
	sig := r.URL.Query().Get("sig")
	if nodeID == "" {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("node_id required"))
		return
	}
	d := s.Store.WaitDesired(nodeID, sig, 25*time.Second)
	writeJSON(w, d)
}

// ---- console API ----

func (s *Server) handleNodes(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.Store.ListNodes())
}

func (s *Server) handleWorkloads(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.Store.ListWorkloads())
}

func (s *Server) handlePutWorkload(w http.ResponseWriter, r *http.Request) {
	var spec api.WorkloadSpec
	if decode(w, r, &spec) != nil {
		return
	}
	if err := s.Store.PutWorkload(spec); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) handleProgress(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.Store.Progress())
}

func (s *Server) handleReleases(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.Store.ListReleases())
}

func (s *Server) handleCreateRelease(w http.ResponseWriter, r *http.Request) {
	var req api.CreateReleaseRequest
	if decode(w, r, &req) != nil {
		return
	}
	rel, err := s.Store.CreateRelease(req)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, rel)
}

func (s *Server) handleGetRelease(w http.ResponseWriter, r *http.Request) {
	rel, ok := s.Store.GetRelease(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, fmt.Errorf("发布单不存在"))
		return
	}
	writeJSON(w, rel)
}

func (s *Server) handleEventsList(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.Store.EventsSince(0))
}

func (s *Server) handleEventsSSE(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	fl, ok := w.(http.Flusher)
	if !ok {
		return
	}
	var last int64
	for _, e := range s.Store.EventsSince(0) {
		fmt.Fprintf(w, "data: %s\n\n", mustJSON(e))
		last = e.ID
	}
	fl.Flush()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-s.Store.ChangeCh():
			for _, e := range s.Store.EventsSince(last) {
				fmt.Fprintf(w, "data: %s\n\n", mustJSON(e))
				last = e.ID
			}
			fl.Flush()
		case <-time.After(30 * time.Second):
			fmt.Fprintf(w, ": ping\n\n")
			fl.Flush()
		}
	}
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func (s *Server) handleQuotas(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.Store.ListQuotas())
}

func (s *Server) handlePutQuota(w http.ResponseWriter, r *http.Request) {
	var q api.Quota
	if decode(w, r, &q) != nil {
		return
	}
	if err := s.Store.PutQuota(q); err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) handleRecommendations(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.Store.Recommendations())
}

// handleNodeLogs proxies a remote log read to the node agent.
func (s *Server) handleNodeLogs(w http.ResponseWriter, r *http.Request) {
	node, ok := s.Store.GetNode(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, fmt.Errorf("节点不存在"))
		return
	}
	if !node.Online {
		writeErr(w, http.StatusBadGateway, fmt.Errorf("节点离线, 无法远程读取日志"))
		return
	}
	q := r.URL.Query()
	url := fmt.Sprintf("http://%s/logs?id=%s&lines=%s",
		node.Addr, q.Get("id"), q.Get("lines"))
	resp, err := s.proxy.Get(url)
	if err != nil {
		writeErr(w, http.StatusBadGateway, fmt.Errorf("读取门店日志失败: %v", err))
		return
	}
	defer resp.Body.Close()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	io.Copy(w, resp.Body)
}

// ---- lifecycle ----

func (s *Server) Start() error {
	ln, err := net.Listen("tcp", s.cfg.Addr)
	if err != nil {
		return err
	}
	s.http = &http.Server{Handler: s.mux}
	go s.http.Serve(ln)
	go s.loop(s.cfg.ReconcileInterval, func() { s.Store.Reconcile() })
	go s.loop(s.cfg.SnapshotInterval, func() { s.Store.Snapshot() })
	go s.loop(time.Second, func() { s.Store.MarkOffline(s.cfg.NodeOfflineAfter) })
	go s.releaseLoop()
	return nil
}

func (s *Server) loop(interval time.Duration, f func()) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-s.stopCh:
			return
		case <-t.C:
			f()
		}
	}
}

// releaseLoop advances releases; the delta is clamped so wall/sim clock
// jumps can neither rewind nor fast-forward the canary soak timer.
func (s *Server) releaseLoop() {
	t := time.NewTicker(300 * time.Millisecond)
	defer t.Stop()
	last := s.clk.Now()
	maxDelta := 5 * time.Minute
	for {
		select {
		case <-s.stopCh:
			return
		case <-t.C:
			now := s.clk.Now()
			delta := now.Sub(last)
			if delta < 0 {
				delta = 0 // 时钟回拨: 浸泡时间不倒退
			}
			if delta > maxDelta {
				delta = maxDelta // 时钟跳变: 不允许一次跳满
			}
			last = now
			s.Store.AdvanceReleases(now, delta)
		}
	}
}

func (s *Server) Shutdown(ctx context.Context) error {
	close(s.stopCh)
	if s.http != nil {
		s.http.Shutdown(ctx)
	}
	return s.Store.Snapshot()
}
