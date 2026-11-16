// Package agent is the edge node agent: it pulls desired state from the
// control plane, supervises local child processes and keeps them alive
// even while disconnected (offline autonomy).
package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"edgeops/internal/api"
	"edgeops/internal/clock"
)

type Config struct {
	NodeID            string // empty -> generated and persisted
	StoreID           string
	Region            string
	Labels            map[string]string
	Taints            []string
	Capacity          api.Resources
	Hours             api.BusinessHours
	CPAddr            string
	ListenAddr        string
	DataDir           string // host-local: identity, cached desired, logs
	StoreDataDir      string // the store's data disk, survives host replacement
	Executor          Executor
	Client            *http.Client // injectable (fault net in simulator)
	Clock             clock.Clock
	HeartbeatInterval time.Duration
	AgentVersion      string
}

type Agent struct {
	cfg     Config
	sup     *Supervisor
	client  *http.Client
	clk     clock.Clock
	desired api.NodeDesired
	nodeID  string
}

type identity struct {
	NodeID string `json:"node_id"`
}

func New(cfg Config) *Agent {
	if cfg.HeartbeatInterval == 0 {
		cfg.HeartbeatInterval = time.Second
	}
	if cfg.Client == nil {
		cfg.Client = &http.Client{Timeout: 30 * time.Second}
	}
	if cfg.Clock == nil {
		cfg.Clock = clock.Real{}
	}
	if cfg.AgentVersion == "" {
		cfg.AgentVersion = "1.0.0"
	}
	return &Agent{cfg: cfg, client: cfg.Client, clk: cfg.Clock}
}

func (a *Agent) NodeID() string { return a.nodeID }

func (a *Agent) Run(ctx context.Context) error {
	if err := os.MkdirAll(a.logDir(), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(a.storeDataDir(), 0o755); err != nil {
		return err
	}
	if err := a.loadIdentity(); err != nil {
		return err
	}
	a.sup = NewSupervisor(a.cfg.Executor, a.clk, a.logDir(), a.storeDataDir())
	go a.sup.Run(ctx)

	// Load last desired state from disk: an agent restart must not
	// interrupt the store's services (offline autonomy).
	if b, err := os.ReadFile(filepath.Join(a.cfg.DataDir, "desired.json")); err == nil {
		var d api.NodeDesired
		if json.Unmarshal(b, &d) == nil {
			a.desired = d
			a.sup.Reconcile(d.Assignments)
		}
	}

	go a.serveLogs(ctx)
	if err := a.registerLoop(ctx); err != nil {
		return err
	}
	go a.desiredLoop(ctx)
	go a.heartbeatLoop(ctx)
	<-ctx.Done()
	a.sup.StopAll()
	return nil
}

func (a *Agent) logDir() string { return filepath.Join(a.cfg.DataDir, "logs") }
func (a *Agent) storeDataDir() string {
	if a.cfg.StoreDataDir != "" {
		return a.cfg.StoreDataDir
	}
	return filepath.Join(a.cfg.DataDir, "storedata")
}

func (a *Agent) loadIdentity() error {
	p := filepath.Join(a.cfg.DataDir, "agent.json")
	if b, err := os.ReadFile(p); err == nil {
		var id identity
		if json.Unmarshal(b, &id) == nil && id.NodeID != "" {
			a.nodeID = id.NodeID
			return nil
		}
	}
	a.nodeID = a.cfg.NodeID
	if a.nodeID == "" {
		a.nodeID = fmt.Sprintf("node-%d", time.Now().UnixNano())
	}
	b, _ := json.Marshal(identity{NodeID: a.nodeID})
	return os.WriteFile(p, b, 0o644)
}

func (a *Agent) registerLoop(ctx context.Context) error {
	body := api.RegisterRequest{
		NodeID: a.nodeID, StoreID: a.cfg.StoreID, Region: a.cfg.Region,
		Labels: a.cfg.Labels, Taints: a.cfg.Taints, Capacity: a.cfg.Capacity,
		Hours: a.cfg.Hours, Addr: a.cfg.ListenAddr, AgentVersion: a.cfg.AgentVersion,
	}
	for {
		if err := a.post("/api/agent/register", body, nil); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

func (a *Agent) desiredLoop(ctx context.Context) {
	sig := a.desired.Sig
	for {
		url := fmt.Sprintf("http://%s/api/agent/desired?node_id=%s&sig=%s", a.cfg.CPAddr, a.nodeID, sig)
		req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
		resp, err := a.client.Do(req)
		if err != nil {
			// 断网: 按最后一次收到的期望状态继续自治
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
			}
			continue
		}
		var d api.NodeDesired
		json.NewDecoder(resp.Body).Decode(&d)
		resp.Body.Close()
		if d.Sig == "" || d.Sig == sig {
			continue
		}
		sig = d.Sig
		a.desired = d
		if b, err := json.Marshal(d); err == nil {
			os.WriteFile(filepath.Join(a.cfg.DataDir, "desired.json"), b, 0o644)
		}
		a.sup.Reconcile(d.Assignments)
	}
}

func (a *Agent) heartbeatLoop(ctx context.Context) {
	t := time.NewTicker(a.cfg.HeartbeatInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			h := api.Heartbeat{
				NodeID:      a.nodeID,
				Usage:       a.sup.Usage(),
				DataMarker:  a.dataMarker(),
				Assignments: a.sup.Statuses(),
				Metrics:     a.sup.Metrics(a.nodeID, a.cfg.StoreID),
			}
			a.post("/api/agent/heartbeat", h, nil) // 失败下个周期重试
		}
	}
}

// dataMarker returns the first line of the store's data marker file,
// proving local data continuity across host replacement.
func (a *Agent) dataMarker() string {
	b, err := os.ReadFile(filepath.Join(a.storeDataDir(), "marker.txt"))
	if err != nil {
		return ""
	}
	for i, c := range b {
		if c == '\n' {
			return string(b[:i])
		}
	}
	return string(b)
}

func (a *Agent) post(path string, body, out any) error {
	b, _ := json.Marshal(body)
	resp, err := a.client.Post("http://"+a.cfg.CPAddr+path, "application/json", bytes.NewReader(b))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

// serveLogs exposes local (size-rotated) logs for remote viewing.
func (a *Agent) serveLogs(ctx context.Context) {
	mux := http.NewServeMux()
	mux.HandleFunc("/logs", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		lines := 100
		fmt.Sscanf(r.URL.Query().Get("lines"), "%d", &lines)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte(tailLog(a.logDir(), id, lines)))
	})
	srv := &http.Server{Addr: a.cfg.ListenAddr, Handler: mux}
	go srv.ListenAndServe()
	<-ctx.Done()
	srv.Close()
}

// KillProcess kills one running workload process (fault injection).
func (a *Agent) KillProcess(id string) bool { return a.sup.Kill(id) }

// RunningIDs returns assignment IDs currently supervised.
func (a *Agent) RunningIDs() []string { return a.sup.IDs() }
