// Package cp is the control plane: state store, scheduler, reconciler,
// release orchestrator and HTTP API.
package cp

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"edgeops/internal/api"
	"edgeops/internal/clock"
)

// Node is the control-plane view of one edge node.
type Node struct {
	NodeID       string            `json:"node_id"`
	StoreID      string            `json:"store_id"`
	Region       string            `json:"region"`
	Labels       map[string]string `json:"labels"`
	Taints       []string          `json:"taints"`
	Capacity     api.Resources     `json:"capacity"`
	Hours        api.BusinessHours `json:"hours"`
	Addr         string            `json:"addr"`
	AgentVersion string            `json:"agent_version"`

	// runtime only
	Online     bool          `json:"-"`
	Replaced   bool          `json:"replaced"`
	LastSeen   time.Time     `json:"-"`
	Usage      api.Resources `json:"-"`
	DataMarker string        `json:"-"`
}

type state struct {
	Nodes       map[string]*Node             `json:"nodes"`
	Workloads   map[string]*api.WorkloadSpec `json:"workloads"`
	Assignments map[string]*api.Assignment   `json:"assignments"`
	Releases    map[string]*api.ReleaseOrder `json:"releases"`
	Quotas      map[string]*api.Quota        `json:"quotas"`
	Overrides   map[string]string            `json:"overrides"` // "store|workload" -> version
	Events      []api.Event                  `json:"events"`

	NodeSig map[string]string             `json:"-"`
	Pending []api.PendingItem             `json:"-"`
	Metrics map[string][]api.MetricSample `json:"-"`
}

// Store is the concurrency-safe control-plane state.
type Store struct {
	mu       sync.Mutex
	clk      clock.Clock
	dataFile string
	changeCh chan struct{}
	eventSeq int64
	dirty    bool
	st       *state
}

func NewStore(clk clock.Clock, dataDir string) (*Store, error) {
	s := &Store{
		clk:      clk,
		dataFile: filepath.Join(dataDir, "state.json"),
		changeCh: make(chan struct{}),
		st: &state{
			Nodes:       map[string]*Node{},
			Workloads:   map[string]*api.WorkloadSpec{},
			Assignments: map[string]*api.Assignment{},
			Releases:    map[string]*api.ReleaseOrder{},
			Quotas:      map[string]*api.Quota{},
			Overrides:   map[string]string{},
			NodeSig:     map[string]string{},
			Metrics:     map[string][]api.MetricSample{},
		},
	}
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, err
	}
	if b, err := os.ReadFile(s.dataFile); err == nil {
		var loaded state
		if err := json.Unmarshal(b, &loaded); err != nil {
			return nil, fmt.Errorf("load state: %w", err)
		}
		if loaded.Nodes != nil {
			s.st.Nodes = loaded.Nodes
		}
		if loaded.Workloads != nil {
			s.st.Workloads = loaded.Workloads
		}
		if loaded.Assignments != nil {
			s.st.Assignments = loaded.Assignments
		}
		if loaded.Releases != nil {
			s.st.Releases = loaded.Releases
		}
		if loaded.Quotas != nil {
			s.st.Quotas = loaded.Quotas
		}
		if loaded.Overrides != nil {
			s.st.Overrides = loaded.Overrides
		}
		s.st.Events = loaded.Events
		for _, n := range s.st.Nodes {
			n.Online = false // re-proven by heartbeats
		}
		if len(s.st.Events) > 0 {
			s.eventSeq = s.st.Events[len(s.st.Events)-1].ID
		}
	}
	return s, nil
}

// changed wakes every long-poll / SSE waiter.
func (s *Store) changed() {
	s.mu.Lock()
	s.changedLocked()
	s.mu.Unlock()
}

func (s *Store) changedLocked() {
	close(s.changeCh)
	s.changeCh = make(chan struct{})
}

// ChangeCh returns a channel closed on the next state change.
func (s *Store) ChangeCh() <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.changeCh
}

func (s *Store) addEventLocked(typ, nodeID, storeID, msg string) {
	s.eventSeq++
	s.st.Events = append(s.st.Events, api.Event{
		ID: s.eventSeq, Time: s.clk.Now(), Type: typ,
		NodeID: nodeID, StoreID: storeID, Message: msg,
	})
	if len(s.st.Events) > 500 {
		s.st.Events = s.st.Events[len(s.st.Events)-500:]
	}
	s.dirty = true
}

// AddEvent appends to the event stream and wakes SSE listeners.
func (s *Store) AddEvent(typ, nodeID, storeID, msg string) {
	s.mu.Lock()
	s.addEventLocked(typ, nodeID, storeID, msg)
	s.mu.Unlock()
	s.changed()
}

// EventsSince returns events with ID > since (max 200).
func (s *Store) EventsSince(since int64) []api.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []api.Event
	for _, e := range s.st.Events {
		if e.ID > since {
			out = append(out, e)
		}
	}
	if len(out) > 200 {
		out = out[len(out)-200:]
	}
	return out
}

// Register upserts a node; a fresh node claiming an existing store replaces the old one.
func (s *Store) Register(req api.RegisterRequest) (replaced []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := s.st.Nodes[req.NodeID]
	if !ok {
		n = &Node{NodeID: req.NodeID}
		s.st.Nodes[req.NodeID] = n
	}
	n.StoreID, n.Region = req.StoreID, req.Region
	n.Labels, n.Taints = req.Labels, req.Taints
	n.Capacity, n.Hours = req.Capacity, req.Hours
	n.Addr, n.AgentVersion = req.Addr, req.AgentVersion
	if !n.Online {
		s.addEventLocked("node_online", n.NodeID, n.StoreID,
			fmt.Sprintf("节点 %s (门店 %s) 上线", req.NodeID, req.StoreID))
	}
	n.Online = true
	n.LastSeen = time.Now()

	for _, other := range s.st.Nodes {
		if other.NodeID != req.NodeID && other.StoreID == req.StoreID && !other.Replaced {
			other.Replaced = true
			other.Online = false
			replaced = append(replaced, other.NodeID)
			s.addEventLocked("node_replaced", other.NodeID, other.StoreID,
				fmt.Sprintf("门店 %s 更换主机: 旧节点 %s 退役, 新节点 %s 接手全部负载与本地数据",
					other.StoreID, other.NodeID, req.NodeID))
		}
	}
	s.dirty = true
	return replaced
}

// Heartbeat records actual state and metrics from an agent (对账).
func (s *Store) Heartbeat(h api.Heartbeat) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := s.st.Nodes[h.NodeID]
	if !ok {
		return
	}
	if !n.Online {
		s.addEventLocked("node_online", n.NodeID, n.StoreID,
			fmt.Sprintf("节点 %s (门店 %s) 恢复连接, 完成对账", n.NodeID, n.StoreID))
	}
	n.Online = true
	n.LastSeen = time.Now()
	n.Usage = h.Usage
	if h.DataMarker != "" {
		n.DataMarker = h.DataMarker
	}
	for _, as := range h.Assignments {
		if a, ok := s.st.Assignments[as.ID]; ok && a.NodeID == h.NodeID {
			a.State = as.State
			a.ActualVersion = as.ActualVersion
			a.Restarts = as.Restarts
			a.Anomalies = as.Anomalies
			a.Reason = as.Reason
		}
	}
	s.addSamplesLocked(h.Metrics)
}

// MarkOffline flips nodes whose heartbeat is stale.
func (s *Store) MarkOffline(after time.Duration) {
	s.mu.Lock()
	changed := false
	for _, n := range s.st.Nodes {
		if n.Online && time.Since(n.LastSeen) > after {
			n.Online = false
			changed = true
			s.addEventLocked("node_offline", n.NodeID, n.StoreID,
				fmt.Sprintf("节点 %s (门店 %s) 离线, 按最后期望状态自治运行", n.NodeID, n.StoreID))
		}
	}
	s.mu.Unlock()
	if changed {
		s.changed()
	}
}

// DesiredFor returns the desired state for a node and its signature.
func (s *Store) DesiredFor(nodeID string) api.NodeDesired {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.desiredForLocked(nodeID)
}

func (s *Store) desiredForLocked(nodeID string) api.NodeDesired {
	var list []api.Assignment
	for _, a := range s.st.Assignments {
		if a.NodeID == nodeID {
			list = append(list, *a)
		}
	}
	sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
	return api.NodeDesired{Sig: s.st.NodeSig[nodeID], Assignments: list}
}

// WaitDesired blocks until the node's desired sig differs from clientSig or timeout.
func (s *Store) WaitDesired(nodeID, clientSig string, timeout time.Duration) api.NodeDesired {
	deadline := time.Now().Add(timeout)
	for {
		s.mu.Lock()
		d := s.desiredForLocked(nodeID)
		if d.Sig != clientSig {
			s.mu.Unlock()
			return d
		}
		ch := s.changeCh
		s.mu.Unlock()
		remain := time.Until(deadline)
		if remain <= 0 {
			return d
		}
		select {
		case <-ch:
		case <-time.After(remain):
			return s.DesiredFor(nodeID)
		}
	}
}

// PutWorkload creates or updates a workload spec.
func (s *Store) PutWorkload(spec api.WorkloadSpec) error {
	if spec.Name == "" || spec.Version == "" || spec.Replicas < 1 || len(spec.Cmd) == 0 {
		return fmt.Errorf("workload requires name, version, replicas>=1 and cmd")
	}
	s.mu.Lock()
	s.st.Workloads[spec.Name] = &spec
	s.addEventLocked("workload", "", "", fmt.Sprintf("工作负载 %s 更新到版本 %s (%d 副本)", spec.Name, spec.Version, spec.Replicas))
	s.dirty = true
	s.mu.Unlock()
	s.Reconcile()
	s.changed()
	return nil
}

func (s *Store) ListWorkloads() []api.WorkloadSpec {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []api.WorkloadSpec
	for _, w := range s.st.Workloads {
		out = append(out, *w)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (s *Store) ListNodes() []api.NodeView {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []api.NodeView
	for _, n := range s.st.Nodes {
		out = append(out, s.nodeViewLocked(n))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].StoreID < out[j].StoreID })
	return out
}

func (s *Store) nodeViewLocked(n *Node) api.NodeView {
	v := api.NodeView{
		NodeID: n.NodeID, StoreID: n.StoreID, Region: n.Region,
		Labels: n.Labels, Taints: n.Taints, Capacity: n.Capacity, Usage: n.Usage,
		Hours: n.Hours, Addr: n.Addr, AgentVersion: n.AgentVersion,
		Online: n.Online, Replaced: n.Replaced, LastSeen: n.LastSeen, DataMarker: n.DataMarker,
	}
	for _, a := range s.st.Assignments {
		if a.NodeID == n.NodeID {
			v.Assignments = append(v.Assignments, *a)
		}
	}
	sort.Slice(v.Assignments, func(i, j int) bool { return v.Assignments[i].ID < v.Assignments[j].ID })
	return v
}

func (s *Store) GetNode(nodeID string) (api.NodeView, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := s.st.Nodes[nodeID]
	if !ok {
		return api.NodeView{}, false
	}
	return s.nodeViewLocked(n), true
}

// Progress computes the per-workload "还差哪一步" view.
func (s *Store) Progress() []api.WorkloadProgress {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []api.WorkloadProgress
	for _, spec := range s.st.Workloads {
		p := api.WorkloadProgress{Spec: *spec}
		for _, a := range s.st.Assignments {
			if a.Workload != spec.Name {
				continue
			}
			p.DesiredTotal++
			if a.State == "Running" {
				p.Running++
			}
			if a.State == "Running" && a.ActualVersion == a.Version {
				p.Updated++
				continue
			}
			step := api.StepItem{StoreID: a.StoreID, AssignmentID: a.ID}
			n := s.st.Nodes[a.NodeID]
			switch {
			case n == nil || !n.Online:
				step.Step = "等待节点上线"
			case a.State == "Pending":
				step.Step = "等待节点确认"
			case a.State == "Starting":
				step.Step = "进程启动中"
			case a.State == "Running" && a.ActualVersion != a.Version:
				step.Step = "版本更新中"
			case a.State == "Failed":
				step.Step = "进程异常, 等待重启"
			default:
				step.Step = a.State
			}
			step.Reason = a.Reason
			p.Steps = append(p.Steps, step)
		}
		for _, pd := range s.st.Pending {
			if pd.Workload == spec.Name {
				p.Pending = append(p.Pending, pd)
				p.Steps = append(p.Steps, api.StepItem{
					StoreID: pd.StoreID, Step: "等待调度", Reason: pd.Reason,
				})
			}
		}
		sort.Slice(p.Steps, func(i, j int) bool { return p.Steps[i].AssignmentID < p.Steps[j].AssignmentID })
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Spec.Name < out[j].Spec.Name })
	return out
}

// PutQuota upserts a quota.
func (s *Store) PutQuota(q api.Quota) error {
	if q.Scope == "" {
		return fmt.Errorf("quota scope required")
	}
	s.mu.Lock()
	s.st.Quotas[q.Scope] = &q
	s.addEventLocked("quota", "", "", fmt.Sprintf("配额 %s 更新: cpu=%dm mem=%dMB replicas=%d", q.Scope, q.MaxCPUm, q.MaxMemMB, q.MaxReplicas))
	s.dirty = true
	s.mu.Unlock()
	s.Reconcile()
	s.changed()
	return nil
}

func (s *Store) ListQuotas() []api.Quota {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []api.Quota
	for _, q := range s.st.Quotas {
		out = append(out, *q)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Scope < out[j].Scope })
	return out
}

// Snapshot persists state if dirty.
func (s *Store) Snapshot() error {
	s.mu.Lock()
	if !s.dirty {
		s.mu.Unlock()
		return nil
	}
	st := s.st
	s.dirty = false
	s.mu.Unlock()
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.dataFile + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, s.dataFile)
}

// ForceDirty marks state for the next snapshot.
func (s *Store) ForceDirty() {
	s.mu.Lock()
	s.dirty = true
	s.mu.Unlock()
}
