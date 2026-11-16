// Package api defines the wire types shared by control plane, agent and console.
package api

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Resources describes cpu (millicores) and memory (MB).
type Resources struct {
	CPUm  int `json:"cpu_m"`
	MemMB int `json:"mem_mb"`
}

func (r Resources) Add(o Resources) Resources {
	return Resources{CPUm: r.CPUm + o.CPUm, MemMB: r.MemMB + o.MemMB}
}

func (r Resources) FitsIn(cap Resources) bool {
	return r.CPUm <= cap.CPUm && r.MemMB <= cap.MemMB
}

func (r Resources) String() string { return fmt.Sprintf("%dm/%dMB", r.CPUm, r.MemMB) }

// BusinessHours of a store, "HH:MM" 24h local time.
type BusinessHours struct {
	Open      string `json:"open"`
	Close     string `json:"close"`
	PeakStart string `json:"peak_start"`
	PeakEnd   string `json:"peak_end"`
}

func ParseHM(s string) (int, error) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return 0, fmt.Errorf("invalid HH:MM %q", s)
	}
	h, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, err
	}
	m, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, err
	}
	if h < 0 || h > 23 || m < 0 || m > 59 {
		return 0, fmt.Errorf("invalid HH:MM %q", s)
	}
	return h*60 + m, nil
}

// InPeak reports whether t falls into the store's peak business window.
func (b BusinessHours) InPeak(t time.Time) bool {
	if b.PeakStart == "" || b.PeakEnd == "" {
		return false
	}
	ps, err1 := ParseHM(b.PeakStart)
	pe, err2 := ParseHM(b.PeakEnd)
	if err1 != nil || err2 != nil {
		return false
	}
	m := t.Hour()*60 + t.Minute()
	if ps <= pe {
		return m >= ps && m < pe
	}
	return m >= ps || m < pe // overnight window
}

// WorkloadSpec is the declarative description of a service.
type WorkloadSpec struct {
	Name         string            `json:"name"`
	Version      string            `json:"version"`
	Replicas     int               `json:"replicas"`
	Cmd          []string          `json:"cmd"`
	Env          map[string]string `json:"env,omitempty"`
	Request      Resources         `json:"request"`
	NodeSelector map[string]string `json:"node_selector,omitempty"`
	Tolerations  []string          `json:"tolerations,omitempty"`
	AntiAffinity bool              `json:"anti_affinity"` // at most one replica per node
}

// Assignment is one replica placed on one node.
type Assignment struct {
	ID            string            `json:"id"` // <workload>:<storeID>:<index>
	Workload      string            `json:"workload"`
	StoreID       string            `json:"store_id"`
	NodeID        string            `json:"node_id"`
	Index         int               `json:"index"`
	Version       string            `json:"version"` // desired version
	ActualVersion string            `json:"actual_version"`
	Cmd           []string          `json:"cmd"`
	Env           map[string]string `json:"env,omitempty"`
	Request       Resources         `json:"request"`
	State         string            `json:"state"` // Pending/Starting/Running/Stopping/Stopped/Failed
	Restarts      int               `json:"restarts"`
	Anomalies     int64             `json:"anomalies"`
	Reason        string            `json:"reason,omitempty"`
}

type RegisterRequest struct {
	NodeID       string            `json:"node_id"`
	StoreID      string            `json:"store_id"`
	Region       string            `json:"region"`
	Labels       map[string]string `json:"labels"`
	Taints       []string          `json:"taints"`
	Capacity     Resources         `json:"capacity"`
	Hours        BusinessHours     `json:"hours"`
	Addr         string            `json:"addr"` // agent http addr for log proxy
	AgentVersion string            `json:"agent_version"`
}

type AssignmentStatus struct {
	ID            string `json:"id"`
	State         string `json:"state"`
	ActualVersion string `json:"actual_version"`
	Restarts      int    `json:"restarts"`
	Anomalies     int64  `json:"anomalies"`
	Reason        string `json:"reason,omitempty"`
}

type MetricSample struct {
	Time      time.Time `json:"time"`
	NodeID    string    `json:"node_id"`
	StoreID   string    `json:"store_id"`
	Workload  string    `json:"workload"`
	CPUm      int       `json:"cpu_m"`
	MemMB     int       `json:"mem_mb"`
	TxCount   int64     `json:"tx_count"`
	Anomalies int64     `json:"anomalies"`
}

type Heartbeat struct {
	NodeID      string             `json:"node_id"`
	Usage       Resources          `json:"usage"`
	DataMarker  string             `json:"data_marker"`
	Assignments []AssignmentStatus `json:"assignments"`
	Metrics     []MetricSample     `json:"metrics"`
}

// NodeDesired is the desired state pushed to one node agent.
type NodeDesired struct {
	Sig         string       `json:"sig"`
	Assignments []Assignment `json:"assignments"`
}

type NodeView struct {
	NodeID       string            `json:"node_id"`
	StoreID      string            `json:"store_id"`
	Region       string            `json:"region"`
	Labels       map[string]string `json:"labels"`
	Taints       []string          `json:"taints"`
	Capacity     Resources         `json:"capacity"`
	Usage        Resources         `json:"usage"`
	Hours        BusinessHours     `json:"hours"`
	Addr         string            `json:"addr"`
	AgentVersion string            `json:"agent_version"`
	Online       bool              `json:"online"`
	Replaced     bool              `json:"replaced"`
	LastSeen     time.Time         `json:"last_seen"`
	DataMarker   string            `json:"data_marker"`
	Assignments  []Assignment      `json:"assignments"`
}

type PendingItem struct {
	Workload string `json:"workload"`
	StoreID  string `json:"store_id"`
	Reason   string `json:"reason"`
}

type StepItem struct {
	StoreID      string `json:"store_id"`
	AssignmentID string `json:"assignment_id"`
	Step         string `json:"step"`
	Reason       string `json:"reason,omitempty"`
}

// WorkloadProgress powers the console "还差哪一步" view.
type WorkloadProgress struct {
	Spec         WorkloadSpec  `json:"spec"`
	DesiredTotal int           `json:"desired_total"`
	Running      int           `json:"running"`
	Updated      int           `json:"updated"`
	Pending      []PendingItem `json:"pending"`
	Steps        []StepItem    `json:"steps"`
}

type ReleaseEvent struct {
	Time    time.Time `json:"time"`
	Phase   string    `json:"phase"`
	StoreID string    `json:"store_id,omitempty"`
	Detail  string    `json:"detail"`
}

type StoreUpdate struct {
	StoreID string    `json:"store_id"`
	Time    time.Time `json:"time"`
}

// ReleaseOrder is a 发布单. State is persisted so a control-plane
// restart mid-release resumes exactly where it stopped.
type ReleaseOrder struct {
	ID                string         `json:"id"`
	Workload          string         `json:"workload"`
	ToVersion         string         `json:"to_version"`
	CanaryCount       int            `json:"canary_count"`
	CanaryDurationSec int64          `json:"canary_duration_sec"`
	BatchSize         int            `json:"batch_size"`
	Status            string         `json:"status"` // canary_wait / rolling / done / failed
	CanaryStores      []string       `json:"canary_stores"`
	AppliedStores     []string       `json:"applied_stores"`
	HealthyAccumSec   int64          `json:"healthy_accum_sec"`
	WaitAccumSec      int64          `json:"wait_accum_sec"`
	PhaseAt           time.Time      `json:"phase_at"`
	History           []ReleaseEvent `json:"history"`
	StoreUpdates      []StoreUpdate  `json:"store_updates"`
	CreatedAt         time.Time      `json:"created_at"`
	UpdatedAt         time.Time      `json:"updated_at"`
	Error             string         `json:"error,omitempty"`
}

type Event struct {
	ID      int64     `json:"id"`
	Time    time.Time `json:"time"`
	Type    string    `json:"type"`
	NodeID  string    `json:"node_id,omitempty"`
	StoreID string    `json:"store_id,omitempty"`
	Message string    `json:"message"`
}

// Quota scopes: "global", "region:<name>", "store:<id>". Zero means unlimited.
type Quota struct {
	Scope       string `json:"scope"`
	MaxCPUm     int    `json:"max_cpu_m"`
	MaxMemMB    int    `json:"max_mem_mb"`
	MaxReplicas int    `json:"max_replicas"`
}

type Recommendation struct {
	Workload       string    `json:"workload"`
	CurrentRequest Resources `json:"current_request"`
	P95            Resources `json:"p95"`
	Suggested      Resources `json:"suggested"`
	Samples        int       `json:"samples"`
}

type CreateReleaseRequest struct {
	Workload          string `json:"workload"`
	ToVersion         string `json:"to_version"`
	CanaryCount       int    `json:"canary_count"`
	CanaryDurationSec int64  `json:"canary_duration_sec"`
	BatchSize         int    `json:"batch_size"`
}
