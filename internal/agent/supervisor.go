package agent

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"edgeops/internal/api"
	"edgeops/internal/clock"
)

// LaunchSpec tells an executor how to start one workload process.
type LaunchSpec struct {
	Assignment api.Assignment
	LogPath    string // rotating log file path
	DataDir    string // store data dir (survives host replacement)
}

// Process is a running workload instance.
type Process interface {
	Wait() error
	Kill() error
	Metrics() (cpuM, memMB int, txCount, anomalies int64)
}

// Executor starts workload processes. RealExecutor spawns OS child
// processes; SimExecutor runs in-process fakes for the simulator.
type Executor interface {
	Start(spec LaunchSpec) (Process, error)
}

type managed struct {
	spec       api.Assignment
	proc       Process
	state      string
	reason     string
	restarts   int
	backoff    time.Duration
	nextRetry  time.Time
	launchedAt time.Time
	done       chan error
	anomalies  int64
}

// Supervisor keeps the local process set converged to the desired
// assignment list, restarting crashed processes with backoff. It never
// talks to the control plane: offline autonomy lives here.
type Supervisor struct {
	ex      Executor
	clk     clock.Clock
	logDir  string
	dataDir string
	mu      sync.Mutex
	procs   map[string]*managed
	usage   api.Resources
}

func NewSupervisor(ex Executor, clk clock.Clock, logDir, dataDir string) *Supervisor {
	return &Supervisor{ex: ex, clk: clk, logDir: logDir, dataDir: dataDir, procs: map[string]*managed{}}
}

// Reconcile applies a new desired assignment list.
func (s *Supervisor) Reconcile(list []api.Assignment) {
	s.mu.Lock()
	defer s.mu.Unlock()
	want := map[string]api.Assignment{}
	for _, a := range list {
		want[a.ID] = a
	}
	for id, m := range s.procs {
		if _, ok := want[id]; !ok {
			s.stopLocked(id, m)
		}
	}
	for id, a := range want {
		if m, ok := s.procs[id]; ok {
			if m.spec.Version != a.Version || strings.Join(m.spec.Cmd, " ") != strings.Join(a.Cmd, " ") {
				s.stopLocked(id, m)
				s.startLocked(a)
			} else {
				m.spec = a
			}
			continue
		}
		s.startLocked(a)
	}
}

func (s *Supervisor) stopLocked(id string, m *managed) {
	m.state = "Stopping"
	if m.proc != nil {
		m.proc.Kill()
	}
	delete(s.procs, id)
}

func (s *Supervisor) startLocked(a api.Assignment) {
	m := &managed{spec: a, state: "Starting", backoff: time.Second}
	s.procs[a.ID] = m
	s.launchLocked(m)
}

func (s *Supervisor) launchLocked(m *managed) {
	spec := LaunchSpec{
		Assignment: m.spec,
		LogPath:    filepath.Join(s.logDir, sanitize(m.spec.ID)+".log"),
		DataDir:    s.dataDir,
	}
	p, err := s.ex.Start(spec)
	if err != nil {
		m.state = "Failed"
		m.reason = err.Error()
		m.proc = nil
		m.nextRetry = time.Now().Add(m.backoff)
		return
	}
	m.proc = p
	m.done = make(chan error, 1)
	m.launchedAt = time.Now()
	go func() { m.done <- p.Wait() }()
	m.state = "Running"
	m.reason = ""
}

// Run monitors process exits and restarts them with backoff.
func (s *Supervisor) Run(ctx context.Context) {
	t := time.NewTicker(300 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.check()
		}
	}
}

func (s *Supervisor) check() {
	s.mu.Lock()
	defer s.mu.Unlock()
	var usage api.Resources
	for _, m := range s.procs {
		if m.proc != nil {
			// 稳定运行 30 秒后重置退避
			if m.backoff > time.Second && time.Since(m.launchedAt) > 30*time.Second {
				m.backoff = time.Second
			}
			cpu, mem, _, an := m.proc.Metrics()
			usage = usage.Add(api.Resources{CPUm: cpu, MemMB: mem})
			m.anomalies = an
			select {
			case err := <-m.done:
				m.proc = nil
				m.restarts++
				m.state = "Failed"
				if err != nil {
					m.reason = fmt.Sprintf("进程退出: %v", err)
				} else {
					m.reason = "进程退出"
				}
				m.nextRetry = time.Now().Add(m.backoff)
			default:
			}
			continue
		}
		if m.state == "Failed" && !m.nextRetry.IsZero() && time.Now().After(m.nextRetry) {
			m.backoff *= 2
			if m.backoff > 10*time.Second {
				m.backoff = 10 * time.Second
			}
			s.launchLocked(m)
		}
	}
	s.usage = usage
}

func (s *Supervisor) Statuses() []api.AssignmentStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []api.AssignmentStatus
	for id, m := range s.procs {
		out = append(out, api.AssignmentStatus{
			ID: id, State: m.state, ActualVersion: m.spec.Version,
			Restarts: m.restarts, Anomalies: m.anomalies, Reason: m.reason,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (s *Supervisor) Metrics(nodeID, storeID string) []api.MetricSample {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []api.MetricSample
	for _, m := range s.procs {
		if m.proc == nil || m.state != "Running" {
			continue
		}
		cpu, mem, tx, an := m.proc.Metrics()
		out = append(out, api.MetricSample{
			Time: time.Now(), NodeID: nodeID, StoreID: storeID,
			Workload: m.spec.Workload, CPUm: cpu, MemMB: mem,
			TxCount: tx, Anomalies: an,
		})
	}
	return out
}

func (s *Supervisor) Usage() api.Resources {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.usage
}

// Kill terminates one workload process (fault injection / 杀进程).
func (s *Supervisor) Kill(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if m, ok := s.procs[id]; ok && m.proc != nil {
		m.proc.Kill()
		return true
	}
	return false
}

func (s *Supervisor) IDs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for id := range s.procs {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

func (s *Supervisor) StopAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, m := range s.procs {
		s.stopLocked(id, m)
	}
}

func sanitize(id string) string {
	return strings.NewReplacer(":", "_", "/", "_").Replace(id)
}
