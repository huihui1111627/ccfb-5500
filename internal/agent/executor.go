package agent

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"time"
)

// ---------- RealExecutor: workloads are local child processes ----------

type RealExecutor struct{}

type realProc struct {
	cmd  *exec.Cmd
	port int
}

func (RealExecutor) Start(spec LaunchSpec) (Process, error) {
	if len(spec.Assignment.Cmd) == 0 {
		return nil, fmt.Errorf("empty cmd")
	}
	port, err := freePort()
	if err != nil {
		return nil, err
	}
	w, err := NewRotatingWriter(spec.LogPath, 1<<20, 3)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(spec.Assignment.Cmd[0], spec.Assignment.Cmd[1:]...)
	cmd.Stdout, cmd.Stderr = w, w
	env := os.Environ()
	for k, v := range spec.Assignment.Env {
		env = append(env, k+"="+v)
	}
	env = append(env,
		"EDGE_ASSIGNMENT_ID="+spec.Assignment.ID,
		"EDGE_WORKLOAD="+spec.Assignment.Workload,
		"EDGE_VERSION="+spec.Assignment.Version,
		"EDGE_PORT="+fmt.Sprint(port),
		"EDGE_DATA_DIR="+spec.DataDir,
	)
	cmd.Env = env
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return &realProc{cmd: cmd, port: port}, nil
}

func (p *realProc) Wait() error { return p.cmd.Wait() }

func (p *realProc) Kill() error {
	if p.cmd.Process != nil {
		return p.cmd.Process.Kill()
	}
	return nil
}

func (p *realProc) Metrics() (int, int, int64, int64) {
	type m struct {
		CPUm      int   `json:"cpu_m"`
		MemMB     int   `json:"mem_mb"`
		TxCount   int64 `json:"tx_count"`
		Anomalies int64 `json:"anomalies"`
	}
	c := &http.Client{Timeout: 300 * time.Millisecond}
	resp, err := c.Get(fmt.Sprintf("http://127.0.0.1:%d/metrics", p.port))
	if err != nil {
		return 0, 0, 0, 0
	}
	defer resp.Body.Close()
	var mm m
	json.NewDecoder(resp.Body).Decode(&mm)
	return mm.CPUm, mm.MemMB, mm.TxCount, mm.Anomalies
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// ---------- SimExecutor: in-process fake processes for the simulator ----------

type SimExecutor struct {
	AnomalyStores map[string]bool // stores whose workloads report anomalies
}

type simProc struct {
	spec      LaunchSpec
	log       *RotatingWriter
	done      chan error
	kill      chan struct{}
	closeOnce atomic.Bool
	cpu       atomic.Int64
	mem       atomic.Int64
	tx        atomic.Int64
	anomalies atomic.Int64
	anomaly   bool
}

func (e *SimExecutor) Start(spec LaunchSpec) (Process, error) {
	w, err := NewRotatingWriter(spec.LogPath, 64*1024, 3)
	if err != nil {
		return nil, err
	}
	p := &simProc{
		spec: spec, log: w,
		done: make(chan error, 1), kill: make(chan struct{}),
		anomaly: e.AnomalyStores[spec.Assignment.StoreID],
	}
	req := spec.Assignment.Request
	p.cpu.Store(int64(req.CPUm) * 4 / 10)
	p.mem.Store(int64(req.MemMB) * 5 / 10)
	// local data continuity: create/append the store data marker
	marker := filepath.Join(spec.DataDir, "marker.txt")
	if _, err := os.Stat(marker); os.IsNotExist(err) {
		os.WriteFile(marker, []byte(fmt.Sprintf("store=%s created\n", spec.Assignment.StoreID)), 0o644)
	}
	f, _ := os.OpenFile(marker, os.O_APPEND|os.O_WRONLY, 0o644)
	if f != nil {
		fmt.Fprintf(f, "start workload=%s version=%s assignment=%s\n",
			spec.Assignment.Workload, spec.Assignment.Version, spec.Assignment.ID)
		f.Close()
	}
	go p.run()
	return p, nil
}

func (p *simProc) run() {
	t := time.NewTicker(150 * time.Millisecond)
	defer t.Stop()
	seq := 0
	for {
		select {
		case <-p.kill:
			p.done <- fmt.Errorf("killed")
			return
		case <-t.C:
			seq++
			p.tx.Add(1)
			// random walk around the request size
			req := p.spec.Assignment.Request
			cpu := int64(req.CPUm)*3/10 + int64(rand.Intn(max(req.CPUm/2, 10)))
			mem := int64(req.MemMB)*4/10 + int64(rand.Intn(max(req.MemMB/4, 8)))
			p.cpu.Store(cpu)
			p.mem.Store(mem)
			if p.anomaly && seq%20 == 0 {
				p.anomalies.Add(1)
			}
			fmt.Fprintf(p.log, "%s tx store=%s workload=%s v=%s seq=%d amount=%d.%02d\n",
				time.Now().Format("15:04:05.000"), p.spec.Assignment.StoreID,
				p.spec.Assignment.Workload, p.spec.Assignment.Version,
				seq, rand.Intn(500)+1, rand.Intn(100))
		}
	}
}

func (p *simProc) Wait() error { return <-p.done }

func (p *simProc) Kill() error {
	if p.closeOnce.CompareAndSwap(false, true) {
		close(p.kill)
	}
	return nil
}

func (p *simProc) Metrics() (int, int, int64, int64) {
	return int(p.cpu.Load()), int(p.mem.Load()), p.tx.Load(), p.anomalies.Load()
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
