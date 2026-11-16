// Package sim runs the chaos simulator: hundreds of in-process node
// agents behind a fault-injecting network, with random disconnects,
// process kills and clock jumps, plus a mid-release control-plane
// restart and a host replacement.
package sim

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"sync"
	"time"

	"edgeops/internal/agent"
	"edgeops/internal/api"
	"edgeops/internal/check"
	"edgeops/internal/clock"
	"edgeops/internal/cp"
)

type Config struct {
	Stores     int
	CPAddr     string
	ClockScale float64
	CanarySec  int64
	BatchSize  int
	DataDir    string
}

// faultNet simulates the flaky store network.
type faultNet struct {
	mu   sync.Mutex
	down map[string]bool
}

func newFaultNet() *faultNet { return &faultNet{down: map[string]bool{}} }

func (f *faultNet) set(key string, down bool) {
	f.mu.Lock()
	f.down[key] = down
	f.mu.Unlock()
}

func (f *faultNet) isDown(key string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.down[key]
}

type transport struct {
	net *faultNet
	key string
}

func (t transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.net.isDown(t.key) {
		return nil, errors.New("simulated network outage")
	}
	return http.DefaultTransport.RoundTrip(req)
}

// proxyTransport keys the control-plane -> agent direction by target host.
type proxyTransport struct{ net *faultNet }

func (t proxyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.net.isDown(req.URL.Host) {
		return nil, errors.New("simulated network outage")
	}
	return http.DefaultTransport.RoundTrip(req)
}

type simNode struct {
	storeID string
	agent   *agent.Agent
	cancel  context.CancelFunc
	addr    string
}

func post(base, path string, body, out any) error {
	b, _ := json.Marshal(body)
	resp, err := http.Post(base+path, "application/json", bytes.NewReader(b))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func getJSON(base, path string, out any) error {
	resp, err := http.Get(base + path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return json.NewDecoder(resp.Body).Decode(out)
}

func logf(format string, args ...any) {
	fmt.Printf("[%s] %s\n", time.Now().Format("15:04:05"), fmt.Sprintf(format, args...))
}

// Run executes the whole scenario and returns the check results.
func Run(cfg Config) ([]check.Result, error) {
	if cfg.Stores == 0 {
		cfg.Stores = 300
	}
	if cfg.ClockScale == 0 {
		cfg.ClockScale = 120
	}
	if cfg.CanarySec == 0 {
		cfg.CanarySec = 3600
	}
	if cfg.BatchSize == 0 {
		cfg.BatchSize = 40
	}
	base := "http://" + cfg.CPAddr
	now := time.Now()
	clk := clock.NewSim(time.Date(now.Year(), now.Month(), now.Day(), 8, 0, 0, 0, time.Local), cfg.ClockScale)
	net := newFaultNet()
	regions := []string{"华东", "华北", "华南"}

	startCP := func() (*cp.Server, error) {
		srv, err := cp.NewServer(cp.Config{
			Addr: cfg.CPAddr, DataDir: cfg.DataDir + "/cp",
			NodeOfflineAfter: 4 * time.Second,
			ProxyTransport:   proxyTransport{net},
		}, clk)
		if err != nil {
			return nil, err
		}
		return srv, srv.Start()
	}
	srv, err := startCP()
	if err != nil {
		return nil, err
	}
	logf("控制面启动于 %s (模拟时钟 %dx)", cfg.CPAddr, int(cfg.ClockScale))

	// ---- declare workloads & quotas ----
	must := func(err error) {
		if err != nil {
			logf("配置失败: %v", err)
		}
	}
	must(post(base, "/api/workloads", api.WorkloadSpec{
		Name: "cashier", Version: "1.0.0", Replicas: 2, Cmd: []string{"workload"},
		Request: api.Resources{CPUm: 100, MemMB: 128},
	}, nil))
	must(post(base, "/api/workloads", api.WorkloadSpec{
		Name: "rx-review", Version: "1.0.0", Replicas: 2, Cmd: []string{"workload"},
		Request: api.Resources{CPUm: 200, MemMB: 256}, AntiAffinity: true,
	}, nil))
	must(post(base, "/api/workloads", api.WorkloadSpec{
		Name: "insurance", Version: "1.0.0", Replicas: 1, Cmd: []string{"workload"},
		Request:      api.Resources{CPUm: 150, MemMB: 192},
		NodeSelector: map[string]string{"network": "dedicated-line"},
	}, nil))
	// 配额演示: S0007 限额 150m, 放不下第二个 cashier 副本
	must(post(base, "/api/quotas", api.Quota{Scope: "store:S0007", MaxCPUm: 150}, nil))
	must(post(base, "/api/quotas", api.Quota{Scope: "region:华北", MaxReplicas: 10000}, nil))

	// ---- start node agents ----
	var mu sync.Mutex
	nodes := map[string]*simNode{} // storeID -> node
	portSeq := 20000
	hostSeq := 0
	startAgent := func(i int) *simNode {
		storeID := fmt.Sprintf("S%04d", i+1)
		region := regions[i%3]
		labels := map[string]string{"region": region}
		if i%10 < 3 { // 30% 门店有医保专线
			labels["network"] = "dedicated-line"
		}
		var taints []string
		if i%97 == 96 { // 个别门店装修中
			taints = append(taints, "maintenance")
		}
		peakStart, peakEnd := "10:00", "12:00"
		if i%3 != 0 {
			peakStart, peakEnd = "14:00", "16:00"
		}
		mu.Lock()
		portSeq++
		hostSeq++
		addr := fmt.Sprintf("127.0.0.1:%d", portSeq)
		hostDir := fmt.Sprintf("%s/hosts/%s-%d", cfg.DataDir, storeID, hostSeq)
		mu.Unlock()
		a := agent.New(agent.Config{
			StoreID: storeID, Region: region, Labels: labels, Taints: taints,
			Capacity: api.Resources{CPUm: 2000, MemMB: 4096},
			Hours: api.BusinessHours{
				Open: "08:00", Close: "22:00", PeakStart: peakStart, PeakEnd: peakEnd,
			},
			CPAddr: cfg.CPAddr, ListenAddr: addr,
			DataDir:      hostDir,                                                     // 主机本地目录: 换机即丢
			StoreDataDir: fmt.Sprintf("%s/stores/%s/storedata", cfg.DataDir, storeID), // 数据盘随门店走
			Executor:     &agent.SimExecutor{},
			Client:       &http.Client{Timeout: 30 * time.Second, Transport: transport{net, storeID}},
			Clock:        clk, HeartbeatInterval: 700 * time.Millisecond,
		})
		ctx, cancel := context.WithCancel(context.Background())
		sn := &simNode{storeID: storeID, agent: a, cancel: cancel, addr: addr}
		go a.Run(ctx)
		mu.Lock()
		nodes[storeID] = sn
		mu.Unlock()
		return sn
	}
	for i := 0; i < cfg.Stores; i++ {
		startAgent(i)
	}
	logf("%d 个节点代理已启动", cfg.Stores)

	// ---- fault injectors (started after initial convergence) ----
	stopFaults := make(chan struct{})
	startFaults := func() {
		go func() { // 随机断网
			for {
				select {
				case <-stopFaults:
					return
				case <-time.After(300 * time.Millisecond):
				}
				mu.Lock()
				for _, sn := range nodes {
					if rand.Intn(1000) < 10 { // 约 6% 时间处于断网
						net.set(sn.storeID, true)
						net.set(sn.addr, true)
						sn := sn
						time.AfterFunc(time.Duration(1+rand.Intn(3))*time.Second, func() {
							net.set(sn.storeID, false)
							net.set(sn.addr, false)
						})
					}
				}
				mu.Unlock()
			}
		}()
		go func() { // 随机杀进程
			for {
				select {
				case <-stopFaults:
					return
				case <-time.After(500 * time.Millisecond):
				}
				mu.Lock()
				for _, sn := range nodes {
					if rand.Intn(1000) < 5 {
						if ids := sn.agent.RunningIDs(); len(ids) > 0 {
							sn.agent.KillProcess(ids[rand.Intn(len(ids))])
						}
					}
				}
				mu.Unlock()
			}
		}()
		go func() { // 时钟跳变
			for {
				select {
				case <-stopFaults:
					return
				case <-time.After(7 * time.Second):
				}
				if rand.Intn(2) == 0 {
					clk.Jump(20 * time.Minute)
				} else {
					clk.Jump(-10 * time.Minute)
				}
				logf("⚡ 时钟跳变, 当前模拟时间 %s", clk.Now().Format("15:04"))
			}
		}()
	}

	waitConverged := func(timeout time.Duration) bool {
		deadline := time.Now().Add(timeout)
		for time.Now().Before(deadline) {
			r := check.Convergence(base)
			if r.OK {
				return true
			}
			time.Sleep(time.Second)
		}
		return false
	}

	if !waitConverged(90 * time.Second) {
		return nil, fmt.Errorf("初始收敛超时")
	}
	logf("初始状态已收敛, 开始注入故障 (断网/杀进程/时钟跳变)")
	startFaults()

	// ---- create release: cashier 1.0.0 -> 2.0.0 ----
	var rel api.ReleaseOrder
	must(post(base, "/api/releases", api.CreateReleaseRequest{
		Workload: "cashier", ToVersion: "2.0.0",
		CanaryCount: 5, CanaryDurationSec: cfg.CanarySec, BatchSize: cfg.BatchSize,
	}, &rel))
	logf("发布单 %s 创建: cashier -> 2.0.0 (试点 5 家, 浸泡 %d 模拟秒)", rel.ID, cfg.CanarySec)

	// ---- mid-release: restart control plane + replace a host ----
	victim := "S0042"
	var victimMarker string
	restarted := false
	replacedHost := false
	done := false
	deadline := time.Now().Add(8 * time.Minute)
	for time.Now().Before(deadline) {
		var cur api.ReleaseOrder
		if err := getJSON(base, "/api/releases/"+rel.ID, &cur); err == nil {
			if cur.Status == "rolling" && !restarted {
				logf("发布进入全量阶段, 模拟控制面宕机重启 (发布中断)...")
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				srv.Shutdown(ctx)
				cancel()
				time.Sleep(300 * time.Millisecond)
				if srv, err = startCP(); err != nil {
					return nil, err
				}
				restarted = true
				logf("控制面已重启, 发布单从持久化状态恢复")
			}
			if cur.Status == "rolling" && restarted && !replacedHost {
				var ns []api.NodeView
				if getJSON(base, "/api/nodes", &ns) == nil {
					for _, n := range ns {
						if n.StoreID == victim && !n.Replaced {
							victimMarker = n.DataMarker
						}
					}
				}
				mu.Lock()
				old := nodes[victim]
				mu.Unlock()
				if old != nil {
					logf("门店 %s 更换主机 (数据盘保留)", victim)
					old.cancel()
					mu.Lock()
					delete(nodes, victim)
					mu.Unlock()
					time.Sleep(500 * time.Millisecond)
					sn := startAgent(41) // 同门店编号, 同数据目录, 新节点
					_ = sn
					replacedHost = true
				}
			}
			if cur.Status == "done" {
				done = true
				break
			}
			if cur.Status == "failed" {
				return nil, fmt.Errorf("发布失败: %s", cur.Error)
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	if !done {
		return nil, fmt.Errorf("发布超时未完成")
	}
	logf("发布完成, 等待最终收敛...")
	close(stopFaults)
	// 恢复所有网络, 等收敛
	mu.Lock()
	for _, sn := range nodes {
		net.set(sn.storeID, false)
		net.set(sn.addr, false)
	}
	mu.Unlock()
	if !waitConverged(60 * time.Second) {
		logf("警告: 最终收敛超时, 仍执行检查")
	}

	// ---- checks ----
	results := []check.Result{
		check.Convergence(base),
		check.ReleaseRules(base),
		check.Handover(base, victim, victimMarker, map[string]int{"cashier": 2, "rx-review": 1}),
	}
	return results, nil
}
