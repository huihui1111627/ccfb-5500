// Package check verifies platform invariants through the control-plane API:
// convergence after interrupted releases, load handover after host
// replacement, and canary/peak-hour release rules.
package check

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"edgeops/internal/api"
)

type Result struct {
	Name   string
	OK     bool
	Detail string
}

func get(base, path string, v any) error {
	c := &http.Client{Timeout: 5 * time.Second}
	resp, err := c.Get(base + path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("%s -> %d", path, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(v)
}

// Convergence: every workload fully converged, ignoring pendings that are
// intentional (anti-affinity, quota demonstrations).
func Convergence(base string) Result {
	var prog []api.WorkloadProgress
	if err := get(base, "/api/workloads/progress", &prog); err != nil {
		return Result{"状态收敛", false, err.Error()}
	}
	var problems []string
	totalDesired := 0
	for _, p := range prog {
		totalDesired += p.DesiredTotal
		for _, s := range p.Steps {
			if strings.Contains(s.Reason, "反亲和") || strings.Contains(s.Reason, "配额") {
				continue // 预期内的不可调度
			}
			problems = append(problems, fmt.Sprintf("%s/%s: %s %s", p.Spec.Name, s.StoreID, s.Step, s.Reason))
		}
	}
	if len(problems) > 0 {
		if len(problems) > 5 {
			problems = append(problems[:5], fmt.Sprintf("... 共 %d 项", len(problems)))
		}
		return Result{"状态收敛", false, strings.Join(problems, "; ")}
	}
	if totalDesired == 0 {
		return Result{"状态收敛", false, "控制面还没有任何负载"}
	}
	total := 0
	for _, p := range prog {
		total += p.Updated
	}
	return Result{"状态收敛", true, fmt.Sprintf("全部工作负载已收敛 (%d 个副本运行中)", total)}
}

// ReleaseRules: canary gate was not bypassed and no store was touched
// during its peak business hours.
func ReleaseRules(base string) Result {
	var rels []api.ReleaseOrder
	if err := get(base, "/api/releases", &rels); err != nil {
		return Result{"发布规则", false, err.Error()}
	}
	var nodes []api.NodeView
	if err := get(base, "/api/nodes", &nodes); err != nil {
		return Result{"发布规则", false, err.Error()}
	}
	hours := map[string]api.BusinessHours{}
	for _, n := range nodes {
		if _, ok := hours[n.StoreID]; !ok {
			hours[n.StoreID] = n.Hours
		}
	}
	var problems []string
	for _, r := range rels {
		if r.Status == "failed" {
			problems = append(problems, fmt.Sprintf("%s 发布失败: %s", r.ID, r.Error))
			continue
		}
		if len(r.CanaryStores) != r.CanaryCount && r.Status != "canary_wait" {
			problems = append(problems, fmt.Sprintf("%s 试点门店数 %d != 要求 %d", r.ID, len(r.CanaryStores), r.CanaryCount))
		}
		var canaryPassedAt time.Time
		for _, h := range r.History {
			if h.Phase == "canary_passed" {
				canaryPassedAt = h.Time
			}
		}
		if r.Status == "rolling" || r.Status == "done" {
			if canaryPassedAt.IsZero() {
				problems = append(problems, fmt.Sprintf("%s 未通过试点就进入全量", r.ID))
			}
		}
		for _, su := range r.StoreUpdates {
			isCanary := false
			for _, c := range r.CanaryStores {
				if c == su.StoreID {
					isCanary = true
				}
			}
			if !isCanary && !canaryPassedAt.IsZero() && su.Time.Before(canaryPassedAt) {
				problems = append(problems, fmt.Sprintf("%s 门店 %s 在试点通过前被推送", r.ID, su.StoreID))
			}
			if h, ok := hours[su.StoreID]; ok && h.InPeak(su.Time) {
				problems = append(problems, fmt.Sprintf("%s 门店 %s 在营业高峰 %s 被推送",
					r.ID, su.StoreID, su.Time.Format("15:04")))
			}
		}
	}
	if len(problems) > 0 {
		return Result{"发布规则", false, strings.Join(problems, "; ")}
	}
	done := 0
	for _, r := range rels {
		if r.Status == "done" {
			done++
		}
	}
	return Result{"发布规则", true, fmt.Sprintf("%d 个发布单全部完成, 试点/错峰规则未被绕过", done)}
}

// Handover: after host replacement the new node runs every expected
// workload and the store's local data survived.
func Handover(base, storeID, expectMarker string, expect map[string]int) Result {
	var nodes []api.NodeView
	if err := get(base, "/api/nodes", &nodes); err != nil {
		return Result{"换机接手", false, err.Error()}
	}
	var cur *api.NodeView
	replaced := 0
	for i := range nodes {
		if nodes[i].StoreID != storeID {
			continue
		}
		if nodes[i].Replaced {
			replaced++
			continue
		}
		cur = &nodes[i]
	}
	if cur == nil {
		return Result{"换机接手", false, "门店 " + storeID + " 没有存活节点"}
	}
	if replaced == 0 {
		return Result{"换机接手", false, "旧节点未被标记更换"}
	}
	if !cur.Online {
		return Result{"换机接手", false, "新节点不在线"}
	}
	running := map[string]int{}
	for _, a := range cur.Assignments {
		if a.State == "Running" {
			running[a.Workload]++
		}
	}
	var missing []string
	for w, n := range expect {
		if running[w] < n {
			missing = append(missing, fmt.Sprintf("%s(%d/%d)", w, running[w], n))
		}
	}
	if len(missing) > 0 {
		return Result{"换机接手", false, "新节点缺少负载: " + strings.Join(missing, ",")}
	}
	if expectMarker != "" && cur.DataMarker != expectMarker {
		return Result{"换机接手", false, fmt.Sprintf("本地数据标记不一致: %q != %q", cur.DataMarker, expectMarker)}
	}
	return Result{"换机接手", true, fmt.Sprintf("门店 %s 新节点 %s 已接手全部负载, 本地数据完整", storeID, cur.NodeID[:12])}
}
