package cp

import (
	"fmt"
	"sort"
	"time"

	"edgeops/internal/api"
)

// CreateRelease validates and registers a release order.
func (s *Store) CreateRelease(req api.CreateReleaseRequest) (*api.ReleaseOrder, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	spec, ok := s.st.Workloads[req.Workload]
	if !ok {
		return nil, fmt.Errorf("工作负载 %s 不存在", req.Workload)
	}
	if req.ToVersion == "" {
		return nil, fmt.Errorf("目标版本不能为空")
	}
	if req.ToVersion == spec.Version {
		return nil, fmt.Errorf("目标版本与当前版本相同")
	}
	for _, r := range s.st.Releases {
		if r.Workload == req.Workload && r.Status != "done" && r.Status != "failed" {
			return nil, fmt.Errorf("工作负载 %s 已有进行中的发布单 %s", req.Workload, r.ID)
		}
	}
	if req.CanaryCount < 1 {
		req.CanaryCount = 3
	}
	if req.CanaryDurationSec <= 0 {
		req.CanaryDurationSec = 24 * 3600 // 试点跑满一天
	}
	if req.BatchSize < 1 {
		req.BatchSize = 10
	}
	now := s.clk.Now()
	rel := &api.ReleaseOrder{
		ID:                fmt.Sprintf("rel-%d", now.UnixNano()),
		Workload:          req.Workload,
		ToVersion:         req.ToVersion,
		CanaryCount:       req.CanaryCount,
		CanaryDurationSec: req.CanaryDurationSec,
		BatchSize:         req.BatchSize,
		Status:            "canary_wait",
		CreatedAt:         now,
		UpdatedAt:         now,
		PhaseAt:           now,
	}
	s.st.Releases[rel.ID] = rel
	s.addEventLocked("release", "", "", fmt.Sprintf("发布单 %s 创建: %s -> %s (试点 %d 家, 浸泡 %ds)",
		rel.ID, req.Workload, req.ToVersion, rel.CanaryCount, rel.CanaryDurationSec))
	s.dirty = true
	return rel, nil
}

func (s *Store) ListReleases() []api.ReleaseOrder {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []api.ReleaseOrder
	for _, r := range s.st.Releases {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}

func (s *Store) GetRelease(id string) (api.ReleaseOrder, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.st.Releases[id]
	if !ok {
		return api.ReleaseOrder{}, false
	}
	return *r, true
}

// targetStoresLocked returns sorted store IDs the workload should run on.
func (s *Store) targetStoresLocked(spec *api.WorkloadSpec) []string {
	seen := map[string]bool{}
	var out []string
	for _, n := range s.st.Nodes {
		if n.Replaced || seen[n.StoreID] {
			continue
		}
		if matches(spec, n) {
			seen[n.StoreID] = true
			out = append(out, n.StoreID)
		}
	}
	sort.Strings(out)
	return out
}

func contains(ss []string, x string) bool {
	for _, s := range ss {
		if s == x {
			return true
		}
	}
	return false
}

// storeConvergedLocked: every assignment of the workload in the store is
// Running at the release target version.
func (s *Store) storeConvergedLocked(storeID, workload, version string) bool {
	found := false
	for _, a := range s.st.Assignments {
		if a.StoreID != storeID || a.Workload != workload {
			continue
		}
		found = true
		if a.State != "Running" || a.ActualVersion != version {
			return false
		}
	}
	return found
}

func (s *Store) storeHealthyLocked(storeID, workload string) bool {
	for _, a := range s.st.Assignments {
		if a.StoreID != storeID || a.Workload != workload {
			continue
		}
		n := s.st.Nodes[a.NodeID]
		if n == nil || !n.Online || a.State != "Running" || a.Anomalies > 0 {
			return false
		}
	}
	return true
}

func (s *Store) storeNodeLocked(storeID string) *Node {
	for _, n := range s.st.Nodes {
		if n.StoreID == storeID && !n.Replaced {
			return n
		}
	}
	return nil
}

// AdvanceReleases drives every active release one step. delta is the
// (clock-jump-clamped) elapsed time since the last tick.
func (s *Store) AdvanceReleases(now time.Time, delta time.Duration) {
	s.mu.Lock()
	changed := false
	for _, rel := range s.st.Releases {
		if rel.Status == "done" || rel.Status == "failed" {
			continue
		}
		if s.advanceLocked(rel, now, delta) {
			changed = true
		}
		rel.UpdatedAt = now
		s.dirty = true
	}
	s.mu.Unlock()
	if changed {
		s.Reconcile()
		s.changed()
	}
}

func (s *Store) advanceLocked(rel *api.ReleaseOrder, now time.Time, delta time.Duration) bool {
	spec, ok := s.st.Workloads[rel.Workload]
	if !ok {
		rel.Status = "failed"
		rel.Error = "工作负载已删除"
		return true
	}
	targets := s.targetStoresLocked(spec)
	if len(targets) == 0 {
		return false
	}
	hist := func(phase, store, detail string) {
		rel.History = append(rel.History, api.ReleaseEvent{Time: now, Phase: phase, StoreID: store, Detail: detail})
		s.addEventLocked("release", "", store, fmt.Sprintf("发布单 %s: %s", rel.ID, detail))
	}

	switch rel.Status {
	case "canary_wait":
		if len(rel.CanaryStores) == 0 {
			n := rel.CanaryCount
			if n > len(targets) {
				n = len(targets)
			}
			rel.CanaryStores = append([]string{}, targets[:n]...)
			for _, st := range rel.CanaryStores {
				s.st.Overrides[overrideKey(st, rel.Workload)] = rel.ToVersion
				rel.AppliedStores = append(rel.AppliedStores, st)
				rel.StoreUpdates = append(rel.StoreUpdates, api.StoreUpdate{StoreID: st, Time: now})
			}
			rel.PhaseAt = now
			hist("canary_start", "", fmt.Sprintf("试点开始: %v", rel.CanaryStores))
			return true
		}
		// wait for canary convergence (timeout: 1h clock time)
		converged := true
		for _, st := range rel.CanaryStores {
			if !s.storeConvergedLocked(st, rel.Workload, rel.ToVersion) {
				converged = false
				break
			}
		}
		if !converged {
			// 用累计 delta 而非时钟差值: 时钟跳变不会撑爆超时
			rel.WaitAccumSec += int64(delta.Seconds())
			if rel.WaitAccumSec > 3600 {
				rel.Status = "failed"
				rel.Error = "试点门店长时间未收敛"
				hist("failed", "", rel.Error)
				return true
			}
			return false
		}
		rel.WaitAccumSec = 0
		// soak: accumulate healthy time; any anomaly resets the window.
		healthy := true
		for _, st := range rel.CanaryStores {
			if !s.storeHealthyLocked(st, rel.Workload) {
				healthy = false
				break
			}
		}
		if healthy {
			rel.HealthyAccumSec += int64(delta.Seconds())
		} else if rel.HealthyAccumSec > 0 {
			rel.HealthyAccumSec = 0
			hist("canary_reset", "", "试点门店出现异常, 浸泡计时清零")
		}
		if rel.HealthyAccumSec >= rel.CanaryDurationSec {
			rel.Status = "rolling"
			rel.PhaseAt = now
			hist("canary_passed", "", fmt.Sprintf("试点跑满 %ds 收银流水无异常, 开始分批推送", rel.CanaryDurationSec))
			return true
		}
		return false

	case "rolling":
		inflight := 0
		done := 0
		changed := false
		for _, st := range targets {
			if contains(rel.CanaryStores, st) {
				done++
				continue
			}
			key := overrideKey(st, rel.Workload)
			if _, applied := s.st.Overrides[key]; !applied {
				if inflight >= rel.BatchSize {
					continue
				}
				node := s.storeNodeLocked(st)
				if node == nil {
					continue
				}
				// 错峰: 营业高峰时段不动这家店
				if node.Hours.InPeak(now) {
					continue
				}
				s.st.Overrides[key] = rel.ToVersion
				rel.AppliedStores = append(rel.AppliedStores, st)
				rel.StoreUpdates = append(rel.StoreUpdates, api.StoreUpdate{StoreID: st, Time: now})
				hist("store_update", st, fmt.Sprintf("门店 %s 推送版本 %s", st, rel.ToVersion))
				inflight++
				changed = true
			} else {
				if s.storeConvergedLocked(st, rel.Workload, rel.ToVersion) {
					done++
				} else {
					inflight++
				}
			}
		}
		if done == len(targets) {
			spec.Version = rel.ToVersion
			for _, st := range rel.AppliedStores {
				delete(s.st.Overrides, overrideKey(st, rel.Workload))
			}
			rel.Status = "done"
			hist("done", "", fmt.Sprintf("发布完成: %s 全量升级到 %s", rel.Workload, rel.ToVersion))
			return true
		}
		return changed
	}
	return false
}
