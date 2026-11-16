package cp

import (
	"fmt"
	"sort"
	"strings"

	"edgeops/internal/api"
)

// matches reports whether the workload may run on the node:
// label selector (affinity) plus taint/toleration.
func matches(spec *api.WorkloadSpec, n *Node) bool {
	for k, v := range spec.NodeSelector {
		if n.Labels[k] != v {
			return false
		}
	}
	for _, t := range n.Taints {
		tolerated := false
		for _, tol := range spec.Tolerations {
			if tol == t {
				tolerated = true
				break
			}
		}
		if !tolerated {
			return false
		}
	}
	return true
}

func overrideKey(storeID, workload string) string { return storeID + "|" + workload }

// Reconcile recomputes the desired assignment set for every node and
// converges stored assignments toward it. It is the declarative core:
// desired state (specs + overrides) vs actual state (reported by agents).
func (s *Store) Reconcile() {
	s.mu.Lock()
	defer s.mu.Unlock()

	desired := map[string][]*api.Assignment{}
	var pending []api.PendingItem
	allocated := map[string]api.Resources{}
	regionReplicas := map[string]int{}
	totalReplicas := 0

	var wnames []string
	for name := range s.st.Workloads {
		wnames = append(wnames, name)
	}
	sort.Strings(wnames)
	var nodes []*Node
	for _, n := range s.st.Nodes {
		if !n.Replaced {
			nodes = append(nodes, n)
		}
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].NodeID < nodes[j].NodeID })

	for _, wname := range wnames {
		spec := s.st.Workloads[wname]
		for _, n := range nodes {
			if !matches(spec, n) {
				continue
			}
			ver := spec.Version
			if ov, ok := s.st.Overrides[overrideKey(n.StoreID, spec.Name)]; ok {
				ver = ov
			}
			for i := 0; i < spec.Replicas; i++ {
				id := fmt.Sprintf("%s:%s:%d", spec.Name, n.StoreID, i)
				if spec.AntiAffinity && i >= 1 {
					pending = append(pending, api.PendingItem{
						Workload: spec.Name, StoreID: n.StoreID,
						Reason: "反亲和约束: 同一节点最多运行一个副本",
					})
					continue
				}
				req := spec.Request
				newAlloc := allocated[n.NodeID].Add(req)
				if !newAlloc.FitsIn(n.Capacity) {
					pending = append(pending, api.PendingItem{
						Workload: spec.Name, StoreID: n.StoreID,
						Reason: fmt.Sprintf("节点资源不足: 需要 %s, 节点容量 %s 已分配 %s",
							req, n.Capacity, allocated[n.NodeID]),
					})
					continue
				}
				if !s.quotaOKLocked(n, req, newAlloc, regionReplicas, totalReplicas) {
					pending = append(pending, api.PendingItem{
						Workload: spec.Name, StoreID: n.StoreID,
						Reason: "超出配额限制",
					})
					continue
				}
				allocated[n.NodeID] = newAlloc
				regionReplicas[n.Region]++
				totalReplicas++
				desired[n.NodeID] = append(desired[n.NodeID], &api.Assignment{
					ID: id, Workload: spec.Name, StoreID: n.StoreID, NodeID: n.NodeID,
					Index: i, Version: ver, Cmd: spec.Cmd, Env: spec.Env,
					Request: req, State: "Pending",
				})
			}
		}
	}

	// Converge: keep actual state of surviving assignments, drop the rest.
	newMap := map[string]*api.Assignment{}
	for _, list := range desired {
		for _, d := range list {
			if old, ok := s.st.Assignments[d.ID]; ok {
				moved := old.NodeID != d.NodeID
				old.NodeID = d.NodeID
				old.Version = d.Version
				old.Cmd, old.Env, old.Request = d.Cmd, d.Env, d.Request
				if moved {
					old.State = "Pending"
					old.ActualVersion = ""
					s.addEventLocked("schedule", d.NodeID, d.StoreID,
						fmt.Sprintf("负载 %s 迁移到新节点 %s", d.ID, d.NodeID))
				}
				newMap[d.ID] = old
			} else {
				newMap[d.ID] = d
			}
		}
	}
	for id, old := range s.st.Assignments {
		if _, ok := newMap[id]; !ok {
			s.addEventLocked("schedule", old.NodeID, old.StoreID,
				fmt.Sprintf("负载 %s 从节点 %s 收回", id, old.NodeID))
		}
	}
	s.st.Assignments = newMap
	s.st.Pending = pending

	// Bump per-node desired signatures.
	sigs := map[string]string{}
	for nodeID, list := range desired {
		var parts []string
		for _, a := range list {
			parts = append(parts, a.ID+"@"+a.Version)
		}
		sort.Strings(parts)
		sigs[nodeID] = fmt.Sprintf("%x", fnv(strings.Join(parts, ",")))
	}
	changed := false
	for _, n := range s.st.Nodes {
		if s.st.NodeSig[n.NodeID] != sigs[n.NodeID] {
			s.st.NodeSig[n.NodeID] = sigs[n.NodeID]
			changed = true
		}
	}
	s.dirty = true
	if changed {
		s.changedLocked()
	}
}

func (s *Store) quotaOKLocked(n *Node, req api.Resources, alloc api.Resources, regionReplicas map[string]int, total int) bool {
	if q, ok := s.st.Quotas["store:"+n.StoreID]; ok {
		if q.MaxCPUm > 0 && alloc.CPUm > q.MaxCPUm {
			return false
		}
		if q.MaxMemMB > 0 && alloc.MemMB > q.MaxMemMB {
			return false
		}
	}
	if q, ok := s.st.Quotas["region:"+n.Region]; ok {
		if q.MaxReplicas > 0 && regionReplicas[n.Region]+1 > q.MaxReplicas {
			return false
		}
	}
	if q, ok := s.st.Quotas["global"]; ok {
		if q.MaxReplicas > 0 && total+1 > q.MaxReplicas {
			return false
		}
	}
	return true
}

func fnv(s string) uint64 {
	var h uint64 = 1469598103934665603
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	return h
}
