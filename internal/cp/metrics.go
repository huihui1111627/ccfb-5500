package cp

import (
	"sort"

	"edgeops/internal/api"
)

const maxSamplesPerWorkload = 2000

func (s *Store) addSamplesLocked(samples []api.MetricSample) {
	for _, sm := range samples {
		buf := s.st.Metrics[sm.Workload]
		buf = append(buf, sm)
		if len(buf) > maxSamplesPerWorkload {
			buf = buf[len(buf)-maxSamplesPerWorkload:]
		}
		s.st.Metrics[sm.Workload] = buf
	}
}

func percentile(sorted []int, p float64) int {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(float64(len(sorted)-1) * p)
	return sorted[idx]
}

// Recommendations derives p95-based resource suggestions from reported usage.
func (s *Store) Recommendations() []api.Recommendation {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []api.Recommendation
	for name, buf := range s.st.Metrics {
		if len(buf) < 5 {
			continue
		}
		var cpus, mems []int
		for _, sm := range buf {
			cpus = append(cpus, sm.CPUm)
			mems = append(mems, sm.MemMB)
		}
		sort.Ints(cpus)
		sort.Ints(mems)
		p95 := api.Resources{CPUm: percentile(cpus, 0.95), MemMB: percentile(mems, 0.95)}
		sug := api.Resources{CPUm: p95.CPUm * 13 / 10, MemMB: p95.MemMB * 13 / 10}
		if sug.CPUm < 10 {
			sug.CPUm = 10
		}
		if sug.MemMB < 16 {
			sug.MemMB = 16
		}
		rec := api.Recommendation{
			Workload: name, P95: p95, Suggested: sug, Samples: len(buf),
		}
		if spec, ok := s.st.Workloads[name]; ok {
			rec.CurrentRequest = spec.Request
		}
		out = append(out, rec)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Workload < out[j].Workload })
	return out
}
