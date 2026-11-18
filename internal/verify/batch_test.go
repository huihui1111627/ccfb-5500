package verify

import "testing"

// TestBatchScenarios 批量跑断链、断路由器与策略变更场景，
// 断言全部无路由环、无黑洞，并输出每个场景的收敛轮数。
func TestBatchScenarios(t *testing.T) {
	report := RunBatchScenarios()
	for _, s := range report.Scenarios {
		if !s.Pass {
			t.Errorf("%s failed: %s (loops=%d blackholes=%d)",
				s.Name, s.Detail, s.Loops, s.Blackholes)
		} else {
			t.Logf("PASS %-28s rounds=%-3d loops=%d blackholes=%d",
				s.Name, s.ConvergenceRounds, s.Loops, s.Blackholes)
		}
	}
	if !report.AllClean {
		t.Fatalf("batch scenarios produced loops or blackholes: %d scenarios", len(report.Scenarios))
	}
}
