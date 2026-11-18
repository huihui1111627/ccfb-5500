package verify

import "testing"

// TestDecisionCases 跑全部按协议手算的选路用例。
func TestDecisionCases(t *testing.T) {
	for _, fn := range DecisionCases() {
		r := fn()
		if !r.Pass {
			t.Errorf("%s failed: %s", r.Name, r.Detail)
		} else {
			t.Logf("PASS %s: %s", r.Name, r.Detail)
		}
	}
}

// TestRPKICases 验证 RPKI 丢弃与降级。
func TestRPKICases(t *testing.T) {
	for _, fn := range []func() Result{caseRPKIDrop, caseRPKIDowngrade} {
		r := fn()
		if !r.Pass {
			t.Errorf("%s failed: %s", r.Name, r.Detail)
		}
	}
}

// TestRRCases 验证路由反射器反射与防环。
func TestRRCases(t *testing.T) {
	for _, fn := range []func() Result{caseRRNoLoop, caseRRClusterLoopBlock} {
		r := fn()
		if !r.Pass {
			t.Errorf("%s failed: %s", r.Name, r.Detail)
		}
	}
}

// TestPolicyCases 验证团体/前缀列表/AS路径策略。
func TestPolicyCases(t *testing.T) {
	for _, fn := range []func() Result{
		casePolicyCommunity, casePolicyPrefixListDeny, casePolicyASPathPrepend, caseECMP,
	} {
		r := fn()
		if !r.Pass {
			t.Errorf("%s failed: %s", r.Name, r.Detail)
		}
	}
}

// TestDampingAndFailure 验证阻尼、断链、断路由器与撤回。
func TestDampingAndFailure(t *testing.T) {
	for _, fn := range []func() Result{
		caseDampingSuppress, caseLinkFailureConvergence,
		caseRouterFailure, caseNoBlackholeOnWithdraw,
	} {
		r := fn()
		if !r.Pass {
			t.Errorf("%s failed: %s", r.Name, r.Detail)
		} else {
			t.Logf("PASS %s: %s (rounds=%d)", r.Name, r.Detail, r.ConvergenceRounds)
		}
	}
}

// TestRunAll 跑完整套件，包含大规模生成场景的无环检查。
func TestRunAll(t *testing.T) {
	report := RunAll()
	if report.Failed != 0 {
		for _, r := range report.Results {
			if !r.Pass {
				t.Errorf("%s failed: %s", r.Name, r.Detail)
			}
		}
	}
	t.Logf("suite: passed=%d failed=%d largeScale(prefixes=%d rounds=%d loops=%d blackholes=%d)",
		report.Passed, report.Failed, report.LargeScalePrefixes, report.LargeScaleRounds,
		report.LargeScaleLoops, report.LargeScaleBlackholes)
}
