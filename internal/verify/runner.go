package verify

import (
	"fmt"

	"github.com/edu-net/bgpsim/internal/gen"
)

// SuiteReport 是一次完整验证的汇总。
type SuiteReport struct {
	Results []Result `json:"results"`
	Passed  int      `json:"passed"`
	Failed  int      `json:"failed"`
	// 大规模场景批跑指标。
	LargeScaleRounds     int `json:"large_scale_rounds"`
	LargeScaleLoops      int `json:"large_scale_loops"`
	LargeScaleBlackholes int `json:"large_scale_blackholes"`
	LargeScalePrefixes   int `json:"large_scale_prefixes"`
}

// RunAll 执行全部手工用例，再跑大规模生成场景并检查环路/黑洞。
func RunAll() SuiteReport {
	report := SuiteReport{}
	cases := append(DecisionCases(),
		func() Result { return caseRPKIDrop() },
		func() Result { return caseRPKIDowngrade() },
		func() Result { return caseRRNoLoop() },
		func() Result { return caseRRClusterLoopBlock() },
		func() Result { return casePolicyCommunity() },
		func() Result { return casePolicyPrefixListDeny() },
		func() Result { return casePolicyASPathPrepend() },
		func() Result { return caseECMP() },
		func() Result { return caseDampingSuppress() },
		func() Result { return caseLinkFailureConvergence() },
		func() Result { return caseRouterFailure() },
		func() Result { return caseNoBlackholeOnWithdraw() },
	)
	for _, fn := range cases {
		r := fn()
		report.Results = append(report.Results, r)
		if r.Pass {
			report.Passed++
		} else {
			report.Failed++
		}
	}

	// 大规模场景：生成并跑到收敛，检查无环、统计收敛轮数。
	scenario, err := gen.Generate(gen.DefaultParams())
	if err != nil {
		report.Results = append(report.Results, Result{
			Name: "large_scale_generate", Pass: false, Detail: err.Error(),
		})
		report.Failed++
		return report
	}
	e, err := buildFromScenario(scenario)
	if err != nil {
		report.Results = append(report.Results, Result{
			Name: "large_scale_build", Pass: false, Detail: err.Error(),
		})
		report.Failed++
		return report
	}
	stats, err := e.Run(0)
	if err != nil {
		report.Results = append(report.Results, Result{
			Name: "large_scale_run", Pass: false, Detail: err.Error(),
		})
		report.Failed++
		return report
	}
	report.LargeScaleRounds = stats.ConvergedInRound
	report.LargeScaleLoops = stats.LoopsDetected
	report.LargeScaleBlackholes = stats.Blackholes
	report.LargeScalePrefixes = len(e.AllPrefixes())
	largePass := stats.LoopsDetected == 0
	if largePass {
		report.Passed++
		report.Results = append(report.Results, Result{
			Name: "large_scale_no_loop", Pass: true,
			Detail: fmt.Sprintf("prefixes=%d rounds=%d blackholes=%d",
				report.LargeScalePrefixes, report.LargeScaleRounds, report.LargeScaleBlackholes),
		})
	} else {
		report.Failed++
		report.Results = append(report.Results, Result{
			Name: "large_scale_no_loop", Pass: false, Detail: "loop detected in large topology",
		})
	}
	return report
}
