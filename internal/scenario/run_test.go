package scenario

import (
	"testing"
)

// TestScenarioSuiteInvariants runs the full scenario set on a small network
// and asserts the invariants the platform promises: every scenario converges,
// and none produces a forwarding loop or a black hole.
func TestScenarioSuiteInvariants(t *testing.T) {
	results, err := Run(Options{Cities: 6, Prefixes: 1500})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) < 5 {
		t.Fatalf("only %d scenarios ran, expected the full set", len(results))
	}
	sawBaseline := false
	for _, r := range results {
		r := r
		t.Run(r.Name, func(t *testing.T) {
			if !r.Converged {
				t.Errorf("did not converge (kind %s)", r.Kind)
			}
			if r.Loops != 0 {
				t.Errorf("%d routing loops", r.Loops)
			}
			if r.Blackholes != 0 {
				t.Errorf("%d black holes", r.Blackholes)
			}
			if r.Rounds < 0 || r.Rounds > 200 {
				t.Errorf("implausible round count %d", r.Rounds)
			}
		})
		if r.Kind == "baseline" {
			sawBaseline = true
			if r.Rounds == 0 {
				t.Error("baseline converged in zero rounds; it should have work to do")
			}
		}
	}
	if !sawBaseline {
		t.Error("the baseline scenario is missing")
	}
}

// TestFaultScenariosActuallyChangeState verifies a scenario that removes a
// provider's border causes BGP work, so the suite is not silently no-oping.
func TestFaultScenariosActuallyChangeState(t *testing.T) {
	results, err := Run(Options{Cities: 6, Prefixes: 1500})
	if err != nil {
		t.Fatal(err)
	}
	var borderFailure *Result
	for i := range results {
		r := &results[i]
		if r.Kind == "router-failure" && len(r.Name) > len("fail-border") &&
			r.Name[:len("fail-border")] == "fail-border" {
			borderFailure = r
			break
		}
	}
	if borderFailure == nil {
		t.Fatal("no border-failure scenario in the suite")
	}
	if borderFailure.Rounds == 0 {
		t.Error("failing a border did not change any BGP path")
	}
	if borderFailure.Updates == 0 {
		t.Error("failing a border produced no update messages")
	}
}
