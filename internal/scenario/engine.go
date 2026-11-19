// Package scenario holds the verification suite: hand-computed reference
// cases for the decision process, plus the larger fault and policy scenarios
// that check a simulation never produces a routing loop or black hole and
// report how many rounds each scenario took to converge.
package scenario

// (The reference cases live in cases_test.go; this file holds the scenario
// runner used by both the tests and the web API.)
