// Command checker verifies a running platform: convergence, release
// rules, and optionally host-replacement handover for one store.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"edgeops/internal/check"
)

func main() {
	base := flag.String("cp", "http://127.0.0.1:8080", "control plane base URL")
	store := flag.String("store", "", "store ID to check handover for (optional)")
	marker := flag.String("marker", "", "expected data marker for -store")
	expect := flag.String("expect", "cashier:2,rx-review:1", "expected running workloads w:n,...")
	flag.Parse()

	results := []check.Result{
		check.Convergence(*base),
		check.ReleaseRules(*base),
	}
	if *store != "" {
		exp := map[string]int{}
		for _, kv := range strings.Split(*expect, ",") {
			var w string
			var n int
			fmt.Sscanf(kv, "%[^:]:%d", &w, &n)
			exp[w] = n
		}
		results = append(results, check.Handover(*base, *store, *marker, exp))
	}
	ok := true
	for _, r := range results {
		mark := "✅ PASS"
		if !r.OK {
			mark = "❌ FAIL"
			ok = false
		}
		fmt.Printf("%s [%s] %s\n", mark, r.Name, r.Detail)
	}
	if !ok {
		os.Exit(1)
	}
}
