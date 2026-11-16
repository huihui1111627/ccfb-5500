// Command simulator runs the chaos scenario and the post-run checks.
package main

import (
	"flag"
	"fmt"
	"os"

	"edgeops/internal/sim"
)

func main() {
	stores := flag.Int("stores", 300, "number of store agents")
	addr := flag.String("cp", "127.0.0.1:18080", "control plane address")
	scale := flag.Float64("scale", 120, "sim clock speed multiplier")
	canary := flag.Int64("canary-sec", 3600, "canary soak time in sim seconds")
	batch := flag.Int("batch", 40, "rollout batch size")
	data := flag.String("data", "", "data dir (default: temp)")
	flag.Parse()
	if *data == "" {
		d, err := os.MkdirTemp("", "edgeops-sim-")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		*data = d
	}
	fmt.Println("数据目录:", *data)
	results, err := sim.Run(sim.Config{
		Stores: *stores, CPAddr: *addr, ClockScale: *scale,
		CanarySec: *canary, BatchSize: *batch, DataDir: *data,
	})
	if err != nil {
		fmt.Println("模拟器执行失败:", err)
		os.Exit(1)
	}
	fmt.Println("\n========== 检查结果 ==========")
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
