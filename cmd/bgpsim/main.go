// Command bgpsim 提供 BGP 仿真平台的网页服务与命令行工具。
//
// 用法：
//
//	bgpsim serve [-addr :8080]      启动网页与 API 服务
//	bgpsim verify                   运行全部手算用例与批量场景，输出报告
//	bgpsim generate [-out dir]      生成大规模场景并导出 JSON（拓扑/流量矩阵）
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/edu-net/bgpsim/internal/gen"
	"github.com/edu-net/bgpsim/internal/server"
	"github.com/edu-net/bgpsim/internal/verify"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "serve":
		runServe(os.Args[2:])
	case "verify":
		runVerify()
	case "generate":
		runGenerate(os.Args[2:])
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "未知子命令: %s\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `bgpsim — BGP 路由策略仿真与验证平台
用法:
  bgpsim serve [-addr :8080]       启动网页与 API 服务
  bgpsim verify                    运行手算用例与批量故障/策略场景
  bgpsim generate [-out DIR]       导出大规模场景 JSON`)
}

func runServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fs.String("addr", ":8080", "HTTP 监听地址")
	_ = fs.Parse(args)
	srv := server.New()
	log.Printf("BGP 仿真平台已启动: http://localhost%s", *addr)
	if err := http.ListenAndServe(*addr, srv.Routes()); err != nil {
		log.Fatal(err)
	}
}

func runVerify() {
	fmt.Println("=== 手算选路/策略/RPKI/RR/阻尼/故障用例 ===")
	report := verify.RunAll()
	pass, fail := 0, 0
	for _, r := range report.Results {
		mark := "PASS"
		if !r.Pass {
			mark = "FAIL"
			fail++
		} else {
			pass++
		}
		extra := ""
		if r.ConvergenceRounds > 0 {
			extra = fmt.Sprintf(" (收敛 %d 轮)", r.ConvergenceRounds)
		}
		fmt.Printf("[%s] %-24s %s%s\n", mark, r.Name, r.Detail, extra)
	}
	fmt.Printf("\n大规模场景: 前缀=%d 收敛=%d 轮 路由环=%d 黑洞=%d\n",
		report.LargeScalePrefixes, report.LargeScaleRounds,
		report.LargeScaleLoops, report.LargeScaleBlackholes)

	fmt.Println("\n=== 批量断链/断路由器/策略变更场景 ===")
	batch := verify.RunBatchScenarios()
	for _, s := range batch.Scenarios {
		mark := "PASS"
		if !s.Pass {
			mark = "FAIL"
		}
		fmt.Printf("[%s] %-28s 收敛=%d 轮 环=%d 黑洞=%d\n",
			mark, s.Name, s.ConvergenceRounds, s.Loops, s.Blackholes)
	}

	if fail != 0 || !batch.AllClean || report.LargeScaleLoops != 0 || report.LargeScaleBlackholes != 0 {
		fmt.Printf("\n结论: 存在失败用例或异常（手算失败 %d）\n", fail)
		os.Exit(1)
	}
	fmt.Printf("\n结论: 全部 %d 个手算用例 + %d 个批量场景通过，全网无路由环、无黑洞。\n",
		pass, len(batch.Scenarios))
}

func runGenerate(args []string) {
	fs := flag.NewFlagSet("generate", flag.ExitOnError)
	out := fs.String("out", "examples", "导出目录")
	small := fs.Bool("small", false, "生成小规模场景（默认大规模）")
	_ = fs.Parse(args)

	params := gen.DefaultParams()
	if *small {
		params.CoreCount = 2
		params.RRCount = 1
		params.AggCount = 2
		params.EdgeCount = 2
		params.CampusesPerAgg = 2
		params.PrefixCount = 200
	}
	scenario, err := gen.Generate(params)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		log.Fatal(err)
	}
	mustWriteJSON(filepath.Join(*out, "config.json"), scenario.Config)
	mustWriteJSON(filepath.Join(*out, "traffic_matrix.json"), scenario.Matrix)
	fmt.Printf("已导出场景到 %s:\n", *out)
	fmt.Printf("  config.json:          %d 节点 / %d 链路 / %d 外部路由 / %d ROA\n",
		len(scenario.Config.Topology.Nodes), len(scenario.Config.Topology.Links),
		len(scenario.Config.Topology.External), len(scenario.Config.Topology.ROAs))
	fmt.Printf("  traffic_matrix.json:  %d 条前缀流量记录\n", len(scenario.Matrix.Flows))
}

func mustWriteJSON(path string, v interface{}) {
	f, err := os.Create(path)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		log.Fatal(err)
	}
}
