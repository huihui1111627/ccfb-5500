// Command agent runs one edge node agent on a store host.
package main

import (
	"context"
	"flag"
	"log"
	"strings"

	"edgeops/internal/agent"
	"edgeops/internal/api"
)

func main() {
	cpAddr := flag.String("cp", "127.0.0.1:8080", "control plane address")
	store := flag.String("store", "", "store ID (required)")
	region := flag.String("region", "默认区", "region")
	listen := flag.String("listen", "127.0.0.1:9000", "agent listen address")
	data := flag.String("data", "", "data dir (default ./agent-data-<store>)")
	cpu := flag.Int("cpu", 2000, "capacity cpu millicores")
	mem := flag.Int("mem", 4096, "capacity memory MB")
	labels := flag.String("labels", "", "k=v,k=v")
	taints := flag.String("taints", "", "t1,t2")
	open := flag.String("open", "08:00", "open time")
	close_ := flag.String("close", "22:00", "close time")
	peakStart := flag.String("peak-start", "10:00", "peak start")
	peakEnd := flag.String("peak-end", "13:00", "peak end")
	flag.Parse()
	if *store == "" {
		log.Fatal("-store required")
	}
	if *data == "" {
		*data = "./agent-data-" + *store
	}
	lm := map[string]string{}
	for _, kv := range strings.Split(*labels, ",") {
		if p := strings.SplitN(kv, "=", 2); len(p) == 2 {
			lm[p[0]] = p[1]
		}
	}
	var tl []string
	if *taints != "" {
		tl = strings.Split(*taints, ",")
	}
	a := agent.New(agent.Config{
		StoreID: *store, Region: *region, Labels: lm, Taints: tl,
		Capacity: api.Resources{CPUm: *cpu, MemMB: *mem},
		Hours: api.BusinessHours{
			Open: *open, Close: *close_, PeakStart: *peakStart, PeakEnd: *peakEnd,
		},
		CPAddr: *cpAddr, ListenAddr: *listen, DataDir: *data,
		Executor: agent.RealExecutor{},
	})
	log.Printf("节点代理启动: 门店=%s 控制面=%s", *store, *cpAddr)
	if err := a.Run(context.Background()); err != nil {
		log.Fatal(err)
	}
}
