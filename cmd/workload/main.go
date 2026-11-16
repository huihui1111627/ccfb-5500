// Command workload is the fake store service (收银/处方审核/医保对接 stand-in).
// The agent launches it as a child process; it prints transaction logs,
// maintains the store data marker and serves /metrics.
package main

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	workload := env("EDGE_WORKLOAD", "unknown")
	version := env("EDGE_VERSION", "0.0.0")
	assignID := env("EDGE_ASSIGNMENT_ID", "-")
	dataDir := env("EDGE_DATA_DIR", ".")
	port := env("EDGE_PORT", "8080")

	os.MkdirAll(dataDir, 0o755)
	marker := filepath.Join(dataDir, "marker.txt")
	if _, err := os.Stat(marker); os.IsNotExist(err) {
		os.WriteFile(marker, []byte(fmt.Sprintf("store created by %s\n", workload)), 0o644)
	}
	if f, err := os.OpenFile(marker, os.O_APPEND|os.O_WRONLY, 0o644); err == nil {
		fmt.Fprintf(f, "start workload=%s version=%s assignment=%s\n", workload, version, assignID)
		f.Close()
	}

	var tx, anomalies atomic.Int64
	anomaly := os.Getenv("EDGE_ANOMALY") == "1"

	http.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"cpu_m": 50 + rand.Intn(100), "mem_mb": 64 + rand.Intn(64),
			"tx_count": tx.Load(), "anomalies": anomalies.Load(),
		})
	})
	go http.ListenAndServe("127.0.0.1:"+port, nil)

	fmt.Printf("workload=%s version=%s assignment=%s started\n", workload, version, assignID)
	seq := 0
	for {
		seq++
		tx.Add(1)
		if anomaly && seq%20 == 0 {
			anomalies.Add(1)
		}
		fmt.Printf("tx workload=%s v=%s seq=%d amount=%d.%02d\n",
			workload, version, seq, rand.Intn(500)+1, rand.Intn(100))
		time.Sleep(300 * time.Millisecond)
	}
}
