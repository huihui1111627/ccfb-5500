// Command controlplane runs the central control plane.
package main

import (
	"flag"
	"log"

	"edgeops/internal/clock"
	"edgeops/internal/cp"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "listen address")
	data := flag.String("data", "./cp-data", "data directory")
	flag.Parse()

	srv, err := cp.NewServer(cp.Config{Addr: *addr, DataDir: *data}, clock.Real{})
	if err != nil {
		log.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		log.Fatal(err)
	}
	log.Printf("控制面已启动: http://%s (控制台)", *addr)
	select {}
}
