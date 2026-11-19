// Command bgpsim runs the BGP policy simulation and verification platform.
//
//	bgpsim serve [-addr :8080]      start the web UI
//	bgpsim verify [-cities N] ...   run the scenario suite headless
//	bgpsim generate -o net.json     write a generated network
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"bgpsim/internal/gen"
	"bgpsim/internal/policy"
	"bgpsim/internal/rpki"
	"bgpsim/internal/scenario"
	"bgpsim/internal/server"
	"bgpsim/internal/sim"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "serve":
		serve(os.Args[2:])
	case "verify":
		verify(os.Args[2:])
	case "generate":
		generate(os.Args[2:])
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `bgpsim — BGP policy simulation and verification

  bgpsim serve    [-addr :8080] [-cities N] [-prefixes N]
  bgpsim verify   [-cities N] [-prefixes N] [-json]
  bgpsim generate [-o file.json] [-cities N] [-prefixes N]

The web UI has pages for topology, the routing table, policy editing, fault
injection with convergence replay, and per-upstream traffic utilisation.
`)
}

func serve(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fs.String("addr", ":8080", "listen address")
	_ = fs.Parse(args)
	srv := server.New()
	fmt.Printf("bgpsim listening on http://localhost%s\n", *addr)
	if err := http.ListenAndServe(*addr, srv.Handler()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func verify(args []string) {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	cities := fs.Int("cities", 12, "number of aggregation sites")
	prefixes := fs.Int("prefixes", 4000, "number of prefixes")
	asJSON := fs.Bool("json", false, "print the result as JSON")
	seed := fs.Int64("seed", 20261120, "generator seed")
	_ = fs.Parse(args)

	start := time.Now()
	results, err := scenario.Run(scenario.Options{Cities: *cities, Prefixes: *prefixes, Seed: *seed})
	if err != nil {
		fmt.Fprintln(os.Stderr, "verify failed:", err)
		os.Exit(1)
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", " ")
		_ = enc.Encode(results)
	} else {
		fmt.Printf("scenario verification — %d scenarios in %s\n\n", len(results), time.Since(start).Round(time.Millisecond))
		fmt.Printf("%-46s %-16s %6s %9s %7s %4s %3s\n", "SCENARIO", "KIND", "ROUNDS", "UPDATES", "CONVERG", "BH", "LOOP")
		fail := 0
		for _, r := range results {
			conv := "yes"
			if !r.Converged {
				conv = "NO"
			}
			if r.Loops > 0 || r.Blackholes > 0 || !r.Converged {
				fail++
			}
			fmt.Printf("%-46s %-16s %6d %9d %7s %4d %4d\n",
				r.Name, r.Kind, r.Rounds, r.Updates, conv, r.Blackholes, r.Loops)
		}
		fmt.Println()
		if fail > 0 {
			fmt.Printf("%d scenario(s) failed invariant checks\n", fail)
			os.Exit(1)
		}
		fmt.Println("all scenarios converged with no loops and no black holes")
	}
}

func generate(args []string) {
	fs := flag.NewFlagSet("generate", flag.ExitOnError)
	out := fs.String("o", "", "output file (default stdout)")
	cities := fs.Int("cities", 12, "number of aggregation sites")
	prefixes := fs.Int("prefixes", 24000, "number of prefixes")
	seed := fs.Int64("seed", 20261120, "generator seed")
	edge := fs.Int("edge-per-city", 2, "edge routers per city")
	rr := fs.Int("rr-pairs", 2, "route reflector pairs")
	upstreams := fs.Int("upstreams", 3, "number of providers")
	verifyRun := fs.Bool("verify", true, "converge and report the baseline")
	_ = fs.Parse(args)

	opts := gen.DefaultOptions()
	opts.Seed = *seed
	opts.Cities = *cities
	opts.Prefixes = *prefixes
	opts.EdgePerCity = *edge
	opts.RRPairs = *rr
	opts.Upstreams = *upstreams
	n, err := gen.Build(opts)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	n.Policies = gen.DefaultPolicy(opts.ProvinceAS, nil)
	if err := n.Build(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if *verifyRun {
		pol, err := policy.Compile(n)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		e := sim.New(n, pol, rpki.New(n.ROAs))
		e.Seed()
		rounds := e.Converge(200)
		fmt.Fprintf(os.Stderr, "generated %d routers, %d links, %d prefixes, %d announcements; converged in %d rounds (%d updates)\n",
			len(n.Routers), len(n.Links), len(n.PrefixesV), len(n.Announcements), rounds, e.Updates)
	}
	data, err := json.MarshalIndent(n, "", " ")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if *out == "" {
		os.Stdout.Write(data)
		os.Stdout.WriteString("\n")
		return
	}
	if err := os.WriteFile(*out, data, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "wrote %s\n", *out)
}
