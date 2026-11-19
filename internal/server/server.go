// Package server exposes the simulator over HTTP and serves the single-page
// front end.  Every handler works on an in-memory session; there is no
// database because a simulation run is cheap to rebuild and the interesting
// state is the network, not the server.
package server

import (
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"bgpsim/internal/bgp"
	"bgpsim/internal/gen"
	"bgpsim/internal/model"
	"bgpsim/internal/policy"
	"bgpsim/internal/rpki"
	"bgpsim/internal/scenario"
	"bgpsim/internal/sim"
	"bgpsim/internal/traffic"
)

//go:embed web
var webFS embed.FS

// Session is one loaded network plus its converged baseline.
type Session struct {
	mu       sync.Mutex
	Net      *model.Network
	Pol      *policy.Engine
	RPKI     *rpki.Validator
	Base     *sim.Engine
	Live     *sim.Engine // current state including faults and edits
	Baseline int
	LastRun  time.Time

	// Cached scenario report so the verification page is instant.
	Report []scenario.Result
}

// Server holds the sessions, keyed by name.
type Server struct {
	mu       sync.Mutex
	sessions map[string]*Session
	genOpts  gen.Options
}

// NewForTest builds a server backed by a smaller generated network with the
// given number of cities and prefixes.  Exported so the HTTP contract can be
// tested without paying for the full province-scale generation.
func NewForTest(cities, prefixes int) *Server {
	s := &Server{sessions: map[string]*Session{}, genOpts: gen.DefaultOptions()}
	opts := gen.DefaultOptions()
	opts.Cities = cities
	opts.Prefixes = prefixes
	sess, err := s.buildSession("default", opts)
	if err != nil {
		panic(err)
	}
	s.sessions["default"] = sess
	return s
}

// New builds a server with one generated default session.
func New() *Server {
	s := &Server{sessions: map[string]*Session{}, genOpts: gen.DefaultOptions()}
	sess, err := s.buildSession("default", gen.DefaultOptions())
	if err != nil {
		log.Printf("default session: %v", err)
	} else {
		s.sessions["default"] = sess
	}
	return s
}

func (s *Server) buildSession(name string, opts gen.Options) (*Session, error) {
	n, err := gen.Build(opts)
	if err != nil {
		return nil, err
	}
	n.Policies = gen.DefaultPolicy(opts.ProvinceAS, nil)
	if err := n.Build(); err != nil {
		return nil, err
	}
	pol, err := policy.Compile(n)
	if err != nil {
		return nil, err
	}
	rp := rpki.New(n.ROAs)
	e := sim.New(n, pol, rp)
	e.Seed()
	rounds := e.Converge(200)
	sess := &Session{Net: n, Pol: pol, RPKI: rp, Base: e, Baseline: rounds, LastRun: time.Now()}
	sess.Live = e
	return sess, nil
}

// Handler returns the root mux.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/state", s.handleState)
	mux.HandleFunc("/api/topology", s.handleTopology)
	mux.HandleFunc("/api/rib", s.handleRIB)
	mux.HandleFunc("/api/decision", s.handleDecision)
	mux.HandleFunc("/api/policies", s.handlePolicies)
	mux.HandleFunc("/api/policies/apply", s.handleApplyPolicies)
	mux.HandleFunc("/api/faults", s.handleFaults)
	mux.HandleFunc("/api/replay", s.handleReplay)
	mux.HandleFunc("/api/traffic", s.handleTraffic)
	mux.HandleFunc("/api/rpki", s.handleRPKI)
	mux.HandleFunc("/api/scenarios", s.handleScenarios)
	mux.HandleFunc("/api/generate", s.handleGenerate)
	mux.HandleFunc("/api/import", s.handleImport)
	mux.HandleFunc("/api/dampening", s.handleDampening)

	sub, err := fs.Sub(webFS, "web")
	if err != nil {
		panic(err)
	}
	mux.Handle("/", http.FileServer(http.FS(sub)))
	return logging(mux)
}

func logging(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		h.ServeHTTP(w, r)
		if strings.HasPrefix(r.URL.Path, "/api/") {
			log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start).Round(time.Millisecond))
		}
	})
}

func (s *Server) session(r *http.Request) *Session {
	name := r.URL.Query().Get("session")
	if name == "" {
		name = "default"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[name]
	if !ok {
		sess = s.sessions["default"]
	}
	sess.mu.Lock()
	return sess
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", " ")
	_ = enc.Encode(v)
}

func writeErr(w http.ResponseWriter, code int, format string, args ...any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf(format, args...)})
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

func (s *Server) handleState(w http.ResponseWriter, r *http.Request) {
	sess := s.session(r)
	defer sess.mu.Unlock()
	n := sess.Net
	e := sess.Live
	writeJSON(w, map[string]any{
		"name":           n.Name,
		"routers":        len(n.Routers),
		"links":          len(n.Links),
		"prefixes":       len(n.PrefixesV),
		"announcements":  len(n.Announcements),
		"sessions":       len(n.Sessions),
		"roas":           len(n.ROAs),
		"baselineRounds": sess.Baseline,
		"updates":        e.Updates,
		"rpki":           sess.RPKI.AnnouncementStats(n),
		"config":         n.Config,
		"routerDown":     keys(e.RouterDown),
		"linkDown":       keys(e.LinkDown),
	})
}

func keys(m map[int]bool) []int {
	var out []int
	for k, v := range m {
		if v {
			out = append(out, k)
		}
	}
	return out
}

type topoRouter struct {
	ID   int     `json:"id"`
	Name string  `json:"name"`
	ASN  uint32  `json:"asn"`
	Role string  `json:"role"`
	Tier string  `json:"tier"`
	RR   bool    `json:"rr"`
	Down bool    `json:"down"`
	X    float64 `json:"x,omitempty"`
	Y    float64 `json:"y,omitempty"`
	// Counts useful to the topology view.
	Prefixes int `json:"prefixes"`
	Peers    int `json:"peers"`
}

func (s *Server) handleTopology(w http.ResponseWriter, r *http.Request) {
	sess := s.session(r)
	defer sess.mu.Unlock()
	n := sess.Net
	type topoLink struct {
		ID       int     `json:"id"`
		A        int     `json:"a"`
		B        int     `json:"b"`
		ActorA   string  `json:"actorA"`
		ActorB   string  `json:"actorB"`
		Cost     int     `json:"cost"`
		Capacity float64 `json:"capacityGbps"`
		Kind     string  `json:"kind"`
		Down     bool    `json:"down"`
		EBGP     bool    `json:"ebgp"`
	}
	var routers []topoRouter
	for i, rt := range n.Routers {
		anns := 0
		for _, a := range n.Announcements {
			if a.RouterIdx == i {
				anns++
			}
		}
		routers = append(routers, topoRouter{
			ID: i, Name: rt.Name, ASN: rt.ASN, Role: rt.Role, Tier: rt.Tier,
			RR: rt.RR, Down: sess.Live.RouterDown[i], Prefixes: anns, Peers: len(rt.Peers),
		})
	}
	var links []topoLink
	for i := range n.Links {
		l := &n.Links[i]
		links = append(links, topoLink{
			ID: i, A: l.AIdx, B: l.BIdx, ActorA: l.A, ActorB: l.B,
			Cost: l.Cost, Capacity: l.Capacity, Kind: l.Kind,
			Down: sess.Live.LinkDown[i],
			EBGP: n.Routers[l.AIdx].ASN != n.Routers[l.BIdx].ASN,
		})
	}
	writeJSON(w, map[string]any{"routers": routers, "links": links})
}

func (s *Server) handleRIB(w http.ResponseWriter, r *http.Request) {
	sess := s.session(r)
	defer sess.mu.Unlock()
	name := r.URL.Query().Get("router")
	idx := sess.Net.RouterIndex(name)
	if idx < 0 {
		writeErr(w, 400, "unknown router %q", name)
		return
	}
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 200
	}
	entries, total := sess.Live.RouterRIB(idx, r.URL.Query().Get("prefix"), offset, limit)
	writeJSON(w, map[string]any{
		"router":  name,
		"entries": entries,
		"total":   total,
		"offset":  offset,
		"limit":   limit,
	})
}

func (s *Server) handleDecision(w http.ResponseWriter, r *http.Request) {
	sess := s.session(r)
	defer sess.mu.Unlock()
	idx := sess.Net.RouterIndex(r.URL.Query().Get("router"))
	p := sess.Net.PrefixIndex(r.URL.Query().Get("prefix"))
	if idx < 0 || p < 0 {
		writeErr(w, 400, "router and prefix are required")
		return
	}
	d := sess.Live.Decision(idx, p)
	if d == nil {
		writeJSON(w, map[string]any{"router": sess.Net.Routers[idx].Name,
			"prefix": sess.Net.PrefixString(p), "candidates": []any{}, "winner": -1})
		return
	}
	writeJSON(w, map[string]any{
		"router":   sess.Net.Routers[idx].Name,
		"prefix":   sess.Net.PrefixString(p),
		"decision": d,
	})
}

func (s *Server) handlePolicies(w http.ResponseWriter, r *http.Request) {
	sess := s.session(r)
	defer sess.mu.Unlock()
	var out []map[string]any
	for i, p := range sess.Net.Policies {
		out = append(out, map[string]any{
			"index":       i,
			"policy":      p,
			"description": policy.Describe(p),
		})
	}
	writeJSON(w, map[string]any{"policies": out})
}

func (s *Server) handleApplyPolicies(w http.ResponseWriter, r *http.Request) {
	sess := s.session(r)
	defer sess.mu.Unlock()
	if r.Method != http.MethodPost {
		writeErr(w, 405, "POST required")
		return
	}
	var req struct {
		Policies []model.Policy `json:"policies"`
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	if err := json.Unmarshal(body, &req); err != nil {
		writeErr(w, 400, "bad JSON: %v", err)
		return
	}
	saved := sess.Net.Policies
	sess.Net.Policies = req.Policies
	pol, err := policy.Compile(sess.Net)
	if err != nil {
		sess.Net.Policies = saved
		writeErr(w, 400, "policy error: %v", err)
		return
	}
	// Re-apply from a cold start, exactly like an inbound soft reset.
	start := time.Now()
	e := sim.New(sess.Net, pol, sess.RPKI)
	e.Seed()
	rounds := e.Converge(200)
	sess.Pol = pol
	sess.Live = e
	sess.LastRun = time.Now()
	writeJSON(w, map[string]any{
		"ok":       true,
		"rounds":   rounds,
		"updates":  e.Updates,
		"elapsed":  time.Since(start).String(),
		"policies": len(req.Policies),
	})
}

func (s *Server) handleFaults(w http.ResponseWriter, r *http.Request) {
	sess := s.session(r)
	defer sess.mu.Unlock()
	if r.Method == http.MethodGet {
		writeJSON(w, map[string]any{
			"routerDown": keys(sess.Live.RouterDown),
			"linkDown":   keys(sess.Live.LinkDown),
		})
		return
	}
	var req struct {
		RouterDown []int `json:"routerDown"`
		LinkDown   []int `json:"linkDown"`
		Reset      bool  `json:"reset"`
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err := json.Unmarshal(body, &req); err != nil {
		writeErr(w, 400, "bad JSON: %v", err)
		return
	}
	// A fault run always starts from the converged baseline plus the current
	// policy, so two fault experiments never compound.
	e := sim.New(sess.Net, sess.Pol, sess.RPKI)
	e.CloneFrom(sess.Base)
	e.SetFaults(req.RouterDown, req.LinkDown)
	start := time.Now()
	rounds := e.Converge(200)
	sess.Live = e
	writeJSON(w, map[string]any{
		"ok":      true,
		"rounds":  rounds,
		"updates": e.Updates,
		"elapsed": time.Since(start).String(),
		"changes": len(e.Changes),
	})
}

type replayRound struct {
	Round   int            `json:"round"`
	Changes []sim.Change   `json:"changes"`
	Counts  map[string]int `json:"counts"`
	Total   int            `json:"total"`
}

func (s *Server) handleReplay(w http.ResponseWriter, r *http.Request) {
	sess := s.session(r)
	defer sess.mu.Unlock()
	onlyRouter := r.URL.Query().Get("router")
	prefix := r.URL.Query().Get("prefix")
	byRound := map[int][]sim.Change{}
	for _, c := range sess.Live.Changes {
		if onlyRouter != "" && c.Router != onlyRouter {
			continue
		}
		if prefix != "" && !strings.HasPrefix(c.Prefix, prefix) {
			continue
		}
		byRound[c.Round] = append(byRound[c.Round], c)
	}
	// Cap how many change records travel to the browser.  A province-scale
	// fault can touch hundreds of thousands of (router, prefix) pairs; the
	// replay view needs the shape of the wave, not every row, so each round
	// keeps a representative sample and reports the true totals separately.
	const perRoundCap = 400
	var rounds []replayRound
	for rd := 1; rd <= 400; rd++ {
		ch, ok := byRound[rd]
		if !ok {
			continue
		}
		counts := map[string]int{"withdraw": 0, "announce": 0}
		for _, c := range ch {
			if c.Withdrawn {
				counts["withdraw"]++
			} else {
				counts["announce"]++
			}
		}
		total := len(ch)
		if len(ch) > perRoundCap {
			ch = ch[:perRoundCap]
		}
		rr := replayRound{Round: rd, Changes: ch, Counts: counts, Total: total}
		rounds = append(rounds, rr)
	}
	writeJSON(w, map[string]any{
		"rounds": rounds,
		"total":  len(sess.Live.Changes),
	})
}

func (s *Server) handleTraffic(w http.ResponseWriter, r *http.Request) {
	sess := s.session(r)
	defer sess.mu.Unlock()
	flows, _ := strconv.Atoi(r.URL.Query().Get("flows"))
	rep := traffic.Analyze(sess.Net, sess.Live, flows)
	// Cap the per-flow list so the response stays small; the aggregate is
	// what the utilisation chart uses.
	if len(rep.Flows) > 300 {
		rep.Flows = rep.Flows[:300]
	}
	writeJSON(w, rep)
}

func (s *Server) handleRPKI(w http.ResponseWriter, r *http.Request) {
	sess := s.session(r)
	defer sess.mu.Unlock()
	stats := sess.RPKI.AnnouncementStats(sess.Net)
	// Per-provider breakdown of invalid offers is what an operator checks
	// first when a prefix stops working.
	type row struct {
		Router   string `json:"router"`
		Valid    int    `json:"valid"`
		Invalid  int    `json:"invalid"`
		NotFound int    `json:"notFound"`
	}
	byRouter := map[string]*row{}
	for _, a := range sess.Net.Announcements {
		name := a.Router
		rw, ok := byRouter[name]
		if !ok {
			rw = &row{Router: name}
			byRouter[name] = rw
		}
		origin := sess.Net.Routers[a.RouterIdx].ASN
		if n := len(a.ASPath); n > 0 {
			origin = a.ASPath[n-1]
		}
		switch sess.RPKI.Validate(sess.Net.PrefixesV[a.PrefixIdx], origin) {
		case model.RPKIValid:
			rw.Valid++
		case model.RPKIInvalid:
			rw.Invalid++
		default:
			rw.NotFound++
		}
	}
	var rows []*row
	for _, rw := range byRouter {
		rows = append(rows, rw)
	}
	writeJSON(w, map[string]any{"stats": stats, "byRouter": rows, "mode": sess.Net.Config.RPKIMode})
}

func (s *Server) handleScenarios(w http.ResponseWriter, r *http.Request) {
	sess := s.session(r)
	defer sess.mu.Unlock()
	if r.Method == http.MethodPost {
		start := time.Now()
		opts := scenario.Options{
			Cities:   len(sess.Net.Routers) / 3,
			Prefixes: len(sess.Net.PrefixesV),
		}
		results, err := scenario.Run(opts)
		if err != nil {
			writeErr(w, 500, "scenario run failed: %v", err)
			return
		}
		sess.Report = results
		log.Printf("scenario run: %d results in %s", len(results), time.Since(start))
	}
	writeJSON(w, map[string]any{"results": sess.Report})
}

func (s *Server) handleGenerate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, 405, "POST required")
		return
	}
	var req struct {
		Session     string `json:"session"`
		Seed        int64  `json:"seed"`
		Cities      int    `json:"cities"`
		Prefixes    int    `json:"prefixes"`
		EdgePerCity int    `json:"edgePerCity"`
		RRPairs     int    `json:"rrPairs"`
		Upstreams   int    `json:"upstreams"`
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	_ = json.Unmarshal(body, &req)
	opts := gen.DefaultOptions()
	if req.Seed != 0 {
		opts.Seed = req.Seed
	}
	if req.Cities > 0 {
		opts.Cities = req.Cities
	}
	if req.Prefixes > 0 {
		opts.Prefixes = req.Prefixes
	}
	if req.EdgePerCity > 0 {
		opts.EdgePerCity = req.EdgePerCity
	}
	if req.RRPairs > 0 {
		opts.RRPairs = req.RRPairs
	}
	if req.Upstreams > 0 {
		opts.Upstreams = req.Upstreams
	}
	name := req.Session
	if name == "" {
		name = "default"
	}
	if name == "default" {
		// Never mutate the built-in default in place: rebuild it.
		sess, err := s.buildSession(name, opts)
		if err != nil {
			writeErr(w, 500, "generate failed: %v", err)
			return
		}
		s.mu.Lock()
		s.sessions[name] = sess
		s.mu.Unlock()
		writeJSON(w, map[string]any{"ok": true, "session": name,
			"routers": len(sess.Net.Routers), "prefixes": len(sess.Net.PrefixesV),
			"rounds": sess.Baseline})
		return
	}
	sess, err := s.buildSession(name, opts)
	if err != nil {
		writeErr(w, 500, "generate failed: %v", err)
		return
	}
	s.mu.Lock()
	s.sessions[name] = sess
	s.mu.Unlock()
	writeJSON(w, map[string]any{"ok": true, "session": name,
		"routers": len(sess.Net.Routers), "prefixes": len(sess.Net.PrefixesV),
		"rounds": sess.Baseline})
}

// handleImport accepts a network plus optional ROAs and traffic as JSON.  The
// shape matches model.Network; that is the "export a router config and a RIB"
// entry point in practice, since the parser for vendor configs lives outside
// this project.
func (s *Server) handleImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, 405, "POST required")
		return
	}
	var n model.Network
	body, _ := io.ReadAll(io.LimitReader(r.Body, 256<<20))
	if err := json.Unmarshal(body, &n); err != nil {
		writeErr(w, 400, "bad network JSON: %v", err)
		return
	}
	if n.Name == "" {
		n.Name = "imported"
	}
	if err := n.Build(); err != nil {
		writeErr(w, 400, "network is invalid: %v", err)
		return
	}
	if len(n.Policies) == 0 {
		n.Policies = gen.DefaultPolicy(n.Routers[0].ASN, nil)
		if err := n.Build(); err != nil {
			writeErr(w, 400, "network is invalid after default policy: %v", err)
			return
		}
	}
	pol, err := policy.Compile(&n)
	if err != nil {
		writeErr(w, 400, "policy error: %v", err)
		return
	}
	e := sim.New(&n, pol, rpki.New(n.ROAs))
	e.Seed()
	rounds := e.Converge(200)
	sess := &Session{Net: &n, Pol: pol, RPKI: rpki.New(n.ROAs), Base: e, Live: e,
		Baseline: rounds, LastRun: time.Now()}
	s.mu.Lock()
	s.sessions[n.Name] = sess
	s.mu.Unlock()
	writeJSON(w, map[string]any{"ok": true, "session": n.Name, "routers": len(n.Routers),
		"prefixes": len(n.PrefixesV), "rounds": rounds})
}

func (s *Server) handleDampening(w http.ResponseWriter, r *http.Request) {
	sess := s.session(r)
	defer sess.mu.Unlock()
	if r.Method == http.MethodGet {
		writeJSON(w, map[string]any{
			"config": sess.Net.Config.Dampening,
			"state":  sess.Live.Damp.Snapshot(),
		})
		return
	}
	var cfg model.DampeningConfig
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err := json.Unmarshal(body, &cfg); err != nil {
		writeErr(w, 400, "bad JSON: %v", err)
		return
	}
	sess.Net.Config.Dampening = cfg
	e := sim.New(sess.Net, sess.Pol, sess.RPKI)
	e.CloneFrom(sess.Base)
	sess.Base = e
	sess.Live = e
	writeJSON(w, map[string]any{"ok": true, "config": cfg})
}

// StepNames is exposed for the UI legend.
func StepNames() []string {
	var out []string
	for i := 0; ; i++ {
		name := bgp.StepName(i)
		if name == "unknown" {
			break
		}
		out = append(out, name)
	}
	return out
}
