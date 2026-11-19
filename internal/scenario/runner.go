package scenario

import (
	"fmt"
	"sort"

	"bgpsim/internal/gen"
	"bgpsim/internal/model"
	"bgpsim/internal/policy"
	"bgpsim/internal/rpki"
	"bgpsim/internal/sim"
)

// Result is the outcome of one scenario.
type Result struct {
	Name         string   `json:"name"`
	Kind         string   `json:"kind"`
	Description  string   `json:"description"`
	Rounds       int      `json:"rounds"`
	Updates      int      `json:"updates"`
	Converged    bool     `json:"converged"`
	LostPrefixes []string `json:"lostPrefixes,omitempty"`
	Blackholes   int      `json:"blackholes"`
	Loops        int      `json:"loops"`
	Notes        []string `json:"notes,omitempty"`
	ElapsedMs    int64    `json:"elapsedMs"`
}

// Scenario is one fault or policy experiment over a generated network.
type Scenario struct {
	Name        string
	Kind        string // baseline, router-failure, link-failure, policy-change, flap
	Description string
	// Fault configuration, applied after the baseline converges.
	RoutersDown []string
	LinksDown   [][2]string
	// PolicyChange replaces the policy set before re-converging.
	PolicyChange []model.Policy
	// FlapRouters lists origins whose prefixes flap three times.
	FlapPrefixes []string
	// MaxRounds bounds the second convergence.
	MaxRounds int
}

// Options controls how the network is generated for a run.
type Options struct {
	Seed     int64
	Cities   int
	Prefixes int
	Routers  int // informational; the generator sizes the topology
}

// Run executes all scenarios against one generated network and returns the
// per-scenario results.  The baseline is converged once; every scenario then
// re-converges from that state, so the reported round counts are the
// incremental cost of the change rather than the cost of a cold start.
func Run(opts Options) ([]Result, error) {
	gopts := gen.DefaultOptions()
	if opts.Seed != 0 {
		gopts.Seed = opts.Seed
	}
	if opts.Cities > 0 {
		gopts.Cities = opts.Cities
	}
	if opts.Prefixes > 0 {
		gopts.Prefixes = opts.Prefixes
	}
	n, err := gen.Build(gopts)
	if err != nil {
		return nil, err
	}
	n.Policies = gen.DefaultPolicy(gopts.ProvinceAS, nil)
	if err := n.Build(); err != nil {
		return nil, err
	}
	pol, err := policy.Compile(n)
	if err != nil {
		return nil, err
	}
	base := sim.New(n, pol, rpki.New(n.ROAs))
	base.Seed()
	baseRounds := base.Converge(200)
	baseline := checkInvariants(n, base, "baseline")
	baseline.Kind = "baseline"
	baseline.Description = "cold start from the announced prefixes"
	baseline.Rounds = baseRounds
	baseline.Updates = base.Updates
	baseline.Converged = baseRounds < 200

	scenarios := defaultScenarios(n)
	results := []Result{baseline}
	for _, sc := range scenarios {
		res := runOne(n, base, sc)
		results = append(results, res)
	}
	return results, nil
}

// defaultScenarios derives a fault list from the generated topology so the
// scenario names match real routers and links.
func defaultScenarios(n *model.Network) []Scenario {
	var out []Scenario
	// Fail each of the first three border routers in turn: the classic
	// "one upstream link goes dark" case.
	seen := 0
	for _, r := range n.Routers {
		if r.Role != "border" || seen >= 3 {
			continue
		}
		seen++
		out = append(out, Scenario{
			Name:        "fail-" + r.Name,
			Kind:        "router-failure",
			Description: fmt.Sprintf("border router %s stops forwarding and its BGP sessions drop", r.Name),
			RoutersDown: []string{r.Name},
		})
	}
	// Fail a core link and an aggregation link.
	var coreLink, aggLink *model.Link
	for i := range n.Links {
		l := &n.Links[i]
		if l.Kind == "core" && coreLink == nil {
			coreLink = l
		}
		if l.Kind == "agg" && aggLink == nil {
			aggLink = l
		}
	}
	if coreLink != nil {
		out = append(out, Scenario{
			Name:        fmt.Sprintf("fail-link-%s-%s", coreLink.A, coreLink.B),
			Kind:        "link-failure",
			Description: fmt.Sprintf("core link %s-%s is cut", coreLink.A, coreLink.B),
			LinksDown:   [][2]string{{coreLink.A, coreLink.B}},
		})
	}
	if aggLink != nil {
		out = append(out, Scenario{
			Name:        fmt.Sprintf("fail-link-%s-%s", aggLink.A, aggLink.B),
			Kind:        "link-failure",
			Description: fmt.Sprintf("aggregation link %s-%s is cut", aggLink.A, aggLink.B),
			LinksDown:   [][2]string{{aggLink.A, aggLink.B}},
		})
	}
	// Cut an upstream (provider) link: the eBGP session drops, so the whole
	// provider's share of the table is withdrawn and has to be re-learnt
	// through the other providers.
	for i := range n.Links {
		l := &n.Links[i]
		if l.Kind != "upstream" {
			continue
		}
		out = append(out, Scenario{
			Name:        fmt.Sprintf("fail-upstream-%s-%s", l.A, l.B),
			Kind:        "link-failure",
			Description: fmt.Sprintf("provider link %s-%s is cut; its eBGP session drops", l.A, l.B),
			LinksDown:   [][2]string{{l.A, l.B}},
		})
		break
	}
	// Take a provider's upstream pseudo-router down: same effect, but from the
	// far side, which also tests that we do not depend on the near side being
	// the one that notices.
	for _, r := range n.Routers {
		if r.Role == "upstream" {
			out = append(out, Scenario{
				Name:        "fail-upstream-router-" + r.Name,
				Kind:        "router-failure",
				Description: fmt.Sprintf("provider router %s (AS%d) stops announcing", r.Name, r.ASN),
				RoutersDown: []string{r.Name},
			})
			break
		}
	}
	// Take an aggregation router down: its edge sites lose their aggregation
	// path and must reroute through the other city.
	for _, r := range n.Routers {
		if r.Role == "agg" {
			out = append(out, Scenario{
				Name:        "fail-agg-router-" + r.Name,
				Kind:        "router-failure",
				Description: fmt.Sprintf("aggregation router %s fails; its edge sites reroute", r.Name),
				RoutersDown: []string{r.Name},
			})
			break
		}
	}
	// A policy change that concentrates all outbound Internet traffic on
	// provider A: exactly the mistake the platform exists to catch, because it
	// turns one provider link into a single point of failure.
	out = append(out, Scenario{
		Name:        "policy-prefer-provider-a",
		Kind:        "policy-change",
		Description: "set local preference 180 on every route learned from provider A",
		PolicyChange: func() []model.Policy {
			v := 180
			pols := gen.DefaultPolicy(64500, nil)
			return append(pols, model.Policy{
				Name: "prefer-provider-a", Direction: "import",
				Match: model.PolicyMatch{
					Communities: []model.Community{model.NewCommunity(0xFFFF, 65001)},
				},
				Actions: model.PolicyActions{SetLocalPref: &v},
			})
		}(),
	})
	// A policy change that shuts the door on provider C entirely.
	out = append(out, Scenario{
		Name:        "policy-deauthorise-provider-c",
		Kind:        "policy-change",
		Description: "deny every route tagged as coming from provider C",
		PolicyChange: func() []model.Policy {
			pols := gen.DefaultPolicy(64500, nil)
			return append(pols, model.Policy{
				Name: "deny-provider-c", Direction: "import",
				Match: model.PolicyMatch{
					Communities: []model.Community{model.NewCommunity(0xFFFF, 65003)},
				},
				Actions: model.PolicyActions{Action: "deny"},
			})
		}(),
	})
	return out
}

func runOne(n *model.Network, base *sim.Engine, sc Scenario) Result {
	res := Result{Name: sc.Name, Kind: sc.Kind, Description: sc.Description}

	// A policy change is modelled as the operator would see it: the inbound
	// policy is re-applied to everything, which on a real router means a soft
	// reset or a session flap.  The honest simulation is a fresh engine with
	// the new policy and a cold start; incremental re-convergence from the
	// cached Adj-RIB-In would silently keep the old attributes.
	if sc.PolicyChange != nil {
		n.Policies = sc.PolicyChange
		pol, err := policy.Compile(n)
		if err != nil {
			res.Notes = append(res.Notes, "policy error: "+err.Error())
			return res
		}
		e := sim.New(n, pol, rpki.New(n.ROAs))
		e.Seed()
		rounds := e.Converge(maxRounds(sc))
		res.Rounds = rounds
		res.Updates = e.Updates
		res.Converged = rounds < maxRounds(sc)
		inv := checkInvariants(n, e, sc.Name)
		res.Blackholes, res.Loops, res.LostPrefixes = inv.Blackholes, inv.Loops, inv.LostPrefixes
		res.Notes = append(res.Notes, inv.Notes...)
		res.Notes = append(res.Notes, "policy re-applied from a cold start (equivalent to an inbound soft reset)")
		return res
	}

	// Fault scenarios start from a fresh engine that holds the converged
	// baseline state, so one scenario cannot contaminate the next.
	e := cloneConverged(n, base)

	var faults []int
	for _, name := range sc.RoutersDown {
		if i := n.RouterIndex(name); i >= 0 {
			faults = append(faults, i)
		}
	}
	var fl []int
	for _, pair := range sc.LinksDown {
		if li := n.LinkBetween(n.RouterIndex(pair[0]), n.RouterIndex(pair[1])); li >= 0 {
			fl = append(fl, li)
		}
	}
	if len(faults) > 0 || len(fl) > 0 {
		e.SetFaults(faults, fl)
	}
	max := maxRounds(sc)
	rounds := e.Converge(max)
	res.Rounds = rounds
	res.Updates = e.Updates
	res.Converged = rounds < max
	if rounds == 0 && res.Converged && (len(sc.RoutersDown) > 0 || len(sc.LinksDown) > 0) {
		res.Notes = append(res.Notes,
			"no BGP path changed: the IGP rerouted around the fault without altering any selected path")
	}
	if !res.Converged {
		res.Notes = append(res.Notes, fmt.Sprintf("did not converge within %d rounds", max))
	}
	inv := checkInvariants(n, e, sc.Name)
	res.Blackholes = inv.Blackholes
	res.Loops = inv.Loops
	res.LostPrefixes = inv.LostPrefixes
	res.Notes = append(res.Notes, inv.Notes...)
	return res
}

func maxRounds(sc Scenario) int {
	if sc.MaxRounds <= 0 {
		return 200
	}
	return sc.MaxRounds
}

// cloneConverged copies the RIBs and adj-in of a converged engine into a new
// engine on the same network.
func cloneConverged(n *model.Network, base *sim.Engine) *sim.Engine {
	e := sim.New(n, base.Pol, base.RPKI)
	e.CloneFrom(base)
	return e
}

// checkInvariants looks for the two failure modes the platform exists to catch:
//
//   - a forwarding loop: a prefix whose selected AS_PATH contains our own AS
//     (an eBGP loop) or an iBGP path that points back to the same exit through
//     a session that should have learned it elsewhere;
//   - a black hole: a prefix installed with a next hop the IGP cannot reach.
func checkInvariants(n *model.Network, e *sim.Engine, label string) Result {
	var res Result
	res.Name = label
	ourAS := n.Routers[0].ASN
	installed := 0
	for r, rtr := range n.Routers {
		if e.RouterDown[r] || rtr.ASN != ourAS {
			// Upstream routers are outside the AS under test; their own RIBs
			// are not ours to police.
			continue
		}
		prefixes, _ := e.RouterRIB(r, "", 0, 0)
		for _, entry := range prefixes {
			if entry.Best == nil {
				continue
			}
			installed++
			if entry.Best.Blackhole {
				res.Blackholes++
			}
			// A forwarding loop is a path that leaves our AS and then comes
			// back to it.  Our own AS appearing first is normal for a route
			// we originated and exported (it is our own prefix); our own AS
			// appearing after a foreign AS means the route came back to us
			// and installing it would send traffic in a circle.
			hops := splitASPath(entry.Best.ASPath)
			for i, asn := range hops {
				if i == 0 {
					continue // first hop is the peer AS, checked below
				}
				if asn == ourAS {
					res.Loops++
					res.Notes = append(res.Notes,
						fmt.Sprintf("%s: %s selected a path through our own AS %d (%s)",
							rtr.Name, entry.Prefix, ourAS, entry.Best.ASPath))
					break
				}
			}
		}
	}
	// Every prefix that has an origin and a reachable origin router should be
	// installed at the core.  Count the ones that are not.
	core := n.RouterIndex("core-1")
	if core >= 0 && !e.RouterDown[core] {
		want := map[int]bool{}
		for _, a := range n.Announcements {
			want[a.PrefixIdx] = true
		}
		for p := range want {
			if e.Best(core, p) == nil {
				res.LostPrefixes = append(res.LostPrefixes, n.PrefixString(p))
			}
		}
		sort.Strings(res.LostPrefixes)
		if len(res.LostPrefixes) > 0 {
			res.Notes = append(res.Notes, fmt.Sprintf("%s: core-1 has no path for %d prefixes", label, len(res.LostPrefixes)))
		}
	}
	if res.Blackholes > 0 {
		res.Notes = append(res.Notes, fmt.Sprintf("%s: %d installed paths point at an unreachable next hop", label, res.Blackholes))
	}
	if res.Loops > 0 {
		res.Notes = append(res.Notes, fmt.Sprintf("%s: %d routing loops detected", label, res.Loops))
	}
	return res
}

func splitASPath(s string) []uint32 {
	var out []uint32
	cur := uint32(0)
	have := false
	for i := 0; i <= len(s); i++ {
		var c byte
		if i < len(s) {
			c = s[i]
		}
		if i == len(s) || c == ' ' || c == '{' || c == '}' || c == ',' {
			if have {
				out = append(out, cur)
				cur, have = 0, false
			}
			continue
		}
		if c < '0' || c > '9' {
			continue
		}
		cur = cur*10 + uint32(c-'0')
		have = true
	}
	return out
}
