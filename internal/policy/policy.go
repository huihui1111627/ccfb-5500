// Package policy implements inbound/outbound route policy: prefix lists,
// AS_PATH regular expressions, community matching, and the actions a policy
// can take (set local preference, prepend AS_PATH, tag communities).
package policy

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"bgpsim/internal/bgp"
	"bgpsim/internal/model"
)

// Compiled is a policy with its regular expressions compiled.
type Compiled struct {
	model.Policy
	re       *regexp.Regexp
	prefixes []compiledPrefix
}

type compiledPrefix struct {
	p      netip.Prefix
	ge, le int
	permit bool
}

// Engine holds all policies indexed by (router, direction).
type Engine struct {
	byRouter map[int][]*Compiled
	any      []*Compiled // policies with no router binding, applied everywhere
}

// Compile validates and compiles the policies in net.
func Compile(net *model.Network) (*Engine, error) {
	e := &Engine{byRouter: map[int][]*Compiled{}}
	for i := range net.Policies {
		p := net.Policies[i]
		c := &Compiled{Policy: p}
		if dir := strings.ToLower(p.Direction); dir != "" && dir != "import" && dir != "export" && dir != "both" {
			return nil, fmt.Errorf("policy %q: bad direction %q (want import, export or both)", p.Name, p.Direction)
		}
		for _, ple := range p.Match.PrefixList {
			cp := compiledPrefix{permit: strings.ToLower(ple.Action) != "deny", ge: ple.Ge, le: ple.Le}
			if strings.ToLower(ple.Action) != "deny" && strings.ToLower(ple.Action) != "permit" && ple.Action != "" {
				return nil, fmt.Errorf("policy %q: bad prefix-list action %q", p.Name, ple.Action)
			}
			pp, err := netip.ParsePrefix(ple.Prefix)
			if err != nil {
				return nil, fmt.Errorf("policy %q: bad prefix %q: %w", p.Name, ple.Prefix, err)
			}
			pp = pp.Masked()
			if cp.ge == 0 {
				cp.ge = pp.Bits()
			}
			if cp.le == 0 {
				cp.le = pp.Bits()
			}
			if cp.ge < pp.Bits() || cp.le < cp.ge || cp.le > pp.Addr().BitLen() {
				return nil, fmt.Errorf("policy %q: impossible ge/le for %s (ge=%d le=%d)", p.Name, ple.Prefix, cp.ge, cp.le)
			}
			cp.p = pp
			c.prefixes = append(c.prefixes, cp)
		}
		if p.Match.ASPathRegex != "" {
			expr := p.Match.ASPathRegex
			// Accept the usual ^...$ notation; go regexp is close enough but
			// "_" in Cisco means "AS boundary".  Translate it.
			expr = translateASPathRegex(expr)
			re, err := regexp.Compile(expr)
			if err != nil {
				return nil, fmt.Errorf("policy %q: bad AS_PATH regex %q: %w", p.Name, p.Match.ASPathRegex, err)
			}
			c.re = re
		}
		if act := strings.ToLower(p.Actions.Action); act != "" && act != "permit" && act != "deny" {
			return nil, fmt.Errorf("policy %q: bad action %q", p.Name, p.Actions.Action)
		}
		if p.Router == "" {
			e.any = append(e.any, c)
			continue
		}
		ri := net.RouterIndex(p.Router)
		e.byRouter[ri] = append(e.byRouter[ri], c)
	}
	return e, nil
}

// translateASPathRegex maps the Cisco AS_PATH regex dialect (_ = AS boundary,
// ^ = start, $ = end) onto Go's regexp.  A literal "_" becomes a non-capturing
// boundary that matches start, end, or a space between AS numbers.
func translateASPathRegex(expr string) string {
	// Path is rendered with single spaces.  Replace unescaped "_" with
	// (^| |$) and anchor handling is left to the user.
	var b strings.Builder
	for i := 0; i < len(expr); i++ {
		ch := expr[i]
		if ch == '\\' && i+1 < len(expr) {
			b.WriteByte(ch)
			i++
			b.WriteByte(expr[i])
			continue
		}
		switch ch {
		case '_':
			b.WriteString(`(?:^| |$)`)
		case '^':
			b.WriteByte('^')
		case '$':
			b.WriteByte('$')
		default:
			b.WriteByte(ch)
		}
	}
	out := b.String()
	// If the user wrote no explicit anchor and used _ at edges, ^ and $ are
	// already produced by the boundary expansion.
	return out
}

// Direction constants.
const (
	Inbound  = "import"
	Outbound = "export"
)

// Result is what a policy chain did to a route.
type Result struct {
	Attr      *bgp.Attr `json:"attr"`
	Denied    bool      `json:"denied"`
	DeniedBy  string    `json:"deniedBy,omitempty"`
	Matched   []string  `json:"matched,omitempty"`
	PrependBy int       `json:"prependBy,omitempty"`
	SetLP     *uint32   `json:"setLocalPref,omitempty"`
	SetComm   []string  `json:"setCommunities,omitempty"`
}

// Apply runs the policies for router in the given direction against a route
// for prefix.  Neighbour is the router on the other side of the session (may
// be -1 for locally originated routes).
func (e *Engine) Apply(net *model.Network, router, neighbor int, dir string, prefix netip.Prefix, attr *bgp.Attr) Result {
	res := Result{Attr: attr}
	if e == nil {
		return res
	}
	run := func(list []*Compiled) bool {
		for _, c := range list {
			d := strings.ToLower(c.Direction)
			if d != "" && d != "both" && d != dir {
				continue
			}
			if c.Neighbor != "" {
				if neighbor < 0 || net.Routers[neighbor].Name != c.Neighbor {
					continue
				}
			}
			if !c.matches(prefix, res.Attr) {
				continue
			}
			res.Matched = append(res.Matched, c.Name)
			if strings.ToLower(c.Actions.Action) == "deny" {
				res.Denied = true
				res.DeniedBy = c.Name
				return false
			}
			if c.Actions.SetLocalPref != nil {
				lp := uint32(*c.Actions.SetLocalPref)
				res.Attr = res.Attr.WithLocalPref(lp)
				v := lp
				res.SetLP = &v
			}
			if c.Actions.PrependCount > 0 {
				asn := c.Actions.PrependASN
				if asn == 0 {
					asn = net.Routers[router].ASN
				}
				res.Attr = res.Attr.Prepend(asn, c.Actions.PrependCount)
				res.PrependBy += c.Actions.PrependCount
			}
			if len(c.Actions.AddCommunities) > 0 {
				res.Attr = res.Attr.AddCommunities(c.Actions.AddCommunities)
				for _, cm := range c.Actions.AddCommunities {
					res.SetComm = append(res.SetComm, cm.String())
				}
			}
		}
		return true
	}
	// Router-bound policies first, then global ones.
	if !run(e.byRouter[router]) {
		return res
	}
	if !run(e.any) {
		return res
	}
	return res
}

func (c *Compiled) matches(prefix netip.Prefix, attr *bgp.Attr) bool {
	m := c.Match
	if len(c.prefixes) > 0 {
		// Standard prefix-list semantics: first matching entry decides.
		hit := false
		for _, cp := range c.prefixes {
			if cp.p.Contains(prefix.Addr()) && prefix.Bits() >= cp.ge && prefix.Bits() <= cp.le &&
				cp.p.Bits() <= prefix.Bits() && cp.p.Addr().BitLen() == prefix.Addr().BitLen() {
				if !cp.permit {
					return false
				}
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}
	if c.re != nil {
		if !c.re.MatchString(attr.ASPathString()) {
			return false
		}
	}
	if len(m.Communities) > 0 {
		if strings.ToLower(m.CommunityMatch) == "all" {
			for _, want := range m.Communities {
				if !attr.HasCommunity(want) {
					return false
				}
			}
		} else {
			found := false
			for _, want := range m.Communities {
				if attr.HasCommunity(want) {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
	}
	if len(m.RPKIStates) > 0 {
		ok := false
		for _, s := range m.RPKIStates {
			if string(s) == string(attr.RPKI) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// AS_PATH regex helpers for validation and for the generator
// ---------------------------------------------------------------------------

// ValidateASPathRegex is exported so the HTTP layer can reject bad input with
// a useful message instead of at simulation time.
func ValidateASPathRegex(s string) error {
	if s == "" {
		return nil
	}
	_, err := regexp.Compile(translateASPathRegex(s))
	return err
}

// Describe renders a policy as a one-line human summary.
func Describe(p model.Policy) string {
	var parts []string
	if len(p.Match.PrefixList) > 0 {
		var ss []string
		for _, pl := range p.Match.PrefixList {
			act := pl.Action
			if act == "" {
				act = "permit"
			}
			s := act + " " + pl.Prefix
			if pl.Ge != 0 || pl.Le != 0 {
				s += fmt.Sprintf(" ge %d le %d", pl.Ge, pl.Le)
			}
			ss = append(ss, s)
		}
		parts = append(parts, "prefix-list ["+strings.Join(ss, ", ")+"]")
	}
	if p.Match.ASPathRegex != "" {
		parts = append(parts, "as-path ~"+p.Match.ASPathRegex)
	}
	if len(p.Match.Communities) > 0 {
		var ss []string
		for _, c := range p.Match.Communities {
			ss = append(ss, c.String())
		}
		parts = append(parts, "community "+strings.Join(ss, ","))
	}
	act := []string{}
	if p.Actions.Action == "deny" {
		act = append(act, "deny")
	}
	if p.Actions.SetLocalPref != nil {
		act = append(act, "local-pref "+strconv.Itoa(*p.Actions.SetLocalPref))
	}
	if p.Actions.PrependCount > 0 {
		act = append(act, fmt.Sprintf("prepend %d", p.Actions.PrependCount))
	}
	if len(p.Actions.AddCommunities) > 0 {
		var ss []string
		for _, c := range p.Actions.AddCommunities {
			ss = append(ss, c.String())
		}
		act = append(act, "add-community "+strings.Join(ss, ","))
	}
	if len(act) == 0 {
		act = append(act, "permit")
	}
	return "match " + strings.Join(parts, " AND ") + " => " + strings.Join(act, " ")
}
