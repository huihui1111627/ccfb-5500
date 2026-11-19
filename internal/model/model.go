// Package model defines the topology, routing attributes and shared
// configuration types used by the BGP simulator.
//
// The model is deliberately boring: JSON-friendly structs plus a Build step
// that resolves names to dense integer indexes.  The simulator works on the
// dense form because a province-scale network has tens of thousands of
// prefixes and every router keeps a RIB for each of them.
package model

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// INF is used for unreachable IGP metrics.
const INF = int(^uint(0) >> 1)

// ---------------------------------------------------------------------------
// Small attribute types
// ---------------------------------------------------------------------------

// OriginType is the BGP ORIGIN attribute.  Lower values are preferred.
type OriginType uint8

const (
	OriginIGP OriginType = iota
	OriginEGP
	OriginIncomplete
)

func (o OriginType) String() string {
	switch o {
	case OriginIGP:
		return "igp"
	case OriginEGP:
		return "egp"
	case OriginIncomplete:
		return "incomplete"
	}
	return "unknown"
}

func (o OriginType) MarshalJSON() ([]byte, error) { return json.Marshal(o.String()) }

// Valid reports whether the value is one of the three defined ORIGIN types.
func (o OriginType) Valid() bool { return o <= OriginIncomplete }

func (o *OriginType) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "igp", "i", "":
		*o = OriginIGP
	case "egp", "e":
		*o = OriginEGP
	case "incomplete", "?":
		*o = OriginIncomplete
	default:
		return fmt.Errorf("unknown origin type %q", s)
	}
	return nil
}

// ASegType is the type of an AS_PATH segment.
type ASegType uint8

const (
	// ASSequence is an ordered AS_SEQUENCE segment.
	ASSequence ASegType = iota
	// ASSet is an unordered AS_SET segment; it counts as one AS hop.
	ASSet
)

func (t ASegType) String() string {
	if t == ASSet {
		return "set"
	}
	return "seq"
}

// ASeg is one AS_PATH segment.
type ASeg struct {
	Type ASegType `json:"type"`
	ASNs []uint32 `json:"asns"`
}

// Community is a standard BGP community (RFC 1997), rendered as ASN:value.
type Community uint32

func NewCommunity(asn, value uint16) Community {
	return Community(uint32(asn)<<16 | uint32(value))
}

func (c Community) ASN() uint16   { return uint16(c >> 16) }
func (c Community) Value() uint16 { return uint16(c) }

func (c Community) String() string {
	return fmt.Sprintf("%d:%d", c.ASN(), c.Value())
}

func (c Community) MarshalJSON() ([]byte, error) { return json.Marshal(c.String()) }

func (c *Community) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		// also accept a raw uint32
		var n uint32
		if err2 := json.Unmarshal(b, &n); err2 == nil {
			*c = Community(n)
			return nil
		}
		return err
	}
	v, err := ParseCommunity(s)
	if err != nil {
		return err
	}
	*c = v
	return nil
}

func ParseCommunity(s string) (Community, error) {
	s = strings.TrimSpace(s)
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return 0, fmt.Errorf("invalid community %q, want ASN:value", s)
	}
	asn, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil || asn > 0xFFFF {
		return 0, fmt.Errorf("invalid community ASN in %q", s)
	}
	val, err := strconv.ParseUint(parts[1], 10, 16)
	if err != nil {
		return 0, fmt.Errorf("invalid community value in %q", s)
	}
	return NewCommunity(uint16(asn), uint16(val)), nil
}

// ValidationState is the result of an RPKI origin validation (RFC 6811).
type ValidationState string

const (
	RPKIValid    ValidationState = "valid"
	RPKINotFound ValidationState = "notfound"
	RPKIInvalid  ValidationState = "invalid"
)

// ---------------------------------------------------------------------------
// Topology
// ---------------------------------------------------------------------------

type Router struct {
	Name      string   `json:"name"`
	ASN       uint32   `json:"asn"`
	RouterID  string   `json:"routerId,omitempty"`
	ClusterID string   `json:"clusterId,omitempty"`
	RR        bool     `json:"rr,omitempty"`
	Clients   []string `json:"clients,omitempty"`
	Role      string   `json:"role,omitempty"` // core / agg / edge / border / upstream — presentation only
	Tier      string   `json:"tier,omitempty"` // region label used by the UI

	// Derived (dense) form.
	Index      int         `json:"-"`
	ID         uint32      `json:"-"`
	Cluster    uint32      `json:"-"`
	Loopback   netip.Addr  `json:"-"`
	Peers      []int       `json:"-"` // sorted peer router indexes
	PeerSlot   map[int]int `json:"-"` // peer router index -> slot in Peers
	ClientOf   []int       `json:"-"` // RRs for which this router is a client
	Adj        []int       `json:"-"` // link indexes
	Originates []int       `json:"-"` // announcement indexes
}

type Link struct {
	A        string  `json:"a"`
	B        string  `json:"b"`
	Cost     int     `json:"cost"`
	Capacity float64 `json:"capacityGbps,omitempty"`
	Kind     string  `json:"kind,omitempty"` // core, agg, access, upstream

	// Derived.
	Index int `json:"-"`
	AIdx  int `json:"-"`
	BIdx  int `json:"-"`
}

// Announcement is one origin of a prefix by one router.  A prefix can have
// several announcements (the same Internet prefix advertised by three
// upstreams with different attributes).
type Announcement struct {
	Prefix      string      `json:"prefix"`
	Router      string      `json:"router"`
	MED         int         `json:"med,omitempty"`
	OriginType  OriginType  `json:"originType"`
	Communities []Community `json:"communities,omitempty"`
	// ASPath is the path carried by the local route *before* the originating
	// router's own AS number is prepended on eBGP export.  It models upstream
	// transit ASes, e.g. [65001, 64500] means the prefix lives in AS64500 and
	// AS65001 is the transit provider.
	ASPath    []uint32 `json:"asPath,omitempty"`
	LocalPref int      `json:"localPref,omitempty"`

	// Derived.
	PrefixIdx int `json:"-"`
	RouterIdx int `json:"-"`
}

type ROA struct {
	Prefix   string `json:"prefix"`
	MaxLen   int    `json:"maxLength"`
	OriginAS uint32 `json:"originAs"`

	PrefixIdx int `json:"-"`
}

type TrafficEntry struct {
	Prefix   string  `json:"prefix"`
	RateGbps float64 `json:"rateGbps"`
	Source   string  `json:"source,omitempty"` // optional source router

	PrefixIdx int `json:"-"`
}

// Session is a BGP peering, derived from links (eBGP) or from RR/client
// relationships (iBGP).
type Session struct {
	A    int
	B    int
	EBGP bool
	Link int // link index for eBGP, -1 for iBGP
}

type SimConfig struct {
	DefaultLocalPref     int             `json:"defaultLocalPref"`
	AlwaysCompareMED     bool            `json:"alwaysCompareMed"`
	OldestPathFirst      bool            `json:"oldestPathFirst"`
	Multipath            bool            `json:"multipath"`
	ECMPMaxPaths         int             `json:"ecmpMaxPaths"`
	RoundSeconds         int             `json:"roundSeconds"`
	RPKIMode             string          `json:"rpkiMode"` // drop | degrade | off
	RPKIDegradeLocalPref int             `json:"rpkiDegradeLocalPref"`
	Dampening            DampeningConfig `json:"dampening"`
}

type DampeningConfig struct {
	Enabled        bool    `json:"enabled"`
	PenaltyPerFlap float64 `json:"penaltyPerFlap"`
	Suppress       float64 `json:"suppressThreshold"`
	Reuse          float64 `json:"reuseThreshold"`
	HalfLifeSec    float64 `json:"halfLifeSeconds"`
	MaxPenalty     float64 `json:"maxPenalty"`
}

func DefaultSimConfig() SimConfig {
	return SimConfig{
		DefaultLocalPref:     100,
		Multipath:            true,
		ECMPMaxPaths:         4,
		RoundSeconds:         30,
		RPKIMode:             "degrade",
		RPKIDegradeLocalPref: 40,
		Dampening: DampeningConfig{
			Enabled:        false,
			PenaltyPerFlap: 1000,
			Suppress:       2000,
			Reuse:          750,
			HalfLifeSec:    900,
			MaxPenalty:     12000,
		},
	}
}

type Network struct {
	Name          string          `json:"name"`
	Routers       []*Router       `json:"routers"`
	Links         []Link          `json:"links"`
	Prefixes      []string        `json:"prefixes,omitempty"`
	Announcements []*Announcement `json:"announcements"`
	Policies      []Policy        `json:"policies,omitempty"`
	ROAs          []ROA           `json:"roas,omitempty"`
	Traffic       []TrafficEntry  `json:"traffic,omitempty"`
	Config        SimConfig       `json:"config"`

	// Derived.
	PrefixesV []netip.Prefix `json:"-"`
	Sessions  []Session      `json:"-"`
	routerIdx map[string]int
	prefixIdx map[string]int
	// Derived state; never serialised.
	AnnByRouter [][]int  `json:"-"`
	SPF         [][]int  `json:"-"` // all-pairs IGP distance within each AS, -1 unreachable
	ClientOf    [][]int  `json:"-"` // router -> RR indexes
	IsClient    [][]bool `json:"-"` // RR -> client? indexed [rr][router]
}

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

type PrefixListEntry struct {
	Prefix string `json:"prefix"`
	Ge     int    `json:"ge,omitempty"`
	Le     int    `json:"le,omitempty"`
	Action string `json:"action"` // permit | deny
}

type PolicyMatch struct {
	PrefixList     []PrefixListEntry `json:"prefixList,omitempty"`
	ASPathRegex    string            `json:"asPathRegex,omitempty"`
	Communities    []Community       `json:"communities,omitempty"`
	CommunityMatch string            `json:"communityMatch,omitempty"` // any (default) | all
	RPKIStates     []ValidationState `json:"rpkiStates,omitempty"`
}

type PolicyActions struct {
	Action         string      `json:"action,omitempty"` // permit (default) | deny
	SetLocalPref   *int        `json:"setLocalPref,omitempty"`
	PrependCount   int         `json:"prependCount,omitempty"`
	PrependASN     uint32      `json:"prependAsn,omitempty"`
	AddCommunities []Community `json:"addCommunities,omitempty"`
}

type Policy struct {
	Name      string        `json:"name"`
	Router    string        `json:"router,omitempty"`
	Neighbor  string        `json:"neighbor,omitempty"`
	Direction string        `json:"direction,omitempty"` // import | export | both (default both)
	Match     PolicyMatch   `json:"match"`
	Actions   PolicyActions `json:"actions"`
}

// ---------------------------------------------------------------------------
// Build
// ---------------------------------------------------------------------------

// Build resolves names to indexes and derives sessions, SPF distances and
// client relationships.  It is safe to call once per loaded network.
func (n *Network) Build() error {
	if n.Config.DefaultLocalPref == 0 {
		def := DefaultSimConfig()
		// Keep explicitly configured zero values where sensible: only fill
		// fields that were clearly left empty.
		n.Config.DefaultLocalPref = def.DefaultLocalPref
	}
	if n.Config.ECMPMaxPaths == 0 {
		n.Config.ECMPMaxPaths = DefaultSimConfig().ECMPMaxPaths
	}
	if n.Config.RoundSeconds == 0 {
		n.Config.RoundSeconds = DefaultSimConfig().RoundSeconds
	}
	if n.Config.RPKIMode == "" {
		n.Config.RPKIMode = DefaultSimConfig().RPKIMode
	}
	if n.Config.Dampening.PenaltyPerFlap == 0 {
		n.Config.Dampening = DefaultSimConfig().Dampening
	}

	n.routerIdx = make(map[string]int, len(n.Routers))
	for i, r := range n.Routers {
		if r.Name == "" {
			return fmt.Errorf("router %d has no name", i)
		}
		if _, dup := n.routerIdx[r.Name]; dup {
			return fmt.Errorf("duplicate router %q", r.Name)
		}
		n.routerIdx[r.Name] = i
		r.Index = i
		if r.ASN == 0 {
			return fmt.Errorf("router %q has ASN 0", r.Name)
		}
		addr := netip.MustParseAddr(fmt.Sprintf("10.255.%d.%d", i/254, i%254+1))
		if r.RouterID != "" {
			a, err := netip.ParseAddr(r.RouterID)
			if err != nil || !a.Is4() {
				return fmt.Errorf("router %q: bad routerId %q", r.Name, r.RouterID)
			}
			addr = a
		}
		r.Loopback = addr
		b := addr.As4()
		r.ID = uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
		r.Cluster = r.ID
		if r.ClusterID != "" {
			a, err := netip.ParseAddr(r.ClusterID)
			if err != nil || !a.Is4() {
				return fmt.Errorf("router %q: bad clusterId %q", r.Name, r.ClusterID)
			}
			c := a.As4()
			r.Cluster = uint32(c[0])<<24 | uint32(c[1])<<16 | uint32(c[2])<<8 | uint32(c[3])
		}
		r.PeerSlot = make(map[int]int)
	}

	// Prefix universe.
	n.prefixIdx = make(map[string]int)
	addPrefix := func(s string) (int, error) {
		if i, ok := n.prefixIdx[s]; ok {
			return i, nil
		}
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return 0, fmt.Errorf("bad prefix %q: %w", s, err)
		}
		p = p.Masked()
		s = p.String()
		if i, ok := n.prefixIdx[s]; ok {
			return i, nil
		}
		i := len(n.PrefixesV)
		n.PrefixesV = append(n.PrefixesV, p)
		n.prefixIdx[s] = i
		return i, nil
	}
	for _, s := range n.Prefixes {
		if _, err := addPrefix(s); err != nil {
			return err
		}
	}
	for _, a := range n.Announcements {
		idx, err := addPrefix(a.Prefix)
		if err != nil {
			return err
		}
		a.PrefixIdx = idx
		ri, ok := n.routerIdx[a.Router]
		if !ok {
			return fmt.Errorf("announcement for %s references unknown router %q", a.Prefix, a.Router)
		}
		a.RouterIdx = ri
		if !a.OriginType.Valid() {
			return fmt.Errorf("announcement for %s on %s has an invalid ORIGIN type %d", a.Prefix, a.Router, a.OriginType)
		}
	}
	for i := range n.ROAs {
		idx, err := addPrefix(n.ROAs[i].Prefix)
		if err != nil {
			return err
		}
		n.ROAs[i].PrefixIdx = idx
		if n.ROAs[i].MaxLen == 0 {
			n.ROAs[i].MaxLen = n.PrefixesV[idx].Bits()
		}
	}
	for i := range n.Traffic {
		idx, err := addPrefix(n.Traffic[i].Prefix)
		if err != nil {
			return err
		}
		n.Traffic[i].PrefixIdx = idx
		if n.Traffic[i].Source != "" {
			if _, ok := n.routerIdx[n.Traffic[i].Source]; !ok {
				return fmt.Errorf("traffic entry references unknown source router %q", n.Traffic[i].Source)
			}
		}
	}

	n.AnnByRouter = make([][]int, len(n.Routers))
	for ai, a := range n.Announcements {
		n.AnnByRouter[a.RouterIdx] = append(n.AnnByRouter[a.RouterIdx], ai)
	}

	// Links.
	for i := range n.Links {
		l := &n.Links[i]
		ai, ok := n.routerIdx[l.A]
		if !ok {
			return fmt.Errorf("link references unknown router %q", l.A)
		}
		bi, ok := n.routerIdx[l.B]
		if !ok {
			return fmt.Errorf("link references unknown router %q", l.B)
		}
		if ai == bi {
			return fmt.Errorf("link %s-%s is a self loop", l.A, l.B)
		}
		if l.Cost <= 0 {
			l.Cost = 10
		}
		if l.Capacity == 0 {
			l.Capacity = 100
		}
		l.Index = i
		l.AIdx, l.BIdx = ai, bi
		n.Routers[ai].Adj = append(n.Routers[ai].Adj, i)
		n.Routers[bi].Adj = append(n.Routers[bi].Adj, i)
	}

	// Client relationships; auto-attach unrouted non-RR routers to every RR
	// in their AS so that the topology still converges.
	rrByAS := map[uint32][]int{}
	for i, r := range n.Routers {
		if r.RR {
			rrByAS[r.ASN] = append(rrByAS[r.ASN], i)
		}
	}
	n.ClientOf = make([][]int, len(n.Routers))
	n.IsClient = make([][]bool, len(n.Routers))
	for i := range n.Routers {
		n.IsClient[i] = make([]bool, len(n.Routers))
	}
	clientSet := make(map[[2]int]bool)
	addClient := func(rr, client int) {
		if rr == client || clientSet[[2]int{rr, client}] {
			return
		}
		clientSet[[2]int{rr, client}] = true
		n.ClientOf[client] = append(n.ClientOf[client], rr)
		n.IsClient[rr][client] = true
	}
	for _, r := range n.Routers {
		if !r.RR {
			continue
		}
		for _, cname := range r.Clients {
			ci, ok := n.routerIdx[cname]
			if !ok {
				return fmt.Errorf("router %q lists unknown client %q", r.Name, cname)
			}
			if n.Routers[ci].ASN != r.ASN {
				return fmt.Errorf("client %q is not in the same AS as RR %q", cname, r.Name)
			}
			addClient(r.Index, ci)
		}
	}
	for i, r := range n.Routers {
		if r.RR || len(rrByAS[r.ASN]) == 0 {
			continue
		}
		if len(n.ClientOf[i]) == 0 {
			for _, rr := range rrByAS[r.ASN] {
				addClient(rr, i)
			}
		}
	}
	for i := range n.ClientOf {
		sort.Ints(n.ClientOf[i])
	}

	// Sessions.
	seen := map[[2]int]bool{}
	addSession := func(a, b int, ebgp bool, link int) {
		if a == b {
			return
		}
		if a > b {
			a, b = b, a
		}
		k := [2]int{a, b}
		if seen[k] {
			return
		}
		seen[k] = true
		n.Sessions = append(n.Sessions, Session{A: a, B: b, EBGP: ebgp, Link: link})
	}
	for i := range n.Links {
		l := &n.Links[i]
		if n.Routers[l.AIdx].ASN != n.Routers[l.BIdx].ASN {
			addSession(l.AIdx, l.BIdx, true, i)
		}
	}
	for i := range n.Routers {
		rr := n.Routers[i]
		if rr.RR {
			for j := range n.Routers {
				if j != i && n.IsClient[i][j] {
					addSession(i, j, false, -1)
				}
			}
			for _, other := range rrByAS[rr.ASN] {
				if other != i {
					addSession(i, other, false, -1)
				}
			}
		}
	}
	// ASes without any RR fall back to an iBGP full mesh.
	for asn, rs := range routersByAS(n) {
		_ = asn
		if len(rrByAS[asn]) > 0 {
			continue
		}
		for i := 0; i < len(rs); i++ {
			for j := i + 1; j < len(rs); j++ {
				addSession(rs[i], rs[j], false, -1)
			}
		}
	}
	// Drop sessions on links that disappeared?  Links are static here; fault
	// injection removes sessions at simulation time.

	for _, s := range n.Sessions {
		n.Routers[s.A].Peers = append(n.Routers[s.A].Peers, s.B)
		n.Routers[s.B].Peers = append(n.Routers[s.B].Peers, s.A)
	}
	for i, r := range n.Routers {
		sort.Ints(r.Peers)
		r.Peers = dedupeInts(r.Peers)
		for slot, p := range r.Peers {
			r.PeerSlot[p] = slot
		}
		_ = i
	}

	// SPF within each AS, over links whose endpoints share the AS.
	spf := make([][]int, len(n.Routers))
	for i := range spf {
		spf[i] = make([]int, len(n.Routers))
		for j := range spf[i] {
			spf[i][j] = -1
		}
	}
	for asn, rs := range routersByAS(n) {
		_ = asn
		idx := map[int]int{}
		for k, r := range rs {
			idx[r] = k
		}
		dist := make([][]int, len(rs))
		for i := range dist {
			dist[i] = make([]int, len(rs))
			for j := range dist[i] {
				dist[i][j] = -1
			}
			dist[i][i] = 0
		}
		for li := range n.Links {
			l := &n.Links[li]
			ka, oka := idx[l.AIdx]
			kb, okb := idx[l.BIdx]
			if !oka || !okb {
				continue
			}
			if dist[ka][kb] == -1 || l.Cost < dist[ka][kb] {
				dist[ka][kb] = l.Cost
				dist[kb][ka] = l.Cost
			}
		}
		// Floyd-Warshall; AS sizes are small (max a few dozen routers).
		for k := range rs {
			for i := range rs {
				if dist[i][k] < 0 {
					continue
				}
				for j := range rs {
					if dist[k][j] < 0 {
						continue
					}
					if d := dist[i][k] + dist[k][j]; dist[i][j] == -1 || d < dist[i][j] {
						dist[i][j] = d
					}
				}
			}
		}
		for i, ri := range rs {
			for j, rj := range rs {
				spf[ri][rj] = dist[i][j]
			}
		}
	}
	n.SPF = spf

	// Keep Configured policies but validate references early.
	for i, p := range n.Policies {
		if p.Router != "" {
			if _, ok := n.routerIdx[p.Router]; !ok {
				return fmt.Errorf("policy %d (%s) references unknown router %q", i, p.Name, p.Router)
			}
		}
		if p.Neighbor != "" {
			if _, ok := n.routerIdx[p.Neighbor]; !ok {
				return fmt.Errorf("policy %d (%s) references unknown neighbor %q", i, p.Name, p.Neighbor)
			}
		}
	}
	return nil
}

// helper: append to a per-router slice that may not be sized yet

func routersByAS(n *Network) map[uint32][]int {
	m := map[uint32][]int{}
	for i, r := range n.Routers {
		m[r.ASN] = append(m[r.ASN], i)
	}
	return m
}

func dedupeInts(s []int) []int {
	if len(s) < 2 {
		return s
	}
	out := s[:1]
	for _, v := range s[1:] {
		if v != out[len(out)-1] {
			out = append(out, v)
		}
	}
	return out
}

// Router returns the router with the given name.
func (n *Network) Router(name string) *Router {
	i, ok := n.routerIdx[name]
	if !ok {
		return nil
	}
	return n.Routers[i]
}

// RouterIndex returns -1 for an unknown name.
func (n *Network) RouterIndex(name string) int {
	if i, ok := n.routerIdx[name]; ok {
		return i
	}
	return -1
}

func (n *Network) PrefixIndex(s string) int {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return -1
	}
	if i, ok := n.prefixIdx[p.Masked().String()]; ok {
		return i
	}
	return -1
}

func (n *Network) PrefixString(i int) string { return n.PrefixesV[i].String() }

// IGPCost returns the IGP distance from router a to its BGP next hop node.
// For an intra-AS next hop it is the SPF distance; for an eBGP peer it is the
// cost of the connecting link.  -1 means unreachable.
func (n *Network) IGPCost(a, nextHop int) int {
	if a == nextHop {
		return 0
	}
	ra, rb := n.Routers[a], n.Routers[nextHop]
	if ra.ASN == rb.ASN {
		return n.SPF[a][nextHop]
	}
	best := -1
	for _, li := range ra.Adj {
		l := &n.Links[li]
		if (l.AIdx == a && l.BIdx == nextHop) || (l.BIdx == a && l.AIdx == nextHop) {
			if best < 0 || l.Cost < best {
				best = l.Cost
			}
		}
	}
	return best
}

// ASNOf returns the ASN of a router index.
func (n *Network) ASNOf(i int) uint32 { return n.Routers[i].ASN }

// LinkBetween returns the link index between two routers or -1.
func (n *Network) LinkBetween(a, b int) int {
	for _, li := range n.Routers[a].Adj {
		l := &n.Links[li]
		if (l.AIdx == a && l.BIdx == b) || (l.BIdx == a && l.AIdx == b) {
			return li
		}
	}
	return -1
}
