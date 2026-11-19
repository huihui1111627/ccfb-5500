// Package bgp implements BGP path attributes and the tie-breaking rules of
// the BGP decision process (RFC 4271 section 9.1.2.2, with the usual vendor
// ordering for local preference, MED and multipath).
package bgp

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"bgpsim/internal/model"
)

// Attr is an immutable-ish set of path attributes.  Every mutating helper
// returns a copy, so the same Attr can be shared by many paths (which is what
// happens when a route reflector reflects one route to fifty clients).
type Attr struct {
	Segments      []model.ASeg          `json:"segments,omitempty"`
	ASLen         int                   `json:"asLen"`
	Origin        model.OriginType      `json:"origin"`
	MED           uint32                `json:"med"`
	LocalPref     uint32                `json:"localPref"`
	Communities   []model.Community     `json:"communities,omitempty"`
	RPKI          model.ValidationState `json:"rpki,omitempty"`
	OriginatorID  uint32                `json:"originatorId,omitempty"`
	HasOriginator bool                  `json:"hasOriginator,omitempty"`
	ClusterList   []uint32              `json:"clusterList,omitempty"`
}

// NewAttr returns an empty attribute set with the given local preference.
func NewAttr(localPref uint32) *Attr {
	return &Attr{Origin: model.OriginIGP, LocalPref: localPref}
}

func (a *Attr) clone() *Attr {
	c := *a
	return &c
}

func (a *Attr) WithLocalPref(lp uint32) *Attr {
	c := a.clone()
	c.LocalPref = lp
	return c
}

func (a *Attr) WithMED(m uint32) *Attr {
	c := a.clone()
	c.MED = m
	return c
}

func (a *Attr) WithOrigin(o model.OriginType) *Attr {
	c := a.clone()
	c.Origin = o
	return c
}

func (a *Attr) WithRPKI(s model.ValidationState) *Attr {
	c := a.clone()
	c.RPKI = s
	return c
}

// Prepend adds n copies of asn to the left of the AS_PATH.
func (a *Attr) Prepend(asn uint32, n int) *Attr {
	if n <= 0 {
		return a
	}
	c := a.clone()
	c.Segments = make([]model.ASeg, 0, len(a.Segments)+1)
	added := make([]uint32, n)
	for i := range added {
		added[i] = asn
	}
	if len(a.Segments) > 0 && a.Segments[0].Type == model.ASSequence {
		first := model.ASeg{Type: model.ASSequence, ASNs: append(added, a.Segments[0].ASNs...)}
		c.Segments = append(c.Segments, first)
		c.Segments = append(c.Segments, a.Segments[1:]...)
	} else {
		c.Segments = append(c.Segments, model.ASeg{Type: model.ASSequence, ASNs: added})
		c.Segments = append(c.Segments, a.Segments...)
	}
	c.ASLen = computeASLen(c.Segments)
	return c
}

func computeASLen(segs []model.ASeg) int {
	n := 0
	for _, s := range segs {
		if s.Type == model.ASSet {
			if len(s.ASNs) > 0 {
				n++ // an AS_SET counts as one AS hop
			}
			continue
		}
		n += len(s.ASNs)
	}
	return n
}

func (a *Attr) AddCommunities(cs []model.Community) *Attr {
	if len(cs) == 0 {
		return a
	}
	set := make(map[model.Community]struct{}, len(a.Communities)+len(cs))
	for _, c := range a.Communities {
		set[c] = struct{}{}
	}
	for _, c := range cs {
		set[c] = struct{}{}
	}
	out := make([]model.Community, 0, len(set))
	for c := range set {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	c := a.clone()
	c.Communities = out
	return c
}

func (a *Attr) HasCommunity(c model.Community) bool {
	for _, x := range a.Communities {
		if x == c {
			return true
		}
	}
	return false
}

// WithReflection records route-reflector metadata.  originator is the BGP
// identifier of the first router inside the AS that advertised the route;
// cluster is the reflector's cluster id.
func (a *Attr) WithReflection(cluster, originator uint32) *Attr {
	c := a.clone()
	if !c.HasOriginator {
		c.OriginatorID = originator
		c.HasOriginator = true
	}
	for _, cl := range a.ClusterList {
		if cl == cluster {
			return c // already present, do not duplicate
		}
	}
	c.ClusterList = append(append([]uint32{}, a.ClusterList...), cluster)
	return c
}

func (a *Attr) HasCluster(cluster uint32) bool {
	for _, c := range a.ClusterList {
		if c == cluster {
			return true
		}
	}
	return false
}

// HasAS reports whether asn appears anywhere in the AS_PATH.  Used for the
// eBGP loop check.
func (a *Attr) HasAS(asn uint32) bool {
	for _, s := range a.Segments {
		for _, x := range s.ASNs {
			if x == asn {
				return true
			}
		}
	}
	return false
}

// FirstAS returns the left-most AS in the path (the neighbour AS used for the
// MED comparison), or 0 when the path is empty.
func (a *Attr) FirstAS() uint32 {
	for _, s := range a.Segments {
		if len(s.ASNs) > 0 {
			return s.ASNs[0]
		}
	}
	return 0
}

// OriginAS returns the right-most AS in the path, i.e. the origin AS used by
// RPKI validation.
func (a *Attr) OriginAS() uint32 {
	for i := len(a.Segments) - 1; i >= 0; i-- {
		s := a.Segments[i]
		if len(s.ASNs) > 0 {
			return s.ASNs[len(s.ASNs)-1]
		}
	}
	return 0
}

// ASPathString renders the path in Cisco-ish notation: sequences space
// separated, sets in braces.
func (a *Attr) ASPathString() string {
	if len(a.Segments) == 0 {
		return ""
	}
	var parts []string
	for _, s := range a.Segments {
		if s.Type == model.ASSet {
			parts = append(parts, "{"+joinASNs(s.ASNs)+"}")
			continue
		}
		for _, x := range s.ASNs {
			parts = append(parts, strconv.FormatUint(uint64(x), 10))
		}
	}
	return strings.Join(parts, " ")
}

func joinASNs(asns []uint32) string {
	parts := make([]string, len(asns))
	for i, a := range asns {
		parts[i] = strconv.FormatUint(uint64(a), 10)
	}
	return strings.Join(parts, ",")
}

// CommunityStrings renders communities as ASN:value.
func (a *Attr) CommunityStrings() []string {
	out := make([]string, len(a.Communities))
	for i, c := range a.Communities {
		out[i] = c.String()
	}
	return out
}

// EqualsAttrs compares the attributes that matter for route selection and
// advertising.  Used by convergence replay to decide whether something
// actually changed.
func (a *Attr) EqualsAttrs(b *Attr) bool {
	if a == nil || b == nil {
		return a == b
	}
	if a.ASLen != b.ASLen || a.Origin != b.Origin || a.MED != b.MED ||
		a.LocalPref != b.LocalPref || a.RPKI != b.RPKI ||
		a.OriginatorID != b.OriginatorID || a.HasOriginator != b.HasOriginator ||
		a.ASPathString() != b.ASPathString() {
		return false
	}
	if len(a.Communities) != len(b.Communities) {
		return false
	}
	for i := range a.Communities {
		if a.Communities[i] != b.Communities[i] {
			return false
		}
	}
	if len(a.ClusterList) != len(b.ClusterList) {
		return false
	}
	for i := range a.ClusterList {
		if a.ClusterList[i] != b.ClusterList[i] {
			return false
		}
	}
	return true
}

func (a *Attr) String() string {
	return fmt.Sprintf("lp=%d aslen=%d origin=%s med=%d path=%q", a.LocalPref, a.ASLen, a.Origin, a.MED, a.ASPathString())
}
