// Package rpki implements ROA-based origin validation (RFC 6811).
//
// A route is:
//   - valid     when a covering ROA exists and the route's origin AS is one of
//     the ROA's origin ASes and the prefix length is <= maxLength;
//   - invalid   when a covering ROA exists but the origin AS does not match, or
//     the prefix is more specific than every covering ROA's maxLength;
//   - not-found when no ROA covers the prefix at all.
package rpki

import (
	"net/netip"
	"sync"

	"bgpsim/internal/bgp"
	"bgpsim/internal/model"
)

// Validator answers validation questions for prefixes.
type Validator struct {
	// roasByLen groups ROAs by the ROA prefix length.  Coverage only depends
	// on the ROA prefix, so a lookup walks the ancestors of the queried prefix
	// and never needs to scan the whole table.  IPv4 only.
	roasByLen [33][]model.ROA
	enabled   bool

	mu    sync.RWMutex
	cache map[cacheKey]model.ValidationState
}

type cacheKey struct {
	p   netip.Prefix
	asn uint32
}

// New builds a validator from ROAs.  Prefixes are normalised with Masked.
func New(roas []model.ROA) *Validator {
	v := &Validator{cache: map[cacheKey]model.ValidationState{}}
	for _, r := range roas {
		p, err := netip.ParsePrefix(r.Prefix)
		if err != nil {
			continue
		}
		p = p.Masked()
		if r.MaxLen == 0 {
			r.MaxLen = p.Bits()
		}
		if r.MaxLen < p.Bits() || r.MaxLen > p.Addr().BitLen() {
			// Ignore malformed ROA rather than failing the whole import.
			continue
		}
		r.Prefix = p.String()
		if p.Bits() > 32 || r.MaxLen > 32 {
			continue
		}
		v.roasByLen[p.Bits()] = append(v.roasByLen[p.Bits()], r)
		v.enabled = true
	}
	return v
}

// Enabled reports whether any ROAs were loaded.
func (v *Validator) Enabled() bool { return v != nil && v.enabled }

// Len returns the number of loaded ROAs.
func (v *Validator) Len() int {
	if v == nil {
		return 0
	}
	n := 0
	for _, g := range v.roasByLen {
		n += len(g)
	}
	return n
}

// Validate returns the RPKI state of a route for prefix advertised with
// originAS.
func (v *Validator) Validate(prefix netip.Prefix, originAS uint32) model.ValidationState {
	if v == nil || !v.enabled {
		return model.RPKINotFound
	}
	prefix = prefix.Masked()
	key := cacheKey{p: prefix, asn: originAS}
	v.mu.RLock()
	if s, ok := v.cache[key]; ok {
		v.mu.RUnlock()
		return s
	}
	v.mu.RUnlock()

	state := v.validate(prefix, originAS)

	v.mu.Lock()
	v.cache[key] = state
	v.mu.Unlock()
	return state
}

func (v *Validator) validate(prefix netip.Prefix, originAS uint32) model.ValidationState {
	// RFC 6811: a route is
	//   - valid     when a VRP matches (covers the address space, the route is
	//     no longer than maxLength, and the origin AS equals the VRP AS);
	//   - invalid   when at least one VRP covers the address space but none
	//     matches (wrong origin, or the route is more specific than maxLength);
	//   - not-found when no VRP covers the address space at all.
	covered := false
	for lp := 0; lp <= prefix.Bits() && lp < len(v.roasByLen); lp++ {
		for _, r := range v.roasByLen[lp] {
			rp, err := netip.ParsePrefix(r.Prefix)
			if err != nil || rp.Addr().BitLen() != prefix.Addr().BitLen() {
				continue
			}
			if !rp.Contains(prefix.Addr()) {
				continue
			}
			covered = true
			if prefix.Bits() <= r.MaxLen && r.OriginAS == originAS {
				return model.RPKIValid
			}
		}
	}
	if covered {
		return model.RPKIInvalid
	}
	return model.RPKINotFound
}

// ValidateAttr stamps the attribute with the validation result.
func (v *Validator) ValidateAttr(prefix netip.Prefix, a *bgp.Attr) *bgp.Attr {
	return a.WithRPKI(v.Validate(prefix, a.OriginAS()))
}

// Stats summarises validation results.
type Stats struct {
	Valid    int `json:"valid"`
	Invalid  int `json:"invalid"`
	NotFound int `json:"notFound"`
	Total    int `json:"total"`
	ROAs     int `json:"roas"`
}

func (s *Stats) add(v model.ValidationState) {
	s.Total++
	switch v {
	case model.RPKIValid:
		s.Valid++
	case model.RPKIInvalid:
		s.Invalid++
	default:
		s.NotFound++
	}
}

// AnnouncementStats validates every announcement origin.
func (v *Validator) AnnouncementStats(net *model.Network) Stats {
	s := Stats{ROAs: v.Len()}
	for _, a := range net.Announcements {
		origin := net.Routers[a.RouterIdx].ASN
		if n := len(a.ASPath); n > 0 {
			origin = a.ASPath[n-1]
		}
		s.add(v.Validate(net.PrefixesV[a.PrefixIdx], origin))
	}
	return s
}
