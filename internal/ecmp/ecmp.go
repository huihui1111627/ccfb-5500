// Package ecmp implements per-flow load sharing across an ECMP group.
//
// The flow key is the classic 5-tuple; the hash is a fast, stable FNV-1a over
// the key so that flows are spread deterministically across the group.  The
// slice is always the same length as the group so a flow that lands on a path
// which disappears is simply re-hashed on the next simulation round.
package ecmp

import (
	"hash/fnv"
	"net/netip"
)

// FiveTuple identifies one flow.
type FiveTuple struct {
	SrcIP   netip.Addr
	DstIP   netip.Addr
	SrcPort uint16
	DstPort uint16
	Proto   uint8
}

// Index returns the index into a group of n equal-cost paths for this flow.
func Index(t FiveTuple, n int) int {
	if n <= 1 {
		return 0
	}
	h := fnv.New64a()
	var b [20]byte
	s := t.SrcIP.As16()
	d := t.DstIP.As16()
	copy(b[0:16], s[:])
	copy(b[16:20], d[:])
	// fold ports/proto into the hash
	_, _ = h.Write(b[:])
	var p [5]byte
	p[0] = byte(t.SrcPort >> 8)
	p[1] = byte(t.SrcPort)
	p[2] = byte(t.DstPort)
	p[3] = byte(t.DstPort >> 8)
	p[4] = t.Proto
	_, _ = h.Write(p[:])
	return int(h.Sum64() % uint64(n))
}

// Distribute assigns totalGbps across weights (typically equal) using a hash
// over synthetic flow identities, and returns the per-path shares.  This is
// used by the traffic matrix view so utilisation reflects hashed, not
// perfectly even, splitting.
func Distribute(flows int, totalGbps float64, n int) []float64 {
	out := make([]float64, n)
	if n <= 0 {
		return out
	}
	if flows <= 0 || totalGbps <= 0 {
		return out
	}
	for i := 0; i < flows; i++ {
		// Synthetic flow key: vary the destination port and the last octet.
		t := FiveTuple{
			SrcIP:   netip.MustParseAddr("10.0.0.1"),
			DstIP:   netip.AddrFrom4([4]byte{203, 0, byte(i >> 8), byte(i)}),
			SrcPort: 1024,
			DstPort: uint16(1024 + (i*97)%60000),
			Proto:   6,
		}
		out[Index(t, n)] += totalGbps / float64(flows)
	}
	return out
}
