package rpki_test

import (
	"net/netip"
	"testing"

	"bgpsim/internal/model"
	"bgpsim/internal/rpki"
)

func TestThreeStates(t *testing.T) {
	v := rpki.New([]model.ROA{
		{Prefix: "198.51.100.0/24", MaxLen: 24, OriginAS: 65001},
		{Prefix: "203.0.113.0/22", MaxLen: 24, OriginAS: 65002},
	})
	for _, tc := range []struct {
		prefix string
		asn    uint32
		want   model.ValidationState
	}{
		{"198.51.100.0/24", 65001, model.RPKIValid},
		{"198.51.100.0/24", 65002, model.RPKIInvalid},
		{"198.51.100.0/25", 65001, model.RPKIInvalid}, // more specific than maxLength
		{"203.0.113.0/24", 65002, model.RPKIValid},    // within a /22 with maxLength /24
		{"203.0.113.0/25", 65002, model.RPKIInvalid},
		{"203.0.112.0/23", 65002, model.RPKIValid},
		{"8.8.8.0/24", 65001, model.RPKINotFound},
	} {
		got := v.Validate(netip.MustParsePrefix(tc.prefix), tc.asn)
		if got != tc.want {
			t.Errorf("%s origin %d = %s, want %s", tc.prefix, tc.asn, got, tc.want)
		}
	}
}

func TestEmptyTable(t *testing.T) {
	v := rpki.New(nil)
	if v.Enabled() {
		t.Fatal("empty validator should report disabled")
	}
	if got := v.Validate(netip.MustParsePrefix("198.51.100.0/24"), 65001); got != model.RPKINotFound {
		t.Fatalf("state %s, want notfound", got)
	}
}

func TestLongestMatchWins(t *testing.T) {
	// A /16 ROA authorises AS65001; a /24 ROA inside it authorises AS65002.
	// The more specific route must match the /24 ROA.
	v := rpki.New([]model.ROA{
		{Prefix: "198.51.0.0/16", MaxLen: 24, OriginAS: 65001},
		{Prefix: "198.51.100.0/24", MaxLen: 24, OriginAS: 65002},
	})
	if got := v.Validate(netip.MustParsePrefix("198.51.100.0/24"), 65002); got != model.RPKIValid {
		t.Errorf("specific ROA origin: %s, want valid", got)
	}
	if got := v.Validate(netip.MustParsePrefix("198.51.100.0/24"), 65001); got != model.RPKIValid {
		// Both ROAs cover the space; the /16 ROA still authorises 65001, so
		// the result is valid by the /16 match.
		t.Errorf("supernet ROA origin: %s, want valid", got)
	}
}
