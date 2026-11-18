package rpki

import (
	"testing"

	"github.com/edu-net/bgpsim/internal/bgpsim"
)

func TestValidateStates(t *testing.T) {
	v := NewValidator([]bgpsim.ROA{
		{ASN: 65001, Prefix: "10.0.0.0/16", MaxLen: 24},    // 覆盖型
		{ASN: 65002, Prefix: "192.168.0.0/24", MaxLen: 24}, // 精确型
	})
	cases := []struct {
		prefix string
		asn    uint32
		want   bgpsim.RPKIState
	}{
		{"10.0.1.0/24", 65001, bgpsim.RPKIValid},    // 覆盖且 ASN/长度合法
		{"10.0.1.0/25", 65001, bgpsim.RPKIInvalid},  // 超出 maxLen
		{"10.0.1.0/24", 65999, bgpsim.RPKIInvalid},  // ASN 不匹配
		{"192.168.0.0/24", 65002, bgpsim.RPKIValid}, // 精确匹配
		{"8.8.8.8/32", 15169, bgpsim.RPKINotFound},  // 无 ROA 覆盖
	}
	for _, tc := range cases {
		got, err := v.Validate(tc.prefix, tc.asn)
		if err != nil {
			t.Fatal(err)
		}
		if got != tc.want {
			t.Errorf("%s asn=%d: want %s got %s", tc.prefix, tc.asn, tc.want, got)
		}
	}
}
