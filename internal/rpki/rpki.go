// Package rpki 实现基于 ROA 的 BGP 路由起源校验（RFC 6482/6811）。
package rpki

import (
	"net/netip"

	"github.com/edu-net/bgpsim/internal/bgpsim"
)

// roaEntry 是解析后的单条 ROA。
type roaEntry struct {
	asn    uint32
	prefix netip.Prefix
	maxLen int
}

// Validator 持有全部 ROA，对前缀+起源 ASN 给出 valid/invalid/notfound 结论。
// ROA 在构造时一次性解析并按“精确前缀 / 覆盖前缀”分桶，避免每次校验重复解析。
type Validator struct {
	// exact 以被授权前缀字符串为键，保存精确长度 ROA。
	exact map[string][]roaEntry
	// covering 保存可能覆盖更具体前缀的 ROA（用于最大长度/聚合授权场景）。
	covering []roaEntry
}

// NewValidator 构造校验器，预先解析全部 ROA。
func NewValidator(roas []bgpsim.ROA) *Validator {
	v := &Validator{exact: map[string][]roaEntry{}}
	for _, r := range roas {
		p, err := netip.ParsePrefix(r.Prefix)
		if err != nil {
			continue // 忽略非法 ROA，与运行期容错保持一致
		}
		entry := roaEntry{
			asn:    r.ASN,
			prefix: p.Masked(),
			maxLen: r.MaxLen,
		}
		if entry.maxLen <= 0 {
			entry.maxLen = p.Bits()
		}
		// maxLen 等于自身前缀长度时只能精确匹配，进精确桶；否则可能覆盖更具体前缀。
		if entry.maxLen <= p.Bits() {
			v.exact[p.String()] = append(v.exact[p.String()], entry)
		} else {
			v.covering = append(v.covering, entry)
		}
	}
	return v
}

// Validate 按 RFC 6483 判定：
//   - 存在覆盖该前缀、且 ASN 与前缀长度都被授权的 ROA → valid
//   - 有 ROA 覆盖该前缀但 ASN 不匹配或超出 maxLen → invalid
//   - 没有任何 ROA 覆盖 → notfound
func (v *Validator) Validate(prefixStr string, originAS uint32) (bgpsim.RPKIState, error) {
	prefix, err := bgpsim.ParsePrefix(prefixStr)
	if err != nil {
		return bgpsim.RPKINone, err
	}
	covered := false

	// 1) 精确桶：同前缀的 ROA 直接判定。
	if entries, ok := v.exact[prefix.String()]; ok {
		covered = true
		for _, e := range entries {
			if e.asn == originAS && prefix.Bits() <= e.maxLen {
				return bgpsim.RPKIValid, nil
			}
		}
	}

	// 2) 覆盖桶：检查聚合 ROA 是否包含该前缀。
	addr := prefix.Addr()
	for _, e := range v.covering {
		if e.prefix.Addr().BitLen() != addr.BitLen() {
			continue
		}
		if !e.prefix.Contains(addr) {
			continue
		}
		covered = true
		if e.asn == originAS && prefix.Bits() <= e.maxLen {
			return bgpsim.RPKIValid, nil
		}
	}

	if covered {
		return bgpsim.RPKIInvalid, nil
	}
	return bgpsim.RPKINotFound, nil
}

// InvalidAction 决定 RPKI invalid 路由的处理方式。
type InvalidAction string

const (
	// InvalidDrop 直接丢弃 invalid 路由。
	InvalidDrop InvalidAction = "drop"
	// InvalidDowngrade 保留路由但把本地优先级降为惩罚值。
	InvalidDowngrade InvalidAction = "downgrade"
)

// InvalidLocalPref 是降级时使用的本地优先级。
const InvalidLocalPref uint32 = 10
