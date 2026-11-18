package bgpsim

import (
	"fmt"
	"net/netip"
)

// Prefix 是对 netip.Prefix 的轻量封装，提供仿真里需要的比较与匹配工具。
type Prefix struct {
	p netip.Prefix
}

// ParsePrefix 解析 "10.0.0.0/8" 形式的 IPv4/IPv6 前缀。
func ParsePrefix(s string) (Prefix, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return Prefix{}, err
	}
	return Prefix{p: p.Masked()}, nil
}

// MustParsePrefix 解析失败时 panic，仅用于生成器和测试中的常量。
func MustParsePrefix(s string) Prefix {
	p, err := ParsePrefix(s)
	if err != nil {
		panic(err)
	}
	return p
}

// String 返回规范前缀字符串。
func (p Prefix) String() string { return p.p.String() }

// Bits 返回前缀长度。
func (p Prefix) Bits() int { return p.p.Bits() }

// Addr 返回前缀地址。
func (p Prefix) Addr() netip.Addr { return p.p.Addr() }

// Contains 判断 p 是否完全覆盖 other（含相同前缀）。
func (p Prefix) Contains(other Prefix) bool {
	if p.p.Addr().BitLen() != other.p.Addr().BitLen() {
		return false
	}
	if p.Bits() > other.Bits() {
		return false
	}
	return p.p.Contains(other.p.Addr())
}

// MatchPrefixListRule 按前缀列表规则匹配：
// action 无关，仅判断前缀是否落在 rule 内且 ge/le 长度条件满足。
// ge、le 为 0 表示未设置。
func (p Prefix) MatchPrefixListRule(rulePrefix string, ge, le int) (bool, error) {
	rule, err := ParsePrefix(rulePrefix)
	if err != nil {
		return false, fmt.Errorf("bad prefix-list entry %q: %w", rulePrefix, err)
	}
	bits := p.Bits()
	if ge != 0 && bits < ge {
		return false, nil
	}
	if le != 0 && bits > le {
		return false, nil
	}
	if ge == 0 && le == 0 && bits != rule.Bits() {
		return false, nil // 无 ge/le 时要求精确长度匹配
	}
	return rule.Contains(p), nil
}

// Community 把 "65001:100" 形式的团体值编码为 uint32。
// 高 16 位为 ASN，低 16 位为自定义值。
func Community(asn, value uint32) uint32 {
	return (asn << 16) | (value & 0xffff)
}

// ParseCommunity 解析 "65001:100" 或纯数字团体值。
func ParseCommunity(s string) (uint32, error) {
	var hi, lo uint32
	if _, err := fmt.Sscanf(s, "%d:%d", &hi, &lo); err == nil {
		if hi > 0xffff || lo > 0xffff {
			return 0, fmt.Errorf("community parts must be <= 65535: %q", s)
		}
		return Community(hi, lo), nil
	}
	if _, err := fmt.Sscanf(s, "%d", &hi); err == nil {
		return hi, nil
	}
	return 0, fmt.Errorf("bad community %q (want ASN:NN or number)", s)
}

// CommunityString 把 uint32 团体值渲染为 "ASN:NN"。
func CommunityString(c uint32) string {
	return fmt.Sprintf("%d:%d", c>>16, c&0xffff)
}
