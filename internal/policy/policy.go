// Package policy 实现 BGP 路由策略的匹配条件与动作。
package policy

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/edu-net/bgpsim/internal/bgpsim"
)

// PrefixListEntry 是一条前缀列表规则。
// ge/le 为 0 表示未设置；语义与 Cisco prefix-list 一致。
type PrefixListEntry struct {
	Prefix string `json:"prefix"`
	GE     int    `json:"ge,omitempty"`
	LE     int    `json:"le,omitempty"`
}

// PrefixList 是命名前缀列表。
type PrefixList struct {
	Name    string            `json:"name"`
	Entries []PrefixListEntry `json:"entries"`
}

// Match 判断前缀是否命中列表中任意一条规则。
func (l *PrefixList) Match(prefixStr string) (bool, error) {
	p, err := bgpsim.ParsePrefix(prefixStr)
	if err != nil {
		return false, err
	}
	for _, e := range l.Entries {
		ok, err := p.MatchPrefixListRule(e.Prefix, e.GE, e.LE)
		if err != nil {
			return false, fmt.Errorf("prefix-list %q: %w", l.Name, err)
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
}

// CommunityMatch 定义团体属性匹配方式。
type CommunityMatch struct {
	Communities []uint32 `json:"communities"`
	// Mode: "any" 命中任一即可，"all" 要求全部携带，缺省为 any。
	Mode string `json:"mode,omitempty"`
}

// Match 判断路由团体属性是否满足条件。
func (m *CommunityMatch) Match(r *bgpsim.Route) bool {
	if len(m.Communities) == 0 {
		return true
	}
	mode := m.Mode
	if mode == "" {
		mode = "any"
	}
	have := map[uint32]bool{}
	for _, c := range r.Attrs.Communities {
		have[c] = true
	}
	hit := 0
	for _, c := range m.Communities {
		if have[c] {
			hit++
		}
	}
	switch mode {
	case "all":
		return hit == len(m.Communities)
	default:
		return hit > 0
	}
}

// ASPathRegexp 封装一条 AS 路径正则。
// 输入采用厂商风格：下划线 _ 自动转换为 AS 边界（逗号/串首/串尾/空格）。
type ASPathRegexp struct {
	raw string
	re  *regexp.Regexp
}

// NewASPathRegexp 编译 AS 路径正则。
func NewASPathRegexp(pattern string) (*ASPathRegexp, error) {
	converted := convertASPathRegex(pattern)
	re, err := regexp.Compile(converted)
	if err != nil {
		return nil, fmt.Errorf("bad as-path regexp %q: %w", pattern, err)
	}
	return &ASPathRegexp{raw: pattern, re: re}, nil
}

// convertASPathRegex 把 Cisco 风格 AS-path 正则转成 Go 正则。语义：
//   - 不含下划线：按子串匹配，"65100" 可命中 "65200 65100 65300"；
//   - 前导 "_"：锚定路径第一个 AS（"_65100" 只匹配以 65100 开头的路径）；
//   - 尾随 "_" 且无前导下划线：锚定路径最后一个 AS（"65100_" 只匹配以 65100 结尾）；
//   - 前后都有 "_"：只锚定开头，后面允许继续接其他 AS；
//   - 中间 "_"：匹配 AS 之间的空白。
func convertASPathRegex(pattern string) string {
	if !strings.Contains(pattern, "_") {
		return pattern
	}
	lead := strings.HasPrefix(pattern, "_")
	trail := strings.HasSuffix(pattern, "_")
	var b strings.Builder
	if lead {
		b.WriteString("^")
	}
	for i := 0; i < len(pattern); i++ {
		if pattern[i] != '_' {
			b.WriteByte(pattern[i])
			continue
		}
		// 首尾下划线只承担锚点职责，锚点在循环外处理；中间下划线转空白。
		if (i == 0 && lead) || (i == len(pattern)-1 && trail) {
			continue
		}
		b.WriteString(`\s+`)
	}
	// 仅“有尾随下划线且无前导下划线”时才锚定串尾。
	if trail && !lead {
		b.WriteString("$")
	}
	return b.String()
}

// Match 对 "65001 65002" 形式的 AS 路径做匹配。
func (a *ASPathRegexp) Match(asPathString string) bool {
	return a.re.MatchString(asPathString)
}

// Raw 返回原始正则文本。
func (a *ASPathRegexp) Raw() string { return a.raw }

// Action 是命中策略后执行的动作集合。
type Action struct {
	SetLocalPref      *uint32  `json:"set_local_pref,omitempty"`
	PrependASPath     []uint32 `json:"prepend_as_path,omitempty"` // 按顺序前置（通常重复本 ASN）
	AddCommunities    []uint32 `json:"add_communities,omitempty"`
	RemoveCommunities []uint32 `json:"remove_communities,omitempty"`
	// Result: permit（默认）/ deny。deny 的路由不进 RIB，等价于丢弃。
	Result string `json:"result,omitempty"`
}

// MatchCondition 是一条 route-map 节点的全部匹配条件，条件之间为 AND。
type MatchCondition struct {
	PrefixLists []string        `json:"prefix_lists,omitempty"`
	Community   *CommunityMatch `json:"community,omitempty"`
	ASPathRegex string          `json:"as_path_regexp,omitempty"`
}

// RouteMapEntry 是 route-map 中一个带序号的节点。
type RouteMapEntry struct {
	Seq     int            `json:"seq"`
	Match   MatchCondition `json:"match"`
	Actions []Action       `json:"actions"`
}

// RouteMap 是命名 route-map，按 Seq 升序逐条匹配，命中即停止。
type RouteMap struct {
	Name    string          `json:"name"`
	Entries []RouteMapEntry `json:"entries"`
}

// PolicySet 是一台设备（或全局）引用的全部策略对象。
type PolicySet struct {
	PrefixLists []PrefixList `json:"prefix_lists"`
	RouteMaps   []RouteMap   `json:"route_maps"`
}

// compiled 是 PolicySet 编译后的可执行形态。
type compiled struct {
	prefixLists map[string]*PrefixList
	asPathRegex map[string]*ASPathRegexp
	routeMaps   map[string]*RouteMap
}

// Compiler 持有编译好的策略集合，可反复对路由求值。
type Compiler struct {
	c compiled
}

// NewCompiler 校验并编译策略集合。
func NewCompiler(ps *PolicySet) (*Compiler, error) {
	c := &Compiler{c: compiled{
		prefixLists: map[string]*PrefixList{},
		asPathRegex: map[string]*ASPathRegexp{},
		routeMaps:   map[string]*RouteMap{},
	}}
	for i := range ps.PrefixLists {
		l := &ps.PrefixLists[i]
		if _, ok := c.c.prefixLists[l.Name]; ok {
			return nil, fmt.Errorf("duplicate prefix-list %q", l.Name)
		}
		for _, e := range l.Entries {
			if _, err := bgpsim.ParsePrefix(e.Prefix); err != nil {
				return nil, fmt.Errorf("prefix-list %q: %w", l.Name, err)
			}
		}
		c.c.prefixLists[l.Name] = l
	}
	for i := range ps.RouteMaps {
		rm := &ps.RouteMaps[i]
		if _, ok := c.c.routeMaps[rm.Name]; ok {
			return nil, fmt.Errorf("duplicate route-map %q", rm.Name)
		}
		for _, e := range rm.Entries {
			if e.Match.ASPathRegex != "" {
				rx, err := NewASPathRegexp(e.Match.ASPathRegex)
				if err != nil {
					return nil, fmt.Errorf("route-map %q seq %d: %w", rm.Name, e.Seq, err)
				}
				c.c.asPathRegex[rm.Name+"#"+fmt.Sprint(e.Seq)] = rx
			}
			for _, plName := range e.Match.PrefixLists {
				if _, ok := c.c.prefixLists[plName]; !ok {
					return nil, fmt.Errorf("route-map %q seq %d references unknown prefix-list %q",
						rm.Name, e.Seq, plName)
				}
			}
		}
		c.c.routeMaps[rm.Name] = rm
	}
	return c, nil
}

// Decision 是一次策略求值结果。
type Decision struct {
	Permit bool
	// Applied 记录实际执行的动作描述，供页面审计。
	Applied []string
}

// Apply 对一条路由按名字执行 route-map。
// 未引用任何 route-map（name 为空）时默认放行且不改属性。
func (c *Compiler) Apply(name string, r *bgpsim.Route) (Decision, error) {
	if name == "" {
		return Decision{Permit: true}, nil
	}
	rm, ok := c.c.routeMaps[name]
	if !ok {
		return Decision{}, fmt.Errorf("unknown route-map %q", name)
	}
	// 按序号升序，命中第一条即停止（与设备行为一致）。
	entries := append([]RouteMapEntry(nil), rm.Entries...)
	sortEntries(entries)
	for _, e := range entries {
		matched, err := c.matchCondition(rm.Name, e, r)
		if err != nil {
			return Decision{}, err
		}
		if !matched {
			continue
		}
		d := Decision{Permit: true}
		for _, act := range e.Actions {
			if act.Result == "deny" {
				d.Permit = false
			}
			if act.SetLocalPref != nil {
				r.Attrs.LocalPref = *act.SetLocalPref
				d.Applied = append(d.Applied, fmt.Sprintf("set local-pref %d", *act.SetLocalPref))
			}
			if len(act.PrependASPath) > 0 {
				r.Attrs.ASPath = append(append([]uint32(nil), act.PrependASPath...), r.Attrs.ASPath...)
				d.Applied = append(d.Applied, fmt.Sprintf("prepend %v", act.PrependASPath))
			}
			for _, comm := range act.AddCommunities {
				if !r.Attrs.HasCommunity(comm) {
					r.Attrs.Communities = append(r.Attrs.Communities, comm)
				}
				d.Applied = append(d.Applied, "add-community "+bgpsim.CommunityString(comm))
			}
			for _, comm := range act.RemoveCommunities {
				filtered := r.Attrs.Communities[:0]
				for _, have := range r.Attrs.Communities {
					if have != comm {
						filtered = append(filtered, have)
					}
				}
				r.Attrs.Communities = filtered
				d.Applied = append(d.Applied, "remove-community "+bgpsim.CommunityString(comm))
			}
		}
		return d, nil
	}
	// 无任何节点命中：route-map 末尾隐式 deny。
	return Decision{Permit: false}, nil
}

func (c *Compiler) matchCondition(rmName string, e RouteMapEntry, r *bgpsim.Route) (bool, error) {
	for _, plName := range e.Match.PrefixLists {
		pl := c.c.prefixLists[plName]
		ok, err := pl.Match(r.Prefix)
		if err != nil {
			return false, err
		}
		if !ok {
			return false, nil
		}
	}
	if e.Match.Community != nil && !e.Match.Community.Match(r) {
		return false, nil
	}
	if e.Match.ASPathRegex != "" {
		rx := c.c.asPathRegex[rmName+"#"+fmt.Sprint(e.Seq)]
		if !rx.Match(r.Attrs.ASPathString()) {
			return false, nil
		}
	}
	return true, nil
}

func sortEntries(entries []RouteMapEntry) {
	sort.Slice(entries, func(i, j int) bool { return entries[i].Seq < entries[j].Seq })
}
