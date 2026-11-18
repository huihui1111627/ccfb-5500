// Package bgpsim 定义 BGP 仿真所需的核心数据模型与最优路径选择算法。
package bgpsim

import "fmt"

// Origin 是 BGP 起源属性类型（RFC 4271）。
type Origin uint8

const (
	OriginIGP        Origin = 0
	OriginEGP        Origin = 1
	OriginIncomplete Origin = 2
)

func (o Origin) String() string {
	switch o {
	case OriginIGP:
		return "igp"
	case OriginEGP:
		return "egp"
	default:
		return "incomplete"
	}
}

// ParseOrigin 把文本起源类型转成枚举，无法识别时返回错误。
func ParseOrigin(s string) (Origin, error) {
	switch s {
	case "igp", "IGP":
		return OriginIGP, nil
	case "egp", "EGP":
		return OriginEGP, nil
	case "incomplete", "INCOMPLETE":
		return OriginIncomplete, nil
	default:
		return 0, fmt.Errorf("unknown origin type %q", s)
	}
}

// RPKIState 表示 RPKI 起源校验结果（RFC 6483）。
type RPKIState uint8

const (
	RPKINone RPKIState = iota // 未校验（无 ROA 覆盖）
	RPKIValid
	RPKIInvalid
	RPKINotFound
)

func (s RPKIState) String() string {
	switch s {
	case RPKIValid:
		return "valid"
	case RPKIInvalid:
		return "invalid"
	case RPKINotFound:
		return "notfound"
	default:
		return "none"
	}
}

// PeerType 区分路由从 eBGP 还是 iBGP 学到。
type PeerType uint8

const (
	PeerEBGP PeerType = iota
	PeerIBGP
)

func (p PeerType) String() string {
	if p == PeerEBGP {
		return "eBGP"
	}
	return "iBGP"
}

// Attributes 是一条 BGP 路由的路径属性集合。
type Attributes struct {
	LocalPref   uint32   `json:"local_pref"`
	MED         uint32   `json:"med"`
	Origin      Origin   `json:"origin"`
	ASPath      []uint32 `json:"as_path"`
	Communities []uint32 `json:"communities,omitempty"`
}

// ASPathLen 返回 AS 路径长度（AS 序列中 AS 个数，前置会重复计入）。
func (a Attributes) ASPathLen() int { return len(a.ASPath) }

// ASPathString 把 AS 路径渲染成 "65001 65002" 形式。
func (a Attributes) ASPathString() string {
	if len(a.ASPath) == 0 {
		return ""
	}
	s := fmt.Sprintf("%d", a.ASPath[0])
	for _, asn := range a.ASPath[1:] {
		s += " " + fmt.Sprintf("%d", asn)
	}
	return s
}

// HasCommunity 判断是否携带指定团体值。
func (a Attributes) HasCommunity(c uint32) bool {
	for _, v := range a.Communities {
		if v == c {
			return true
		}
	}
	return false
}

// Clone 深拷贝属性，避免策略修改时共享底层切片。
func (a Attributes) Clone() Attributes {
	cp := a
	cp.ASPath = append([]uint32(nil), a.ASPath...)
	cp.Communities = append([]uint32(nil), a.Communities...)
	return cp
}

// Route 是运行期一条 BGP 路由（Adj-RIB-In / Loc-RIB 表项）。
type Route struct {
	Prefix       string     `json:"prefix"`
	Attrs        Attributes `json:"attrs"`
	NextHop      string     `json:"next_hop"`      // BGP 下一跳（IP 字符串）
	ReceivedFrom string     `json:"received_from"` // 对端路由器节点 ID
	PeerType     PeerType   `json:"peer_type"`
	IGPNextHop   string     `json:"igp_next_hop"` // 解析到的 IGP 下一跳节点 ID
	IGPCost      int        `json:"igp_cost"`     // 到 BGP 下一跳的 IGP 开销
	OriginatorID string     `json:"originator_id,omitempty"`
	ClusterList  []string   `json:"cluster_list,omitempty"`
	RPKI         RPKIState  `json:"rpki"`
	// Suppressed 表示该路由因路由翻动抑制被压住，不参与最优选择也不下发。
	Suppressed bool `json:"suppressed,omitempty"`
	// Penalty 是当前累积的翻动惩罚值。
	Penalty float64 `json:"penalty,omitempty"`
}

// Key 返回路由在单台设备 RIB 内的稳定标识，用于决策追踪时区分候选。
func (r *Route) Key() string {
	return fmt.Sprintf("%s|nh=%s|from=%s|asp=%d", r.Prefix, r.NextHop, r.ReceivedFrom, r.Attrs.ASPathLen())
}

// Clone 深拷贝路由。
func (r *Route) Clone() *Route {
	cp := *r
	cp.Attrs = r.Attrs.Clone()
	cp.ClusterList = append([]string(nil), r.ClusterList...)
	return &cp
}

// NodeRole 描述路由器在拓扑中的角色。
type NodeRole string

const (
	RoleCore     NodeRole = "core"
	RoleAgg      NodeRole = "agg"
	RoleEdge     NodeRole = "edge"
	RoleRR       NodeRole = "rr"
	RoleExternal NodeRole = "external"
)

// Node 是一台路由器或一个外部 AS 边界设备。
type Node struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	ASN        uint32   `json:"asn"`
	Role       NodeRole `json:"role"`
	RouterID   string   `json:"router_id"`
	RRClientOf []string `json:"rr_client_of,omitempty"` // 该节点是哪些 RR 的客户端
	X          float64  `json:"x"`                      // 网页布座标
	Y          float64  `json:"y"`
	Up         bool     `json:"up"`
}

// IsExternal 判断是否为本地 AS 之外的节点。
func (n *Node) IsExternal(localAS uint32) bool { return n.ASN != localAS }

// Link 是两台路由器之间的一条物理/IGP 链路或 eBGP 对接链路。
type Link struct {
	ID      string `json:"id"`
	A       string `json:"a"`
	B       string `json:"b"`
	IGPCost int    `json:"igp_cost"` // 0 表示 eBGP 外部链路（不参与 IGP）
	Up      bool   `json:"up"`
}

// PeerOf 给定链路一端返回另一端节点 ID。
func (l *Link) PeerOf(nodeID string) (string, bool) {
	switch nodeID {
	case l.A:
		return l.B, true
	case l.B:
		return l.A, true
	default:
		return "", false
	}
}

// ExternalRoute 是导入的一条外部路由（在上游边界处注入仿真）。
type ExternalRoute struct {
	Prefix      string   `json:"prefix"`
	RouterID    string   `json:"router_id"` // 接收该路由的本地边缘路由器节点 ID
	PeerID      string   `json:"peer_id"`   // 上游对端节点 ID
	NextHop     string   `json:"next_hop"`  // 上游通告的下一跳 IP
	LocalPref   uint32   `json:"local_pref"`
	MED         uint32   `json:"med"`
	Origin      string   `json:"origin"`
	ASPath      []uint32 `json:"as_path"`
	Communities []uint32 `json:"communities,omitempty"`
}

// ROA 是一条路由起源授权（RPKI）。
type ROA struct {
	ASN    uint32 `json:"asn"`
	Prefix string `json:"prefix"`
	MaxLen int    `json:"max_len"` // -1/0 表示与前缀长度相同
}

// Topology 是一次仿真的完整静态输入。
type Topology struct {
	LocalAS  uint32          `json:"local_as"`
	Nodes    []*Node         `json:"nodes"`
	Links    []*Link         `json:"links"`
	External []ExternalRoute `json:"external_routes"`
	ROAs     []ROA           `json:"roas,omitempty"`
}

// Node 按 ID 取节点。
func (t *Topology) Node(id string) *Node {
	for _, n := range t.Nodes {
		if n.ID == id {
			return n
		}
	}
	return nil
}

// DefaultLocalPref 是本地策略未改写时的默认本地优先级（Cisco/行业惯例 100）。
const DefaultLocalPref = 100
