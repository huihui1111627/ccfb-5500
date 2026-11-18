package bgpsim

import (
	"fmt"
	"hash/fnv"
)

// FiveTuple 是参与 ECMP 哈希的五元组。
type FiveTuple struct {
	SrcIP   string `json:"src_ip"`
	DstIP   string `json:"dst_ip"`
	Proto   uint8  `json:"proto"` // 1=ICMP 6=TCP 17=UDP
	SrcPort uint16 `json:"src_port"`
	DstPort uint16 `json:"dst_port"`
}

// Hash 返回五元组的 64 位 FNV-1a 哈希值。
// 选 FNV 是因为它在 Go 标准库内、零依赖，且分流均匀性足以支撑仿真。
func (f FiveTuple) Hash() uint64 {
	h := fnv.New64a()
	fmt.Fprintf(h, "%s|%s|%d|%d|%d", f.SrcIP, f.DstIP, f.Proto, f.SrcPort, f.DstPort)
	return h.Sum64()
}

// SelectECMPPath 在等价路径集合中按五元组哈希确定性地选一条。
// paths 为空时返回 -1。
func SelectECMPPath(paths []*Route, flow FiveTuple) int {
	if len(paths) == 0 {
		return -1
	}
	return int(flow.Hash() % uint64(len(paths)))
}
