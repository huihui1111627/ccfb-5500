// Package verify 内置一批按 BGP 协议规则手工算好的小场景，
// 对仿真结果逐条断言，并提供断链/改策略批处理与收敛轮数统计。
package verify

import (
	"fmt"
	"strings"

	"github.com/edu-net/bgpsim/internal/bgpsim"
	"github.com/edu-net/bgpsim/internal/damping"
	"github.com/edu-net/bgpsim/internal/engine"
	"github.com/edu-net/bgpsim/internal/policy"
	"github.com/edu-net/bgpsim/internal/rpki"
)

// Result 是单个用例的校验结果。
type Result struct {
	Name   string `json:"name"`
	Pass   bool   `json:"pass"`
	Detail string `json:"detail"`
	// ConvergenceRounds 记录收敛轮数（适用时）。
	ConvergenceRounds int `json:"convergence_rounds,omitempty"`
}

// harness 封装手工小场景的构造。
type harness struct {
	localAS   uint32
	nodes     []*bgpsim.Node
	links     []*bgpsim.Link
	external  []bgpsim.ExternalRoute
	roas      []bgpsim.ROA
	policies  policy.PolicySet
	routerPol []engine.RouterPolicy
	maxPaths  int
	rpkiAct   rpki.InvalidAction
	dampCfg   damping.Config
	stepSec   float64
}

func newHarness() *harness {
	return &harness{
		localAS: 65000, maxPaths: 1,
		rpkiAct: rpki.InvalidDrop,
		dampCfg: damping.DefaultConfig(),
		stepSec: 1,
	}
}

func (h *harness) node(id string, asn uint32, role bgpsim.NodeRole, rrOf ...string) {
	rid := "10.0.0." + strings.TrimPrefix(id, "r")
	h.nodes = append(h.nodes, &bgpsim.Node{
		ID: id, Name: id, ASN: asn, Role: role, RouterID: rid,
		Up: true, RRClientOf: rrOf, X: 0, Y: 0,
	})
}

func (h *harness) link(a, b string, cost int) {
	h.links = append(h.links, &bgpsim.Link{
		ID: "link-" + a + "-" + b, A: a, B: b, IGPCost: cost, Up: true,
	})
}

func (h *harness) ext(prefix, edge, peer string, lp, med uint32, origin string, asPath []uint32, comm ...uint32) {
	h.external = append(h.external, bgpsim.ExternalRoute{
		Prefix: prefix, RouterID: edge, PeerID: peer, NextHop: "nh-" + peer,
		LocalPref: lp, MED: med, Origin: origin, ASPath: asPath, Communities: comm,
	})
}

func (h *harness) build() (*engine.Engine, error) {
	cfg := engine.Config{
		Topology: bgpsim.Topology{
			LocalAS: h.localAS, Nodes: h.nodes, Links: h.links,
			External: h.external, ROAs: h.roas,
		},
		Policies:       h.policies,
		RouterPolicies: h.routerPol,
		Selection:      bgpsim.SelectionOptions{MaxPaths: h.maxPaths},
		RPKIAction:     h.rpkiAct,
		Damping:        h.dampCfg,
		TimeStepSec:    h.stepSec,
	}
	return engine.New(cfg)
}

// winnerOf 返回某节点上某前缀选出的最优路由来源，无路由时为空串。
func winnerOf(e *engine.Engine, node, prefix string) string {
	detail, ok := e.PrefixDetail(node, prefix)
	if !ok {
		return ""
	}
	return detail.Winner
}

// assertEqual 给出带名称的等值断言结果。
func assertEqual(name, got, want string) Result {
	if got == want {
		return Result{Name: name, Pass: true, Detail: fmt.Sprintf("winner=%s", got)}
	}
	return Result{Name: name, Pass: false,
		Detail: fmt.Sprintf("want winner %q, got %q", want, got)}
}
