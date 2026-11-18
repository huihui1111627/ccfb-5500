# BGP 路由策略仿真与验证平台

面向教育网多上游出口场景的 BGP 路由策略仿真器。把路由器拓扑、外部路由表、ROA 和
流量矩阵导入后，**在改策略或割接之前先在仿真里逐轮跑一遍**，输出每条前缀的选路
原因、故障收敛轮数、路由环/黑洞检查以及各上游链路的预计利用率，避免手工敲命令
配错本地优先级导致整网流量挤到一条线上。

## 能力对照

| 需求 | 实现位置 |
| --- | --- |
| 完整顺序最优路径选择（LocalPref→AS路径→起源→MED→eBGP优先→IGP开销→RouterID），逐级解释 | `internal/bgpsim/decision.go` |
| 路由反射器与 Cluster-List/Originator-ID 防环，多 RR 不反射成环 | `internal/engine/propagate.go` |
| 团体/前缀列表/AS 路径正则匹配；改 LocalPref、前置 AS 路径、打团体 | `internal/policy/policy.go` |
| RPKI 起源校验，invalid 按策略丢弃或降级 | `internal/rpki/rpki.go`、`internal/engine/message.go` |
| 路由翻动抑制：惩罚累加、阈值抑制、半衰期衰减释放 | `internal/damping/damping.go` |
| 等价路径五元组哈希分流，ECMP 条数可配 | `internal/bgpsim/ecmp.go`、`SelectionOptions.MaxPaths` |
| 链路/路由器故障，逐轮回放路由表变化，统计收敛轮数 | `internal/engine/run.go`、快照 `Snapshot` |
| 流量矩阵按选路分摊到出口，计算上游链路利用率 | `internal/traffic/traffic.go` |
| 生成器：几十台路由器、三家上游、数万前缀、ROA、流量矩阵 | `internal/gen/gen.go` |
| 手算用例逐条对比 + 断链/改策略批跑，检查无环无黑洞、统计收敛轮数 | `internal/verify/` |

## 目录结构

```
cmd/bgpsim/            命令行入口（serve / verify / generate）
internal/
  bgpsim/              核心数据模型、选路算法、ECMP 哈希、前缀工具
  policy/              前缀列表、AS 路径正则、团体匹配、route-map
  rpki/                ROA 起源校验
  damping/             路由翻动抑制
  engine/              事件驱动逐轮仿真：消息、反射、IGP、故障、快照、环/黑洞检测
  traffic/             流量矩阵与出口利用率
  gen/                 大规模场景生成器
  verify/              手算用例与批量场景（含 go test）
  server/              HTTP API 与嵌入的网页（web/）
examples/              generate 导出的示例场景 JSON
```

## 快速开始

```bash
# 1. 跑全部验证（手算用例 + 批量断链/策略场景 + 大规模无环检查）
go run ./cmd/bgpsim verify

# 2. 启动网页平台
go run ./cmd/bgpsim serve -addr :8080
# 浏览器打开 http://localhost:8080

# 3. 导出一份生成的场景
go run ./cmd/bgpsim generate -small -out examples/small
```

## 网页五个标签页

1. **拓扑**：核心/反射器/汇聚/出口/上游分层绘制，点击节点看角色、ASN、RR 归属与邻居。
2. **路由表**：选路由器查看全量选路结果，点任意前缀展开**逐级比较过程**
   （每一级保留了哪些候选、淘汰了谁、原因是什么），含 ECMP 与 RPKI 状态。
3. **策略编辑**：表单构造 route-map（前缀列表/团体/AS 路径正则 + 改 LP/前置/打团体/deny），
   应用到边缘路由器后自动重建引擎并重跑到收敛。
4. **故障仿真 / 收敛回放**：断链路或断路由器后逐轮回放，每轮显示路由表增/删/切换、
   收敛轮数、环与黑洞计数，支持自动播放。
5. **流量与利用率**：按当前选路把前缀流量分摊到 9 条上游链路（3 出口 × 3 运营商），
   柱状图 + 表格显示利用率，超 70% 预警、超 100% 标红。

## 选路顺序（与设备行为对齐）

1. 权重/可达性（被阻尼抑制、策略丢弃的路由不参与）
2. **LocalPref** 高者胜
3. **AS 路径** 短者胜
4. **起源类型** IGP < EGP < incomplete
5. **MED** 低者胜（默认仅相邻 AS 相同时比较，可用 `AlwaysCompareMED` 放开）
6. **eBGP** 优于 iBGP
7. 到下一跳的 **IGP 开销** 低者胜
8. 宣告者 **RouterID** 小者胜（保证确定性）；第 7 步后仍打平的进入 ECMP 集合，
   按 `MaxPaths` 截断，五元组 FNV 哈希选路。

## 仿真模型要点

- **逐轮事件驱动**：一轮内派发全部消息、统一重算受影响路由器（仅重算脏前缀），
  再抓全量快照，因此收敛轮数和路由表变化可完整回放。
- **iBGP 拓扑**：RR 与客户端、RR 之间全互联；普通路由器之间全互联。反射遵循
  RFC 4456 的客户端/非客户端反射规则，Originator-ID 与 Cluster-List 双重防环。
- **防环/黑洞检测**：收敛后沿每台设备的 IGP 下一跳逐跳追踪转发路径，重复访问即环路；
  BGP 下一跳 IGP 不可达即黑洞。
- **确定性**：消息按 (接收方, 发送方, 前缀, 类型) 排序，等开销路径取节点 ID 最小者，
  同一份输入多次运行结果完全一致。

## 测试

```bash
go test ./...
```

- `internal/bgpsim`：选路各级、MED 相邻 AS 规则、ECMP 哈希确定性与均匀性、前缀列表。
- `internal/policy`：前缀列表、AS 路径正则下划线边界、route-map 动作与隐式 deny。
- `internal/rpki`：valid/invalid/notfound 与 maxLen。
- `internal/damping`：抑制阈值、半衰期衰减、自动释放、稳定路由不罚。
- `internal/verify`：20 个手算端到端用例 + 12 个批量故障/策略场景 + 3 万前缀大规模无环检查。

## 性能

3 万前缀（约 7.5 万条外部路由注入、238 万条 BGP 消息）在普通笔记本上约 5 秒、
6 轮收敛。关键优化：IGP 最短路径按拓扑版本缓存、RPKI 校验器预解析 ROA 分桶、
运行期选路不分配决策轨迹（仅页面按需查询时构建）、增量重算脏前缀。
