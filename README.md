# BGP 路由策略仿真与验证平台

给省级教育网出口做 BGP 策略的仿真与验证：把路由器配置和路由表导进来，改策略前先在仿真里跑一遍，看选路结果、故障收敛和每条上游的预计利用率，再决定要不要下发。

整个项目是一个 Go 程序加一份内嵌的网页，没有数据库，也没有外部依赖。仿真本身是确定性的，同样输入永远得到同样输出，方便把一次结论讲给别人听。

## 快速开始

```bash
go build -o bgpsim ./cmd/bgpsim
./bgpsim serve -addr :8080        # 打开 http://localhost:8080
```

默认加载一台生成器造出来的省级网络：56 台路由器、3 家上游运营商、24000 条前缀、约 7 万条通告。

其它命令：

```bash
./bgpsim verify -cities 12 -prefixes 4000      # 无界面跑完整场景套件，输出收敛轮数与不变量检查
./bgpsim verify -json                          # 同样的结果，JSON 格式，便于接入 CI
./bgpsim generate -o net.json -prefixes 24000  # 导出一份生成的网络（含策略、ROA、流量矩阵）
```

跑测试：

```bash
go test ./...
```

## 页面

网页分六块，和日常工作流对应：

| 页面 | 用途 |
| --- | --- |
| 拓扑 | 全部路由器与链路，按角色着色；点节点看详情，再跳到它的路由表。故障与过载链路标红 |
| 路由表 | 任意路由器的 Loc-RIB，分页、按前缀过滤；每条前缀上的「为什么？」展开选路全过程 |
| 策略编辑 | 可视化编辑策略链，支持团体、前缀列表、AS_PATH 正则、RPKI 状态匹配，以及改本地优先级、前置 AS_PATH、打团体标签；应用后从冷启动重新收敛 |
| 故障仿真与回放 | 勾选要断的路由器或链路，逐轮回放每台路由器的路由表变化，统计收敛轮数 |
| 流量与出口利用率 | 按前缀流量矩阵和当前选路结果，算出每条上游链路和每条内部链路的利用率，超过 100% 标红 |
| 场景验证 | 一键跑完整场景套件，列出每个场景的收敛轮数、黑洞数、路由环数 |

页面状态可以用 URL 片段直接引用：`#rib/border-1-2/58.17.97.0%2F24` 打开某台路由器对某条前缀的选路解释，`#policy/deny-bogons` 打开某条策略，`#verify` 自动跑验证。

## 选路模型

候选路径来自本地起源路由和每个对等体的 Adj-RIB-In。选择顺序完全按协议，并且每一步都记录下谁被淘汰、为什么：

1. **locally originated (weight)** — 本地起源的路由永远优先
2. **highest local-preference** — 最高本地优先级，绝对值
3. **shortest AS_PATH** — AS_SET 只算一跳
4. **lowest ORIGIN** — IGP < EGP < INCOMPLETE
5. **lowest MED** — 默认只在同一个相邻 AS 之间比较；打开 always-compare-med 才跨 AS
6. **eBGP over iBGP**
7. **lowest IGP metric to next hop** — 到出口路由器的域内最短路径代价
8. **lowest router ID** — 反射路由用 ORIGINATOR_ID
9. **shortest CLUSTER_LIST**
10. **lowest peer BGP identifier**

第 7 步之后仍然并列的路径构成 ECMP 组，组大小由 `ecmpMaxPaths` 限制；剩下的并列由第 8–10 步挑出唯一一条用于通告，但不会把 ECMP 成员踢出转发组。这是真实路由器的行为：安装多径和选择通告路径是两件事。

MED 的比较有一个容易踩的坑：默认跨 AS 不比较。平台把这两条 MED 比较路径都在 trace 里写清楚，页面上能直接看到「从不同相邻 AS 来的 MED 被忽略，落到 IGP 开销」。

### 路由反射

按 RFC 4456 实现：

- 客户端路由反射给客户端和非客户端；非客户端路由只反射给客户端；从不反射回来源。
- 反射时把本反射器的 cluster ID 加进 CLUSTER_LIST；已经有自己 cluster ID 的路由不再反射，这是两个反射器之间不成环的关键。
- ORIGINATOR_ID 记录首个在 AS 内通告该路由的路由器，路由器 ID 比较时用它。
- 没有配置反射器时退化成 iBGP 全互联，iBGP 路由不再转发给 iBGP（水平分割）。

参考用例 `two-reflectors-do-not-form-a-loop` 用两个同 cluster 的反射器验证了这一点。

### eBGP 与 iBGP 的通告规则

- eBGP 发送时前置自己的 AS 号、重置 LOCAL_PREF 和 MED；接收时检查 AS_PATH 不含本 AS。
- iBGP 发送时保留 LOCAL_PREF，不改 AS_PATH，下一跳是出口路由器。
- 一条路由只有在自己的出口路由器通过 IGP 可达时才会被安装，否则当作下一跳不可达丢弃。这是链路故障后路由真正消失、而不是变成黑洞的原因。

## 策略

策略由「匹配」和「动作」两部分组成，可以绑定到路由器、邻居和方向（import / export / both）。未绑定的策略对所有路由器生效。

匹配条件（全部满足才算命中）：

- **前缀列表** — 标准 `ge`/`le` 语义，第一条命中的条目决定结果
- **AS_PATH 正则** — 用下划线 `_` 表示 AS 边界，`_64500_` 匹配路径中出现 AS64500，`^65001` 匹配以它开头
- **团体属性** — `ASN:value` 格式，`any` 或 `all`
- **RPKI 状态** — valid / invalid / notfound

动作：

- **permit / deny**
- **setLocalPref** — 设置本地优先级
- **prepend** — 前置 AS_PATH，次数和使用的 AS 号可配
- **addCommunities** — 打团体标签

导出方向的策略在 AS_PATH 前置之后执行，导入方向在 RPKI 校验之后执行。应用策略相当于做一次入方向软重置：平台从冷启动重新收敛，因为缓存里的 Adj-RIB-In 还带着旧属性，只重算选择结果会漏掉属性变化。

## RPKI 起源校验

按 RFC 6811 的三态语义：

- **valid** — 有覆盖该前缀的 ROA，起源 AS 与 ROA 一致，且前缀长度不超过 maxLength
- **invalid** — 有 ROA 覆盖地址空间，但起源 AS 不匹配，或前缀比 maxLength 更具体
- **notfound** — 没有任何 ROA 覆盖

校验只在 eBGP 边界做，iBGP 路由保留入网时的状态。「无效前缀按策略降级或丢弃」通过 `rpkiMode` 配置：`degrade` 把本地优先级降到 `rpkiDegradeLocalPref`（默认 40），`drop` 直接丢弃，`off` 忽略。也可以用策略的 RPKI 状态匹配做更细的处理。

ROA 查询按前缀长度分桶，一次查询只走覆盖该地址的前缀长度，不会扫全表。

## 路由翻动抑制

RFC 2439 风格。每条 (路由器, 前缀) 维护一个惩罚值：

- 每次撤销加一个固定惩罚（默认 1000）
- 超过抑制阈值（默认 2000）开始抑制，此时该前缀不再安装、不再通告
- 惩罚值按半衰期（默认 900 秒）指数衰减
- 低于复用阈值（默认 750）再放出来，需要两轮半衰期

`TestDampeningDecay` 直接验证算术：两次翻动后惩罚 2000 触发抑制，一个半衰期后 1000 仍然抑制，两个半衰期后 500 释放。`TestDampeningSuppressesFlappingPrefix` 让一个起源反复上下线，验证前缀最终被抑制。

## ECMP 分流

同一前缀有多条等价路径时，按五元组（源/目的 IP、源/目的端口、协议）做 FNV-1a 哈希分流，等价路径条数由 `ecmpMaxPaths` 配置。

`ecmp.Distribute` 用合成的流身份把前缀流量分到各成员，所以流量页面上的分配反映的是哈希后的实际分布，而不是理想均分。

## 故障仿真与收敛回放

注入故障时：

1. 断掉的会话两侧立刻清空 Adj-RIB-In —— 这是 BGP speaker 看到会话断开后的第一反应
2. 断掉的路由器清空整个 RIB
3. 重新计算 IGP，所有已安装路由重新评估，但通过正常的逐轮传播路径发生
4. 故障期间一直断着的会话不需要全表，只有恢复的会话做初始全表交换

每一轮的路由变更都记录在 `Changes` 里（路由器、前缀、通告/撤销、AS_PATH、LP、下一跳），回放页面按轮展示，能看到通告波如何一圈圈扩散出去。

**收敛轮数就是第二轮收敛实际用掉的轮数**，不是从头冷启动的轮数。这更接近工程师关心的「这次变更多久能收敛完」。

## 场景验证

`bgpsim verify` 和页面上的「场景验证」跑同一套场景：

- **baseline** — 冷启动
- **router-failure** — 逐台断掉边界路由器、一台上游路由器、一台汇聚路由器
- **link-failure** — 断核心链路、汇聚链路、上游链路
- **policy-change** — 提高某家上游的本地优先级；完全拒绝某家上游

每个场景检查三件事：

- **已收敛** — 在 200 轮内稳定
- **无敌路由环** — 本 AS 内没有一条已安装路径在本 AS 之后又绕回本 AS
- **无黑洞** — 已安装路径的下一跳都 IGP 可达

并统计收敛轮数。

生成器造的网络里会有单归属的接入路由器，断掉它所在的汇聚路由器后这些前缀会丢；这本身就是真实结论，验证输出会列出丢失的前缀数量。

## 生成器

`internal/gen` 造的是两类前缀，因为它们的行为完全不同：

- **省内前缀** 由接入站点起源，再经由三家上游回流。回流路径带各家的 transit AS 和团体标签，正是本地优先级和 AS_PATH 策略作用的对象。
- **外部 Internet 前缀** 在省外起源，每家上游各给一份，主上游路径更短，其余多一跳，MED 和 ORIGIN 各不相同，让选路有东西可比。

ROA 覆盖大部分前缀，其中一部分故意指向错误的起源 AS，让 RPKI 的三条路径（valid / invalid / notfound）都有流量。流量矩阵按前缀给，规模调到三家上游在基线下约 60% 利用率、断掉一个边界后某家超过 100%。

## 代码结构

```
cmd/bgpsim              命令行入口：serve / verify / generate
internal/model          拓扑、属性、策略、配置的数据模型与 Build
internal/bgp            AS_PATH 属性、决策过程与可解释 trace
internal/policy         策略编译、匹配与动作
internal/rpki           ROA 查询与三态校验
internal/dampening      惩罚值与半衰期衰减
internal/ecmp           五元组哈希分流
internal/sim            逐轮传播引擎：RIB、通告、故障、回放
internal/traffic        流量矩阵到链路利用率
internal/gen            拓扑与前缀生成器，默认策略
internal/scenario       手算参考用例与场景验证
internal/server         HTTP API 与内嵌网页
```

## 参考用例

`internal/scenario/cases_test.go` 里是 11 条手算过的选路用例，每条都在注释里写清楚为什么这么选：

| 用例 | 验证点 |
| --- | --- |
| local-preference-beats-as-path-length | LP 先于 AS_PATH 长度比较 |
| shortest-as-path | 等 LP 时短路径胜出 |
| origin-type-igp-before-egp-before-incomplete | ORIGIN 顺序 |
| med-lower-wins-within-one-neighbour-as | 同一相邻 AS 内 MED 有效 |
| med-not-compared-across-different-as | 跨 AS 默认不比 MED |
| ebgp-preferred-over-ibgp | eBGP 优于 iBGP |
| igp-cost-to-egress | IGP 开销决定出口 |
| router-id-tiebreak | 路由器 ID 兜底 |
| route-reflector-reflects-client-route | 反射器转发客户端路由 |
| two-reflectors-do-not-form-a-loop | 两个反射器不成环 |
| rpki-invalid-loses-to-valid | RPKI 无效路径降级后输给有效路径 |

`internal/scenario/features_test.go` 还覆盖多径安装与上限、五元组哈希分布、四种策略动作、RPKI 三态、翻动抑制的算术与端到端行为、以及 trace 的完整性。

## 已知边界

- 时间是离散的轮，一轮 30 秒，不建模 MRAI 抖动和每会话定时器。用于比较策略和判断收敛轮数足够，不能用来预测秒级收敛时间。
- 不解析厂商配置文本。导入接口接受 `model.Network` 的 JSON 形状；真实环境里需要另外写一个从 `show running-config` / `show ip bgp` 到该结构的转换器。
- 压缩（confederation）没有实现。
- 流量按前缀沿 IGP 最短路归属到出口链路；这是按选路结果的估算，不是逐跳的流量工程模型。
