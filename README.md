# ChargeOps 安全自查平台

面向充电桩运营后台等保自查的本地靶场 + 自动化扫描平台。**仅用于本地授权测试。**

```
target/     故意含漏洞的充电桩运营后台(Flask + SPA)
scanner/    扫描平台(爬虫/检测/复现/复核/报告)
benchmark/  埋点清单(18 个已知漏洞)
tools/      CLI 扫描与基准评测
```

## 一、快速开始

```bash
# 1) 初始化并启动靶场(默认 http://127.0.0.1:5000)
python3 target/seed.py
python3 -m flask --app target.app run --port 5000 --no-reload

# 2) 启动扫描平台(默认 http://127.0.0.1:8000)
python3 -m scanner.server
```

浏览器打开 `http://127.0.0.1:8000/tasks`,新建任务,目标填 `http://127.0.0.1:5000`,点“开始扫描”。

也可以纯命令行跑一轮:

```bash
python3 tools/run_scan.py --target http://127.0.0.1:5000 --rate 8
python3 tools/benchmark.py --task 1
```

## 二、靶场

### 业务与角色

| 角色 | 账号 | 密码 | 可见面 |
|---|---|---|---|
| 管理员 | `admin` | `Admin@123` | 全部 |
| 运营 | `operator` | `Operator@123` | 场站、订单、工单、用户 |
| 财务 | `finance` | `Finance@123` | 发票、结算 |
| 客服 | `support` | `Support@123` | 工单 |
| 车主 A | `alice` | `Alice@123` | 自己的订单/发票/工单 |
| 车主 B | `bob` | `Bob@123` | 自己的订单/发票/工单 |
| 场站合作方 | `merchant` | `Merchant@123` | 场站 |

前端是单页应用(`/static/app.js`),订单、场站、发票、工单、结算、工具等视图全部走 `/api/*`;另有服务端渲染的 `/help/search`、`/notice`、`/profile/<id>`、`/admin/console`。

### 埋点清单(18 个)

| ID | 类型 | 位置 |
|---|---|---|
| SQLI-01 | SQL 注入 | `GET /api/orders` 的 `q` / `sort` |
| SQLI-02 | SQL 注入 | `POST /api/auth/login` 的 `username` |
| XSS-01 | 反射型 XSS | `GET /help/search?keyword=` |
| XSS-02 | 存储型 XSS | 提交工单 → `/notice` 渲染 |
| XSS-03 | 存储型 XSS | 修改显示名 → `/profile/<id>` 渲染 |
| SSRF-01 | SSRF | `GET /api/stations/<id>/cover?url=` |
| SSRF-02 | SSRF | `GET /api/integrations/fetch?url=` |
| TRAV-01 | 路径穿越 | `GET /api/invoices/<id>/attachment?file=` |
| TRAV-02 | 路径穿越 | `GET /api/files/download?path=` |
| IDOR-01 | 水平越权 | `GET /api/orders/<id>` 未校验归属 |
| IDOR-02 | 水平越权 | `GET /api/invoices/<id>` |
| IDOR-03 | 水平越权 | `GET /api/feedback/<id>` |
| IDOR-04 | 水平越权 | `GET /api/users/<id>`(泄露 API Key) |
| BAC-01 | 垂直越权 | `GET /api/admin/users` 无角色校验 |
| BAC-02 | 垂直越权 | `GET /api/admin/api-keys` 无角色校验 |
| BAC-03 | 垂直越权 | `GET /api/finance/settlements` 无角色校验 |
| BAC-04 | 垂直越权 | `PUT /api/profile` 批量赋值改 `role` |
| INFO-01 | 信息泄露 | `GET /api/debug/config` 未授权 |

清单同时存在 `benchmark/vuln_catalog.json`(统计口径以此为准)。

## 三、扫描平台

### 页面

- **扫描任务** `/tasks`:新建、进度、暂停/续扫/停止、埋点清单一览
- **资产** `/assets`:爬到的页面/接口/表单/SPA 请求,含参数与发现角色
- **漏洞** `/findings`:按任务/状态/类型筛选,展开看请求响应原文
- **复核** `/review`:确认/疑似清单,单条重新验证、标误报、恢复
- **报告** `/reports`:HTML/JSON 预览与下载,含检出率/误报率

### 功能实现

1. **带登录态爬全站**:四个角色分别建立会话;解析 `a[href]`、表单、外链 JS 里的 `/api/...` 字面量(含 `method` 与请求体字段);Playwright 真实浏览器点遍 SPA 导航,捕获 XHR/fetch。
2. **注入类检测**:SQL 注入(报错/布尔/联合/时间四类载荷)、反射与存储型 XSS、SSRF、路径穿越、信息泄露、开放重定向。
3. **越权检测**:车主 A 访问车主 B 的订单/发票/工单/用户档案(水平);普通角色访问 admin/finance 接口与批量赋值提权(垂直)。所有请求显式带各自 Cookie,避免会话串号。
4. **自动复现**:每条疑似漏洞由 `scanner/verify.py` 构造独立验证请求,只有复现成功才置为 `confirmed`;验证请求/响应原文单独留存。
5. **多参数合并**:同一接口同一类型只留一条,命中的参数与载荷进 `occurrences`,报告里显示“合并 N 个参数”。
6. **暂停续扫 + 限速**:`HttpEngine` 全局限速器 + `PauseController`;暂停时阻塞在请求前,续扫从未完成阶段开始(阶段进度存于任务 `state`)。
7. **误报抑制**:复核页标误报会写入 `suppressions` 表(按主机 + dedup key),之后同主机扫描在检测与落库两处跳过。
8. **报告**:`scanner/report.py` 生成自包含 HTML 与结构化 JSON,附触发请求、响应原文、复现请求/响应。

### 检出率与误报率口径

- 检出率 = 已确认且能匹配到埋点 ID 的数量 / 清单总数
- 越权检出率 = 已确认的 IDOR+BAC 埋点数 / 其中总数(单独盯,避免被其它类型平均掉)
- 误报率 = (人工标记误报 + 无法匹配任何埋点的“已确认”项) / (已确认总数 + 人工误报数)

`tools/benchmark.py --task N` 会打印逐项 ✓/✗。

## 四、安全边界

- 靶场与扫描器都只监听 `127.0.0.1`。
- 扫描器默认排除 `/api/auth/logout`、订单取消等有副作用的接口;存储型 XSS 写入后会还原显示名。
- 不要把 `target/` 部署到任何可达网络;它的 `SECRET_KEY`、API Key、SMTP/支付凭据都是假数据,但漏洞是真的。

## 五、已知限制

- 存储型 XSS 目前覆盖工单与个人资料两个 sink,新增 sink 需在 `config.STORED_XSS_SINKS`/检测器里补规则。
- 布尔盲注依赖响应长度差异,分页或随机内容会降低准确性。
- 水平越权依赖“受害者资源列表接口”取 ID;若列表接口本身严格鉴权且无详情枚举,需改用人工提供的 ID 字典。
- SPA 抓取依赖本机 Playwright Chromium;无浏览器环境会自动退化为静态 JS 解析。
