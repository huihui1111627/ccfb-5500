"""漏洞检测器:注入、XSS、SSRF、路径穿越、水平/垂直越权、信息泄露、开放重定向。

每个检测器只产出 "疑似" 发现;是否确认由 verify.py 的复现请求决定。
"""
import json
import re
import urllib.parse
from dataclasses import dataclass, field

from scanner import config as C
from scanner.http import HttpEngine, RecordedExchange, ScanStopped

WSCN = {"invoice": "发票", "feedback": "工单", "order": "订单"}


@dataclass
class Candidate:
    category: str
    title: str
    severity: str
    url: str
    method: str
    param: str = ""
    role: str = ""
    confidence: str = "medium"
    evidence: dict = field(default_factory=dict)
    request: str = ""
    response: str = ""
    dedup_key: str = ""
    vuln_id: str = ""
    occurrences: list = field(default_factory=list)

    def add_occurrence(self, param, payload):
        entry = {"param": param, "payload": payload}
        if entry not in self.occurrences:
            self.occurrences.append(entry)


def _host(url: str) -> str:
    return urllib.parse.urlsplit(url).hostname or ""


def _with_query(url: str, params: dict) -> str:
    parsed = urllib.parse.urlsplit(url)
    q = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
    q.update({k: v for k, v in params.items() if v is not None})
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urllib.parse.urlencode(q), ""))


def _replace_path_param(url: str, name: str, value) -> str:
    parsed = urllib.parse.urlsplit(url)
    segs = parsed.path.split("/")
    out = []
    replaced = False
    for seg in segs:
        if not replaced and seg.isdigit():
            out.append(str(value))
            replaced = True
        else:
            out.append(seg)
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, "/".join(out), parsed.query, ""))


class Detectors:
    def __init__(self, engine: HttpEngine, config, sessions, pivot=None):
        self.engine = engine
        self.config = config
        self.sessions = sessions
        self.base = config.target_url.rstrip("/")
        self.candidates: list[Candidate] = []
        self.pivot = pivot  # (role, url, param, value) 参照点
        self.on_progress = None

    # ------------------------------------------------------------ 工具
    def _headers(self, role):
        s = self.sessions.get(role)
        return s.auth_headers() if s else {}

    def _sorted_roles(self):
        order = ["admin", "operator", "finance", "support", "driver", "merchant", "other_driver"]
        return [r for r in order if r in self.sessions.sessions]

    def _emit(self, msg):
        if self.on_progress:
            self.on_progress(msg)

    def _excluded(self, url: str) -> bool:
        return any(p in (url or "") for p in self.config.exclude_patterns)

    # ------------------------------------------------------------ 注入
    def run_injection(self, requests):
        for req in requests:
            if not self.config.check_types:
                return
            if self._excluded(req.url):
                continue
            if "sqli" in self.config.check_types:
                for param in [p for p in req.params if p["in"] in ("query", "body")]:
                    self._test_sqli(req, param)
            if "xss" in self.config.check_types:
                for param in [p for p in req.params if p["in"] in ("query", "body")]:
                    self._test_xss(req, param)
            if "ssrf" in self.config.check_types:
                if any(k in req.url.lower() for k in ("url=", "cover", "/fetch", "callback", "webhook")):
                    self._test_ssrf(req)
            if "traversal" in self.config.check_types:
                if any(k in req.url.lower() for k in ("file=", "path=", "download", "attachment")):
                    self._test_traversal(req)
            if "redirect" in self.config.check_types:
                if "next=" in req.url or "redirect" in req.url.lower():
                    self._test_redirect(req)
            if "info" in self.config.check_types:
                self._test_info_leak(req)

    def _test_sqli(self, req, param):
        role = req.role or "admin"
        baseline = self._baseline(req, role)
        if baseline is None:
            return
        for kind in ("error", "union", "boolean_true", "boolean_false"):
            for payload in C.SQL_PAYLOADS[kind]:
                try:
                    if param["in"] == "query":
                        target = _with_query(req.url, {param["name"]: payload})
                        ex = self.engine.request(req.method, target, headers=self._headers(role))
                    else:
                        body = dict(req_body_json(req.body))
                        body[param["name"]] = payload
                        ex = self.engine.request(req.method, req.url, headers=self._headers(role), json_body=body)
                except ScanStopped:
                    raise
                error_hit = any(m.lower() in (ex.body or "").lower() for m in C.SQL_ERROR_MARKERS)
                if error_hit and not any(m.lower() in (baseline.body or "").lower() for m in C.SQL_ERROR_MARKERS):
                    self._add_sqli(req, param, payload, ex, "error-based", baseline)
                    return
        # 布尔盲注:比较 true/false 响应相似度
        try:
            t_ex = self._send_payload(req, param, C.SQL_PAYLOADS["boolean_true"][0], role)
            f_ex = self._send_payload(req, param, C.SQL_PAYLOADS["boolean_false"][0], role)
        except ScanStopped:
            raise
        if _similar(t_ex, baseline) and not _similar(f_ex, baseline):
            if abs(len(t_ex.body) - len(f_ex.body)) > 30:
                self._add_sqli(req, param, C.SQL_PAYLOADS["boolean_true"][0], t_ex, "boolean-blind", baseline)

    def _add_sqli(self, req, param, payload, ex, technique, baseline):
        dedup = f"sqli|{req.template()}"
        existing = next((c for c in self.candidates if c.dedup_key == dedup), None)
        if existing:
            existing.add_occurrence(param["name"], payload)
            return
        self.candidates.append(Candidate(
            category="sqli", title=f"SQL 注入 · {urllib.parse.urlsplit(req.url).path} 参数 {param['name']}",
            severity="critical", url=req.url, method=req.method, param=param["name"],
            role=req.role, evidence={"technique": technique, "payload": payload,
                                     "baseline_len": len(baseline.body),
                                     "probe_len": len(ex.body),
                                     "error_marker": _first_error(ex.body)},
            request=ex.request, response=ex.response, dedup_key=dedup,
        ))

    def _baseline(self, req, role):
        try:
            return self.engine.request(req.method, req.url, headers=self._headers(role), timeout=self.config.timeout)
        except ScanStopped:
            raise

    def _send_payload(self, req, param, payload, role):
        if param["in"] == "query":
            target = _with_query(req.url, {param["name"]: payload})
            return self.engine.request(req.method, target, headers=self._headers(role))
        body = dict(req_body_json(req.body))
        body[param["name"]] = payload
        return self.engine.request(req.method, req.url, headers=self._headers(role), json_body=body)

    # ------------------------------------------------------------ XSS
    def _test_xss(self, req, param):
        role = req.role or "admin"
        token = f"xss{abs(hash((req.template(), param['name'])) % 10**10):010d}"
        for payload_tpl in C.XSS_PAYLOADS:
            payload = payload_tpl.replace("{token}", token)
            try:
                ex = self._send_payload(req, param, payload, role)
            except ScanStopped:
                raise
            ctype = (ex.headers.get("content-type") or "").lower()
            if "html" not in ctype:
                # JSON/纯文本回显不构成反射型 XSS
                continue
            raw_reflected = _raw_marker(ex.body or "", payload) or payload in (ex.body or "")
            if not raw_reflected:
                continue
            # 判定反射型:重放一次确认稳定,且输出未转义
            confirm = self._send_payload(req, param, payload, role)
            if payload not in (confirm.body or "") and _raw_marker(confirm.body or "", payload):
                confirm = ex
            if payload not in (confirm.body or ""):
                continue
            dedup = f"xss|{req.template()}"
            existing = next((c for c in self.candidates if c.dedup_key == dedup), None)
            if existing:
                existing.add_occurrence(param["name"], payload)
                return
            self.candidates.append(Candidate(
                category="xss", title=f"反射型 XSS · {urllib.parse.urlsplit(req.url).path} 参数 {param['name']}",
                severity="high", url=req.url, method=req.method, param=param["name"],
                role=req.role, evidence={"payload": payload, "token": token, "kind": "reflected",
                                         "raw": True},
                request=confirm.request, response=confirm.response,
                dedup_key=f"xss|{req.template()}",
            ))
            return

    def run_stored_xss(self, sessions):
        """向写入点提交带标记的载荷,再访问渲染页面确认未转义输出。"""
        role = next((r for r in ("driver", "other_driver") if self.sessions.get(r) and self.sessions.get(r).cookies), None)
        if not role:
            return
        sess = self.sessions.get(role)
        # ---- 反馈 -> /notice
        token = "xssstore" + str(abs(hash((self.base, "feedback"))) % 10**8)
        payload = f"<img src=x onerror=window.__XSS_HIT=1 data-t={token}>"
        ex = self.engine.request(
            "POST", self.base + "/api/feedback",
            headers={"Content-Type": "application/json"}, cookies=sess.cookies,
            json_body={"content": payload, "category": "other", "contact": "13900000000"},
        )
        if ex.status_code in (200, 201):
            view = self.engine.request("GET", self.base + "/notice", cookies=sess.cookies)
            if payload in (view.body or ""):
                self.candidates.append(Candidate(
                    category="xss", title="存储型 XSS · 工单内容在公告页未转义输出",
                    severity="high", url=self.base + "/notice", method="GET", param="content",
                    role=role, evidence={"payload": payload, "token": token, "kind": "stored",
                                         "submit": "POST /api/feedback", "sink": "/notice"},
                    request=ex.request, response=view.response,
                    dedup_key=f"xss|{self.base}/api/feedback|content|stored",
                ))
        # ---- 个人资料 -> /profile/<uid>
        token2 = "xssprof" + str(abs(hash((self.base, "profile"))) % 10**8)
        payload2 = f"<svg onload=window.__XSS_HIT=1 data-t={token2}>"
        uid = sess.user_info.get("id")
        before = self.engine.request("GET", self.base + "/api/auth/me", cookies=sess.cookies)
        orig_name = ""
        try:
            orig_name = json.loads(before.body)["user"]["display_name"]
        except (ValueError, KeyError):
            pass
        ex2 = self.engine.request(
            "PUT", self.base + "/api/profile",
            headers={"Content-Type": "application/json"}, cookies=sess.cookies,
            json_body={"display_name": payload2},
        )
        if ex2.status_code == 200 and uid:
            view2 = self.engine.request("GET", self.base + f"/profile/{uid}", cookies=sess.cookies)
            if payload2 in (view2.body or ""):
                self.candidates.append(Candidate(
                    category="xss", title="存储型 XSS · 用户显示名在档案页未转义输出",
                    severity="high", url=self.base + f"/profile/{uid}", method="GET",
                    param="display_name", role=role,
                    evidence={"payload": payload2, "token": token2, "kind": "stored",
                              "submit": "PUT /api/profile", "sink": f"/profile/{uid}",
                              "field": "display_name", "restore": orig_name},
                    request=ex2.request, response=view2.response,
                    dedup_key=f"xss|{self.base}/api/profile|display_name|stored",
                ))
            # 还原显示名,避免污染靶场
            if orig_name:
                self.engine.request("PUT", self.base + "/api/profile",
                                    headers={"Content-Type": "application/json"},
                                    cookies=sess.cookies, json_body={"display_name": orig_name})

    # ------------------------------------------------------------ SSRF
    def _test_ssrf(self, req):
        role = req.role or "admin"
        parsed = urllib.parse.urlsplit(req.url)
        q = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
        target_param = next((k for k in q if k in ("url", "target", "uri", "dest", "image")), "url")
        probes = [(self.base + path, marks) for path, marks in C.SSRF_INTERNAL_PROBES]
        probes += [(url, [marker]) for url, marker in C.SSRF_FILE_PROBES]
        for probe, marks in probes:
            url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path,
                                           urllib.parse.urlencode({**q, target_param: probe}), ""))
            try:
                ex = self.engine.request(req.method, url, headers=self._headers(role),
                                         timeout=self.config.verify_timeout)
            except ScanStopped:
                raise
            body = ex.body or ""
            matched = [m for m in marks if m in body]
            if matched and ex.status_code == 200:
                self.candidates.append(Candidate(
                    category="ssrf", title=f"SSRF · {parsed.path} 参数 {target_param}",
                    severity="high", url=req.url, method=req.method, param=target_param,
                    role=req.role,
                    evidence={"probe": probe, "marker": matched[0], "matched": matched,
                              "probe_status": ex.status_code, "probe_len": len(body)},
                    request=ex.request, response=ex.response,
                    dedup_key=f"ssrf|{req.template()}|{target_param}",
                ))
                return

    # ------------------------------------------------------------ 路径穿越
    def _test_traversal(self, req):
        role = req.role or "admin"
        parsed = urllib.parse.urlsplit(req.url)
        q = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
        target_param = next((k for k in q if k in ("file", "path", "name", "filename", "download")), "path")
        for payload in C.TRAVERSAL_PAYLOADS:
            url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path,
                                           urllib.parse.urlencode({**q, target_param: payload}), ""))
            try:
                ex = self.engine.request(req.method, url, headers=self._headers(role))
            except ScanStopped:
                raise
            if any(m in (ex.body or "") for m in C.TRAVERSAL_ABS_MARKERS):
                dedup = f"traversal|{req.template()}|{target_param}"
                self.candidates.append(Candidate(
                    category="traversal", title=f"路径穿越 · {parsed.path} 参数 {target_param}",
                    severity="high", url=req.url, method=req.method, param=target_param,
                    role=req.role, evidence={"payload": payload, "matched": True, "status": ex.status_code},
                    request=ex.request, response=ex.response, dedup_key=dedup,
                ))
                return

    # ------------------------------------------------------------ 开放重定向
    def _test_redirect(self, req):
        parsed = urllib.parse.urlsplit(req.url)
        q = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
        if "next" not in q:
            return
        probe = "https://evil.example.org/scan-redirect"
        url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path,
                                       urllib.parse.urlencode({**q, "next": probe}), ""))
        try:
            ex = self.engine.request("GET", url, headers=self._headers(req.role or "admin"))
        except ScanStopped:
            raise
        loc = ex.headers.get("location", "")
        if probe in loc:
            self.candidates.append(Candidate(
                category="redirect", title=f"开放重定向 · {parsed.path}",
                severity="medium", url=req.url, method="GET", param="next", role=req.role,
                evidence={"payload": probe, "location": loc},
                request=ex.request, response=ex.response, dedup_key=f"redirect|{req.template()}",
            ))

    # ------------------------------------------------------------ 信息泄露
    def _test_info_leak(self, req):
        try:
            ex = self.engine.request("GET", req.url, headers={})
        except ScanStopped:
            raise
        if ex.status_code != 200:
            return
        body_low = (ex.body or "").lower()
        matched = [k for k in C.SENSITIVE_KEYWORDS if k in body_low]
        if len(matched) >= 2:
            self.candidates.append(Candidate(
                category="info", title=f"敏感配置未授权访问 · {urllib.parse.urlsplit(req.url).path}",
                severity="high", url=req.url, method="GET", param="", role="anonymous",
                evidence={"matched_keywords": matched, "status": ex.status_code},
                request=ex.request, response=ex.response,
                dedup_key=f"info|{req.template()}",
            ))

    # ------------------------------------------------------------ 越权
    def run_authz(self, requests):
        """水平越权:低权限角色访问他人的同类资源;垂直越权:低权限访问高权限接口。"""
        roles = self._sorted_roles()
        if not roles:
            return self.candidates
        attackers = [r for r in ("driver", "other_driver") if r in roles and self.sessions.get(r).cookies]
        if not attackers:
            return self.candidates
        attacker = attackers[0]
        victims = [r for r in attackers if r != attacker]
        if not victims:
            victims = attackers
        victim = victims[0]

        # ---------- 水平:以车主 A 访问车主 B 的资源
        self._test_horizontal_orders(attacker, victim)
        self._test_horizontal_by_template(attacker, victim)

        # ---------- 垂直:低权限访问高权限接口
        for needed_role, path in C.PRIVILEGED_PATHS:
            self._test_vertical(path, needed_role, roles)
        # ---------- 批量赋值提权
        self._test_mass_assignment(attacker, roles)
        return self.candidates

    def _victim_resources(self, victim, path: str) -> list[int]:
        ex = self.engine.request("GET", self.base + path, headers=self._headers(victim))
        if ex.status_code != 200:
            return []
        try:
            data = json.loads(ex.body)
        except ValueError:
            return []
        items = data.get("items") if isinstance(data, dict) else None
        if not isinstance(items, list):
            return []
        return [int(i["id"]) for i in items if isinstance(i, dict) and i.get("id") is not None]

    def _test_horizontal_orders(self, attacker, victim):
        victim_ids = self._victim_resources(victim, "/api/orders")
        if not victim_ids:
            return
        victim_name = self.sessions.get(victim).user_info.get("username", "")
        for oid in victim_ids[:3]:
            url = f"{self.base}/api/orders/{oid}"
            ex = self.engine.request("GET", url, headers=self._headers(attacker))
            if ex.status_code != 200 or '"order"' not in (ex.body or ""):
                continue
            # 确认资源确实属于受害者(响应中的用户与攻击者不同)
            try:
                order_user = json.loads(ex.body)["order"].get("username", "")
            except (ValueError, KeyError):
                order_user = ""
            if order_user and order_user != self.sessions.get(attacker).user_info.get("username"):
                self.candidates.append(Candidate(
                    category="idor",
                    title=f"水平越权 · 车主可读取他人订单详情(订单 #{oid})",
                    severity="high", url=url, method="GET", param="id", role=attacker,
                    evidence={"actor": attacker, "victim": victim, "victim_id": oid,
                              "victim_username": order_user, "status": ex.status_code,
                              "note": "订单详情接口未校验归属"},
                    request=ex.request, response=ex.response,
                    dedup_key=f"idor|{self.base}/api/orders/{{id}}|owner-check",
                ))
                return

    def _test_horizontal_by_template(self, attacker, victim):
        """发票/工单/用户档案:用受害者自身的 ID 交叉访问。"""
        plans = [
            ("/api/invoices", "/api/invoices/{id}", "invoice", ("user_name", "username")),
            ("/api/feedback", "/api/feedback/{id}", "feedback", ("user_name",)),
        ]
        for list_path, detail_path, wrapper, keys in plans:
            vids = self._victim_resources(victim, list_path)
            if not vids:
                continue
            for rid in vids[:2]:
                url = self.base + detail_path.format(id=rid)
                ex = self.engine.request("GET", url, headers=self._headers(attacker))
                if ex.status_code != 200:
                    continue
                try:
                    obj = json.loads(ex.body).get(wrapper, {})
                except (ValueError, AttributeError):
                    obj = {}
                owner = next((obj.get(k) for k in keys if obj.get(k)), "")
                attacker_name = self.sessions.get(attacker).user_info.get("username", "")
                if owner and owner != attacker_name:
                    self.candidates.append(Candidate(
                        category="idor",
                        title=f"水平越权 · 车主可读取他人{WSCN.get(wrapper, wrapper)} #{rid}",
                        severity="high", url=url, method="GET", param="id", role=attacker,
                        evidence={"actor": attacker, "victim": victim, "victim_id": rid,
                                  "owner": owner, "status": ex.status_code},
                        request=ex.request, response=ex.response,
                        dedup_key=f"idor|{self.base}{detail_path.replace('{id}', '{id}')}|owner-check",
                    ))
                    break
        # 用户档案:按 ID 枚举其他用户
        ex_me = self.engine.request("GET", self.base + "/api/auth/me", headers=self._headers(victim))
        victim_uid = None
        try:
            victim_uid = json.loads(ex_me.body)["user"]["id"]
        except (ValueError, KeyError):
            pass
        if victim_uid:
            url = f"{self.base}/api/users/{victim_uid}"
            ex = self.engine.request("GET", url, headers=self._headers(attacker))
            if ex.status_code == 200 and '"api_key"' in (ex.body or "") and '"email"' in (ex.body or ""):
                try:
                    uname = json.loads(ex.body).get("user", {}).get("username", "")
                except ValueError:
                    uname = ""
                self.candidates.append(Candidate(
                    category="idor",
                    title="水平越权 · 车主可读取他人用户档案(含 API Key)",
                    severity="high", url=url, method="GET", param="id", role=attacker,
                    evidence={"actor": attacker, "victim": victim, "victim_id": victim_uid,
                              "victim_username": uname, "status": ex.status_code,
                              "sensitive": ["email", "phone", "api_key"]},
                    request=ex.request, response=ex.response,
                    dedup_key=f"idor|{self.base}/api/users/{{id}}|owner-check",
                ))

    def _test_vertical(self, path, needed_role, roles):
        url = self.base + path
        for role in roles:
            sess = self.sessions.get(role)
            if not sess or not sess.cookies:
                continue
            actual = sess.user_info.get("role", "")
            if actual == needed_role or actual == "admin":
                continue
            try:
                ex = self.engine.request("GET", url, headers=self._headers(role))
            except ScanStopped:
                raise
            if ex.status_code == 200:
                existing = next((c for c in self.candidates if c.dedup_key == f"bvac|{url}"), None)
                actual_roles = [actual]
                if existing:
                    existing.evidence.setdefault("actor_roles", [existing.evidence.get("actor_role")])
                    if actual not in existing.evidence["actor_roles"]:
                        existing.evidence["actor_roles"].append(actual)
                    existing.add_occurrence("role", actual)
                    continue
                self.candidates.append(Candidate(
                    category="bvac",
                    title=f"垂直越权 · 低权限角色可访问 {path}",
                    severity="critical" if "admin" in path else "high",
                    url=url, method="GET", param="", role=role,
                    evidence={"actor_role": actual, "actor_roles": actual_roles,
                              "required_role": needed_role,
                              "status": ex.status_code, "body_len": len(ex.body),
                              "sensitive": [k for k in ("api_key", "balance", "settlement_account", "bank", "role")
                                            if k in (ex.body or "").lower()]},
                    request=ex.request, response=ex.response,
                    dedup_key=f"bvac|{url}",
                ))

    def _test_vertical_page(self, path, needed_role, roles):
        url = self.base + path
        for role in roles:
            sess = self.sessions.get(role)
            if not sess or not sess.cookies:
                continue
            actual = sess.user_info.get("role", "")
            if actual == needed_role or actual == "admin":
                continue
            ex = self.engine.request("GET", url, headers=self._headers(role))
            if ex.status_code == 200 and "管理控制台" in (ex.body or ""):
                existing = next((c for c in self.candidates if c.dedup_key == f"bvac|{url}|page"), None)
                if existing:
                    existing.evidence.setdefault("actor_roles", [existing.evidence.get("actor_role")])
                    if actual not in existing.evidence["actor_roles"]:
                        existing.evidence["actor_roles"].append(actual)
                    existing.add_occurrence("role", actual)
                    continue
                self.candidates.append(Candidate(
                    category="bvac", title="垂直越权 · 低权限角色可访问管理控制台页面",
                    severity="medium", url=url, method="GET", param="", role=role,
                    evidence={"actor_role": actual, "actor_roles": [actual],
                              "required_role": needed_role, "status": 200},
                    request=ex.request, response=ex.response,
                    dedup_key=f"bvac|{url}|page",
                ))

    def _test_mass_assignment(self, attacker, roles):
        """通过 PUT /api/profile 把 role 改成 admin,确认后立即改回。"""
        sess = self.sessions.get(attacker)
        if not sess or not sess.cookies:
            return
        before = sess.user_info.get("role", "")
        url = self.base + "/api/profile"
        ex = self.engine.request("PUT", url, headers={"Content-Type": "application/json"},
                                 cookies=sess.cookies, json_body={"role": "admin"})
        try:
            ok = ex.status_code == 200 and json.loads(ex.body).get("user", {}).get("role") == "admin"
        except (ValueError, AttributeError):
            ok = False
        restored = self.engine.request("PUT", url, headers={"Content-Type": "application/json"},
                                       cookies=sess.cookies, json_body={"role": before})
        if ok:
            self.candidates.append(Candidate(
                category="bvac", title="垂直越权 · 个人资料接口批量赋值可将角色改为管理员",
                severity="critical", url=url, method="PUT", param="role", role=attacker,
                evidence={"actor_role": before, "escalated_to": "admin",
                          "status": ex.status_code, "restored": restored.status_code == 200},
                request=ex.request, response=ex.response,
                dedup_key=f"bvac|{url}|mass-assignment",
            ))


def req_body_json(body: str) -> dict:
    try:
        data = json.loads(body)
        return data if isinstance(data, dict) else {}
    except (ValueError, TypeError):
        return {}


def _similar(a: RecordedExchange, b: RecordedExchange) -> bool:
    if a.status_code != b.status_code:
        return False
    al, bl = len(a.body or ""), len(b.body or "")
    if max(al, bl) == 0:
        return True
    return abs(al - bl) / max(al, bl) < 0.15


def _first_error(body: str) -> str:
    for m in C.SQL_ERROR_MARKERS:
        if m.lower() in (body or "").lower():
            return m
    return ""


def _raw_marker(body: str, payload: str) -> bool:
    """输出中未转义的证据(不是 &lt;script&gt;)。"""
    if payload not in body:
        return False
    escaped = payload.replace("<", "&lt;").replace(">", "&gt;")
    return escaped not in body or payload in body


def _extract_json(body: str, keys) -> str:
    try:
        data = json.loads(body)
    except ValueError:
        return ""
    if isinstance(data, dict):
        for key in keys:
            node = data.get("order") or data.get("invoice") or data.get("feedback") or data.get("user") or data
            if isinstance(node, dict) and key in node:
                return str(node[key])
    return ""
