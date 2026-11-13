"""爬虫:带登录态遍历页面、解析表单/API、从 JS 中提取接口;SPA 用 Playwright 抓 XHR。"""
import json
import re
import urllib.parse
from dataclasses import dataclass, field

from bs4 import BeautifulSoup

from scanner.http import HttpEngine, ScanStopped

API_STR_RE = re.compile(r"""['"`](/api/[^'"`\s]*)['"`]""")
FETCH_RE = re.compile(r"""fetch\(\s*[`'"]([^`'"]+)[`'"]""")
SCRIPT_SRC_RE = re.compile(r"""<script[^>]+src=['"]([^'"]+)['"]""", re.I)
PLACEHOLDER_RE = re.compile(r"\$\{[^}]*\}")
QUERY_PAIR_RE = re.compile(r"[?&]([A-Za-z_][\w\-]*)(?:=([^&'\"`]*))?")
METHOD_NEAR_RE = re.compile(r"method\s*:\s*['\"](\w+)['\"]")
BODY_OBJ_RE = re.compile(r"JSON\.stringify\(\s*\{([^}]*)\}", re.S)
OBJ_KEY_RE = re.compile(r"([A-Za-z_][\w\-]*)\s*:")
CALL_RANGE = 500


@dataclass
class DiscoveredRequest:
    method: str
    url: str
    kind: str = "page"  # page / api / form / spa-api
    role: str = ""
    params: list = field(default_factory=list)   # [{in: query|body|path, name, value}]
    headers: dict = field(default_factory=dict)
    body: str = ""
    source: str = "crawl"

    def template(self) -> str:
        parsed = urllib.parse.urlsplit(self.url)
        return f"{self.method} {parsed.scheme}://{parsed.netloc}{parsed.path}"


def _resolve(base: str, href: str) -> str:
    return urllib.parse.urljoin(base, href)


class Crawler:
    def __init__(self, engine: HttpEngine, config, session_manager):
        self.engine = engine
        self.config = config
        self.sessions = session_manager
        self.base = config.target_url.rstrip("/")
        self.origin = "{0.scheme}://{0.netloc}".format(urllib.parse.urlsplit(self.base))
        self.visited: set[str] = set()
        self.results: list[DiscoveredRequest] = []
        self.max_requests = min(config.max_scan_requests, 3000)
        self.request_count = 0
        self.js_modules: set[str] = set()
        self.spa_count = 0
        self.on_progress = None

    # ------------------------------------------------------------ 入口
    def run(self, primary_role: str = "admin") -> list[DiscoveredRequest]:
        sess = self.sessions.get(primary_role) or next(iter(self.sessions.sessions.values()))
        # 种子页面:首页 + SPA + 服务端渲染页
        seeds = ["/", "/app", "/help/search", "/notice", "/profile/5"]
        queue = [(self.base + p, 0) for p in seeds]
        # 登录接口本身就是重点测试对象(注入),直接登记
        self.results.append(DiscoveredRequest(
            method="POST", url=self.base + "/api/auth/login", kind="api", role="anonymous",
            params=[{"in": "body", "name": "username", "value": ""},
                    {"in": "body", "name": "password", "value": ""}],
            source="auth-endpoint",
        ))
        for role, s in self.sessions.sessions.items():
            if s.cookies and role in ("operator", "finance", "support"):
                queue.append((self.base + "/admin/console", 0))

        while queue and self.request_count < self.max_requests:
            url, depth = queue.pop(0)
            if url in self.visited or depth > self.config.max_depth:
                continue
            if self._excluded(url):
                continue
            self.visited.add(url)
            self._fetch_and_parse(url, depth, sess, queue)

        # SPA 动态接口抓取
        if self.config.crawl_spa:
            self._spa_crawl(primary_role)
        self._emit(100)
        return self._dedupe(self.results)

    def _excluded(self, url: str) -> bool:
        for pattern in self.config.exclude_patterns:
            if pattern in url:
                return True
        return False

    def _emit(self, pct, msg=""):
        if self.on_progress:
            self.on_progress(pct, msg)

    def _fetch_and_parse(self, url: str, depth: int, sess, queue):
        self.request_count += 1
        ex = self.engine.request("GET", url, headers=sess.auth_headers())
        self._emit(min(95, 10 + self.request_count), "爬取 " + url)
        ctype = ex.headers.get("content-type", "")
        parsed = urllib.parse.urlsplit(url)
        params = [{"in": "query", "name": k, "value": v[0] if v else ""} for k, v in urllib.parse.parse_qs(parsed.query).items()]
        kind = "api" if parsed.path.startswith("/api/") else ("page" if "text/html" in ctype else "asset")
        if kind != "asset":
            self.results.append(DiscoveredRequest(
                method="GET", url=url, kind=kind, role=sess.role, params=params,
                headers={"Accept": ctype or "*/*"}, source="crawl",
            ))
        if kind == "page" and "text/html" in ctype:
            self._parse_html(ex.body, url, depth, queue, sess)
        if "javascript" in ctype or url.endswith(".js"):
            self._parse_js(ex.body, url, depth, queue, sess)

    def _parse_html(self, html: str, base_url: str, depth: int, queue, sess):
        soup = BeautifulSoup(html or "", "html.parser")
        for a in soup.find_all("a", href=True):
            link = _resolve(base_url, a["href"])
            if link.startswith(self.origin) and link not in self.visited:
                queue.append((link.split("#")[0], depth + 1))
        for form in soup.find_all("form"):
            action = _resolve(base_url, form.get("action") or base_url)
            method = (form.get("method") or "get").upper()
            fields = []
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if name:
                    fields.append({"in": "body" if method == "POST" else "query", "name": name,
                                   "value": inp.get("value") or ""})
            if fields:
                self.results.append(DiscoveredRequest(
                    method=method, url=action, kind="form", role=sess.role, params=fields,
                    source="crawl",
                ))
                queue.append((action, depth + 1))
        # 外链 JS:抓取后解析接口(SPA 的核心逻辑都在这里)
        for m in SCRIPT_SRC_RE.finditer(html or ""):
            src = _resolve(base_url, m.group(1))
            if src.startswith(self.origin) and src not in self.visited:
                queue.append((src, depth + 1))
        # 从内联脚本提取接口
        for script in soup.find_all("script"):
            if script.string:
                self._extract_api_strings(script.string, base_url, sess)

    def _extract_api_strings(self, code: str, base_url: str, sess):
        found = []
        patterns = [API_STR_RE, FETCH_RE, re.compile(r"""['"`](/api/[^'"`\s]*)['"`]""")]
        for pat in patterns:
            for m in pat.finditer(code):
                path = m.group(1) if pat.groups else m
                if not path.startswith("/"):
                    continue
                snippet = code[m.end(): m.end() + CALL_RANGE]
                method = "GET"
                mm = METHOD_NEAR_RE.search(snippet)
                if mm:
                    method = mm.group(1).upper()
                body_params = []
                bm = BODY_OBJ_RE.search(snippet)
                if bm:
                    body_params = [{"in": "body", "name": k, "value": ""}
                                   for k in OBJ_KEY_RE.findall(bm.group(1))]
                if method == "GET" and body_params:
                    body_params = []
                found.append((method, path, body_params))
        seen = set()
        for method, path, body_params in found:
            cleaned = PLACEHOLDER_RE.sub("1", path)
            if (method, cleaned) in seen:
                continue
            seen.add((method, cleaned))
            params = [{"in": "query", "name": name, "value": value}
                      for name, value in QUERY_PAIR_RE.findall(cleaned)]
            params += [p for p in body_params if p["name"] not in {x["name"] for x in params}]
            full = _resolve(self.base, cleaned)
            if any(r.url == full and r.method == method for r in self.results):
                continue
            self.results.append(DiscoveredRequest(
                method=method, url=full, kind="api", role=sess.role, source="js-static",
                params=params,
            ))

    def _parse_js(self, code: str, base_url: str, depth: int, queue, sess):
        self.js_modules.add(urllib.parse.urlsplit(base_url).path)
        self._extract_api_strings(code, base_url, sess)

    def _spa_crawl(self, role: str):
        """用 Playwright 以真实浏览器访问 SPA,捕获 XHR/fetch 请求。"""
        try:
            from scanner.browser import SpaCrawler
        except ImportError:
            return
        try:
            sed = self.sessions.get(role)
            spa = SpaCrawler(self.base, timeout=int(self.config.timeout))
            captured = spa.capture(sed.cookies if sed else {}, max_actions=24)
        except Exception as exc:  # noqa: BLE001
            self._emit(96, f"SPA 抓取跳过: {exc}")
            return
        for item in captured:
            url = _resolve(self.base, item["url"])
            if not url.startswith(self.origin):
                continue
            if any(r.url == url and r.method == item["method"] for r in self.results):
                continue
            body = item.get("post_data") or ""
            params = []
            parsed = urllib.parse.urlsplit(url)
            for k, v in urllib.parse.parse_qs(parsed.query, keep_blank_values=True).items():
                params.append({"in": "query", "name": k, "value": v[0] if v else ""})
            if body:
                try:
                    jb = json.loads(body)
                    if isinstance(jb, dict):
                        for k, v in jb.items():
                            params.append({"in": "body", "name": k, "value": str(v)})
                except ValueError:
                    for pair in body.split("&"):
                        if "=" in pair:
                            k, v = pair.split("=", 1)
                            params.append({"in": "body", "name": k, "value": v})
            self.results.append(DiscoveredRequest(
                method=item["method"], url=url, kind="spa-api", role=role, params=params,
                headers=item.get("headers", {}), body=body, source="spa",
            ))
            self.spa_count += 1
        self._emit(96, f"SPA 捕获 {len(captured)} 条请求")

    @staticmethod
    def _dedupe(items: list[DiscoveredRequest]) -> list[DiscoveredRequest]:
        out, index = [], {}
        for it in items:
            key = (it.method, it.template(), tuple(sorted(p["name"] for p in it.params)))
            if key in index:
                kept = index[key]
                if len(it.params) > len(kept.params) or (it.source == "spa" and kept.source != "spa"):
                    kept.params = it.params or kept.params
                    kept.body = it.body or kept.body
                    kept.headers = it.headers or kept.headers
                    kept.source = it.source
                    kept.kind = it.kind or kept.kind
                continue
            index[key] = it
            out.append(it)
        # 同一路径、参数集为空的 GET 资产被带参版本覆盖时,去掉重复(保留参数更全的一条)
        final, by_template = [], {}
        for it in out:
            tpl = (it.method, it.template())
            if tpl in by_template:
                prev = by_template[tpl]
                if len(it.params) > len(prev.params):
                    final[final.index(prev)] = it
                    by_template[tpl] = it
                continue
            by_template[tpl] = it
            final.append(it)
        return final
