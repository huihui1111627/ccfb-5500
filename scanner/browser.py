"""Playwright SPA 抓取:真实浏览器登录、点击导航、捕获 XHR/fetch 请求。"""
import re
import time

from playwright.sync_api import sync_playwright

INTERESTING = re.compile(r"(/api/|/admin/|/finance/|/profile/|/help/|/notice/|/uploads/|/files/)")


class SpaCrawler:
    def __init__(self, base_url: str, timeout: int = 10, headless: bool = True):
        self.base = base_url.rstrip("/")
        self.timeout = timeout
        self.headless = headless
        self.captured: list[dict] = []

    def _record(self, request):
        try:
            url = request.url
            if not url.startswith(self.base):
                return
            if not INTERESTING.search(url) and not url.startswith(self.base + "/api/"):
                return
            method = request.method
            if method in ("OPTIONS", "HEAD"):
                return
            post_data = request.post_data or ""
            if len(self.captured) < 120:
                self.captured.append({
                    "url": url, "method": method, "post_data": post_data,
                    "headers": request.headers,
                })
        except Exception:  # noqa: BLE001
            pass

    def capture(self, cookies: dict, max_actions: int = 16) -> list[dict]:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=self.headless)
            context = browser.new_context(ignore_https_errors=True, user_agent="ChargeOps-Scanner/1.0")
            if cookies:
                context.add_cookies([
                    {"name": k, "value": v, "domain": _domain(self.base), "path": "/"}
                    for k, v in cookies.items()
                ])
            page = context.new_page()
            page.on("request", self._record)
            page.goto(self.base + "/app", wait_until="domcontentloaded", timeout=self.timeout * 1000)
            page.wait_for_timeout(1200)

            # 逐个点击左侧导航,触发各视图的接口调用
            views = ["orders", "stations", "invoices", "feedback", "users", "settlement", "tools", "profile", "dashboard"]
            for view in views[:max_actions]:
                try:
                    page.evaluate(f"location.hash = '{view}'")
                    page.wait_for_timeout(700)
                    # 列表页里的详情/操作入口也点一下
                    if view in ("orders", "invoices", "feedback"):
                        for selector in page.query_selector_all("[data-order], [data-invoice], [data-fb]"):
                            try:
                                selector.click(timeout=1500)
                                page.wait_for_timeout(400)
                                page.keyboard.press("Escape")
                            except Exception:  # noqa: BLE001
                                pass
                            break
                except Exception:  # noqa: BLE001
                    continue

            # DOM XSS 探针:插入 hash 后观察是否执行
            try:
                page.evaluate("location.hash = 'welcome=' + encodeURIComponent('<img src=x onerror=window.__xss=1>')")
                page.wait_for_timeout(400)
                xss_hit = bool(page.evaluate("window.__xss === 1"))
            except Exception:  # noqa: BLE001
                xss_hit = False

            context.close()
            browser.close()
            self.dom_xss = xss_hit
            return self.captured


def _domain(base: str) -> str:
    from urllib.parse import urlsplit
    return urlsplit(base).hostname or "localhost"
