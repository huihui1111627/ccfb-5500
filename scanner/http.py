"""HTTP 客户端:全局限速、暂停/停止控制、请求响应留档。"""
import threading
import time
from dataclasses import dataclass, field

import httpx


@dataclass
class RecordedExchange:
    request: str
    response: str
    status_code: int
    headers: dict
    body: str
    elapsed_ms: float
    error: str = ""

    def as_dict(self):
        return {
            "request": self.request, "response": self.response, "status": self.status_code,
            "headers": self.headers, "body": self.body, "elapsed_ms": round(self.elapsed_ms, 1),
            "error": self.error,
        }


def format_request(method, url, headers, body) -> str:
    lines = [f"{method} {url}"]
    for k, v in (headers or {}).items():
        if k.lower() in ("authorization", "cookie"):
            lines.append(f"{k}: {v}")
        elif k.startswith("_"):
            continue
        else:
            lines.append(f"{k}: {v}")
    lines.append("")
    if body:
        lines.append(body[:2000])
    return "\n".join(lines)


def format_response(resp: httpx.Response) -> str:
    lines = [f"HTTP {resp.status_code} {resp.reason_phrase}"]
    for k, v in resp.headers.items():
        if k.lower() == "set-cookie":
            v = v.split(";")[0]
        lines.append(f"{k}: {v}")
    lines.append("")
    text = resp.text
    lines.append(text[:4000])
    if len(text) > 4000:
        lines.append(f"... (截断,共 {len(text)} 字符)")
    return "\n".join(lines)


class RateLimiter:
    def __init__(self, rate_per_sec: float):
        self.rate = max(rate_per_sec, 0.2)
        self.min_interval = 1.0 / self.rate
        self._lock = threading.Lock()
        self._next_at = 0.0

    def acquire(self):
        with self._lock:
            now = time.monotonic()
            wait = self._next_at - now
            if wait > 0:
                time.sleep(wait)
                now = time.monotonic()
            self._next_at = now + self.min_interval


class PauseController:
    """跨线程的暂停/停止信号。"""

    def __init__(self):
        self._resume = threading.Event()
        self._resume.set()
        self._stop = threading.Event()

    def pause(self):
        self._resume.clear()

    def resume(self):
        self._resume.set()

    def stop(self):
        self._stop.set()
        self._resume.set()

    @property
    def stopped(self):
        return self._stop.is_set()

    @property
    def paused(self):
        return not self._resume.is_set()

    def checkpoint(self):
        """在每次请求前调用;暂停时阻塞,停止时返回 False。"""
        while not self._resume.wait(0.5):
            if self._stop.is_set():
                return False
        return not self._stop.is_set()


class HttpEngine:
    """线程安全的请求器,记录全部请求/响应并计数。"""

    def __init__(self, config, pause: PauseController, on_request=None):
        self.config = config
        self.pause = pause
        self.limiter = RateLimiter(config.rate_limit)
        self._local = threading.local()
        self._count_lock = threading.Lock()
        self.request_count = 0
        self.on_request = on_request  # callback(method,url,status)
        self._closed = False

    def _client(self) -> httpx.Client:
        client = getattr(self._local, "client", None)
        if client is None or client.is_closed:
            client = httpx.Client(
                timeout=self.config.timeout,
                follow_redirects=False,
                verify=False,
                headers={"User-Agent": self.config.user_agent, "Accept": "*/*"},
            )
            self._local.client = client
        return client

    def close(self):
        client = getattr(self._local, "client", None)
        if client is not None:
            client.close()
        self._closed = True

    def request(self, method, url, *, cookies=None, headers=None, json_body=None,
                data=None, content=None, follow_redirects=False, timeout=None,
                record=True) -> RecordedExchange:
        if not self.pause.checkpoint():
            raise ScanStopped()
        self.limiter.acquire()
        if self.pause.stopped:
            raise ScanStopped()

        hdrs = {"User-Agent": self.config.user_agent, "Accept": "*/*"}
        if headers:
            hdrs.update(headers)
        body_text = ""
        if json_body is not None:
            import json as _json
            body_text = _json.dumps(json_body, ensure_ascii=False)
        elif data is not None:
            body_text = str(data)
        elif content is not None:
            body_text = content.decode("utf-8", "replace") if isinstance(content, bytes) else str(content)

        start = time.monotonic()
        try:
            client = self._client()
            # 清空客户端 cookie jar,避免不同角色会话互相污染(必须显式传 cookies)
            client.cookies.clear()
            resp = client.request(
                method, url, cookies=cookies, headers=hdrs, json=json_body, data=data,
                content=content, follow_redirects=follow_redirects,
                timeout=timeout or self.config.timeout,
            )
            elapsed = (time.monotonic() - start) * 1000
            ex = RecordedExchange(
                request=format_request(method, url, hdrs, body_text),
                response=format_response(resp),
                status_code=resp.status_code,
                headers=dict(resp.headers),
                body=resp.text,
                elapsed_ms=elapsed,
            )
            if record:
                self._bump()
            if self.on_request:
                self.on_request(method, url, resp.status_code)
            return ex
        except httpx.HTTPError as exc:
            elapsed = (time.monotonic() - start) * 1000
            self._bump()
            if self.on_request:
                self.on_request(method, url, 0)
            return RecordedExchange(
                request=format_request(method, url, hdrs, body_text),
                response=f"请求异常: {type(exc).__name__}: {exc}",
                status_code=0, headers={}, body="", elapsed_ms=elapsed, error=str(exc),
            )

    def _bump(self):
        with self._count_lock:
            self.request_count += 1


class ScanStopped(Exception):
    pass
