"""多角色会话管理。"""
import json

from scanner.http import HttpEngine


class RoleSession:
    def __init__(self, role: str, username: str, password: str):
        self.role = role
        self.username = username
        self.password = password
        self.cookies: dict = {}
        self.user_info: dict = {}
        self.login_error = ""

    def cookie_header(self) -> str:
        return "; ".join(f"{k}={v}" for k, v in self.cookies.items())

    def auth_headers(self) -> dict:
        return {"Cookie": self.cookie_header()} if self.cookies else {}


class SessionManager:
    """按角色登录靶场,并在扫描中检测会话是否失效。"""

    def __init__(self, engine: HttpEngine, config, roles: dict | None = None):
        self.engine = engine
        self.config = config
        self.roles_def = roles or config.roles
        self.sessions: dict[str, RoleSession] = {}
        self._excluded: set[str] = set()

    def login_all(self):
        base = self.config.target_url.rstrip("/")
        for role, cred in self.roles_def.items():
            if not cred.get("username"):
                continue
            sess = RoleSession(role, cred["username"], cred["password"])
            resp = self.engine.request(
                "POST", base + "/api/auth/login",
                json_body={"username": sess.username, "password": sess.password},
            )
            if resp.status_code == 200:
                sess.cookies = self._extract_cookies(resp)
                try:
                    body = json.loads(resp.body)
                    sess.user_info = body.get("user", {})
                except ValueError:
                    sess.user_info = {"role": role}
            else:
                sess.login_error = resp.body[:200]
            self.sessions[role] = sess
        return self.sessions

    @staticmethod
    def _extract_cookies(ex) -> dict:
        raw = ex.headers.get("set-cookie", "")
        cookies = {}
        for part in raw.split(","):
            piece = part.split(";")[0].strip()
            if "=" in piece:
                k, v = piece.split("=", 1)
                cookies[k.strip()] = v.strip()
        return cookies

    def get(self, role: str) -> RoleSession | None:
        return self.sessions.get(role)

    def working_roles(self) -> list[str]:
        return [r for r, s in self.sessions.items() if s.cookies]

    def verify_session(self, role: str) -> bool:
        sess = self.sessions.get(role)
        if not sess:
            return False
        resp = self.engine.request(
            "GET", self.config.target_url.rstrip("/") + "/api/auth/me",
            headers=sess.auth_headers(),
        )
        return resp.status_code == 200 and '"user"' in resp.body

    def cookie_expired(self, ex) -> bool:
        return ex.status_code in (401, 302) and "unauthorized" in (ex.body or "").lower()
