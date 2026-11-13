"""充电桩运营后台靶场 —— 仅用于本地安全测试与扫描器验证。

本应用故意包含已知漏洞,禁止部署到任何公网环境。
"""
import os
import sqlite3

from flask import Flask, g

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "data", "charger.db")

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config.update(
    SECRET_KEY="charger-ops-secret-2024",
    SESSION_COOKIE_NAME="ops_session",
    JSON_AS_ASCII=False,
)
app.config["DB_PATH"] = DB_PATH


@app.after_request
def security_headers(resp):
    # 注意:缺少 CSP / X-Frame-Options 等安全响应头(靶场特性)
    resp.headers["Server"] = "ChargeOps/1.0"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DB_PATH"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


# 路由模块在 db 初始化之后导入
from target import auth, views, api  # noqa: E402,F401
from target.seed import init_db  # noqa: E402

if not os.path.exists(app.config["DB_PATH"]):
    init_db(app.config["DB_PATH"])
