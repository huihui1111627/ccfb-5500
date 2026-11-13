"""页面渲染:登录页、SPA 主界面、若干服务端渲染页面。"""
import os

from flask import redirect, render_template, request, session

from target.app import app
from target.auth import current_user, role_required

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


@app.route("/")
def index():
    if current_user():
        return redirect("/app")
    return render_template("login.html")


@app.route("/app")
def spa():
    if not current_user():
        return redirect("/")
    return render_template("app.html", user=current_user())


@app.route("/help/search")
def help_search():
    # 漏洞:反射型 XSS,keyword 未转义直接输出
    keyword = request.args.get("keyword", "")
    results = []
    if keyword:
        rows = __import__("target.app", fromlist=["get_db"]).get_db().execute(
            "SELECT * FROM stations WHERE name LIKE ?", (f"%{keyword}%",)
        ).fetchall()
        results = [dict(r) for r in rows]
    return render_template("help_search.html", keyword=keyword, results=results)


@app.route("/notice")
def notice():
    db = __import__("target.app", fromlist=["get_db"]).get_db()
    rows = [dict(r) for r in db.execute(
        "SELECT * FROM feedback WHERE status='open' ORDER BY id DESC LIMIT 10"
    ).fetchall()]
    return render_template("notice.html", items=rows)


@app.route("/profile/<int:uid>")
def profile_page(uid):
    # 漏洞:存储型 XSS,display_name 直接以 safe 输出
    db = __import__("target.app", fromlist=["get_db"]).get_db()
    row = db.execute(
        "SELECT id,username,role,display_name,email,phone,balance FROM users WHERE id=?", (uid,)
    ).fetchone()
    if not row:
        return "用户不存在", 404
    return render_template("profile.html", user=dict(row))


@app.route("/admin/console")
@role_required("admin")
def admin_console():
    return render_template("admin.html", user=current_user())


@app.route("/tools/faq")
@role_required("operator", "support", "admin")
def tools_faq():
    return render_template("help_search.html", keyword="", results=[])
