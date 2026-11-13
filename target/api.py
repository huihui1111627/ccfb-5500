"""业务 API —— 故意包含若干已知漏洞,仅供本地靶场验证。"""
import os
import sqlite3
import urllib.parse
import urllib.request

import httpx
from flask import Response, jsonify, redirect, request, session

from target.app import app, get_db
from target.auth import auth_payload, current_user, hash_password, login_required

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FILES_DIR = os.path.join(BASE_DIR, "files")
UPLOADS_DIR = os.path.join(BASE_DIR, "uploads")


def _json_body():
    return request.get_json(silent=True) or {}


# ---------------------------------------------------------------- 认证
@app.post("/api/auth/login")
def api_login():
    data = _json_body() or request.form
    username = str(data.get("username", ""))
    password = str(data.get("password", ""))
    # 漏洞:字符串拼接 SQL,用户名与密码均可注入
    sql = (
        "SELECT * FROM users WHERE username = '"
        + username
        + "' AND password_hash = '"
        + hash_password(password)
        + "'"
    )
    try:
        row = get_db().execute(sql).fetchone()
    except sqlite3.Error as exc:
        return jsonify({"error": f"登录失败:数据库错误 {exc}", "code": "db_error"}), 500
    if not row:
        return jsonify({"error": "用户名或密码错误", "code": "bad_credentials"}), 401
    session.clear()
    session["uid"] = row["id"]
    session.permanent = True
    return jsonify({"user": auth_payload(dict(row)), "token": f"session-{row['id']}"})


@app.post("/api/auth/logout")
def api_logout():
    session.clear()
    return jsonify({"ok": True})


@app.get("/api/auth/me")
def api_me():
    user = current_user()
    if not user:
        return jsonify({"error": "未登录", "code": "unauthorized"}), 401
    return jsonify({"user": auth_payload(user)})


@app.get("/api/auth/sso")
def api_sso():
    # 漏洞:未校验 next,可开放重定向
    nxt = request.args.get("next", "/")
    return redirect(nxt or "/")


# ---------------------------------------------------------------- 订单
@app.get("/api/orders")
@login_required
def api_orders():
    user = current_user()
    status = request.args.get("status", "")
    q = request.args.get("q", "")
    sort = request.args.get("sort", "id")

    db = get_db()
    params = []
    where = []
    if user["role"] not in ("admin", "operator", "finance", "support"):
        where.append("user_id=?")
        params.append(user["id"])
    if status:
        where.append("status=?")
        params.append(status)
    # 漏洞:q 与 sort 直接拼接到 SQL
    key = f"order_no LIKE '%{q}%' OR vehicle_plate LIKE '%{q}%'"
    clause = ("WHERE " + " AND ".join(where) if where else "WHERE 1=1")
    sql = f"SELECT * FROM orders {clause} AND ({key}) ORDER BY {sort} ASC"

    try:
        rows = [dict(r) for r in db.execute(sql, params).fetchall()]
    except sqlite3.Error as exc:
        return jsonify({"error": f"查询失败:{exc}", "sql": sql, "code": "query_error"}), 500
    return jsonify({"items": rows, "total": len(rows), "query": sql})


@app.get("/api/orders/<int:oid>")
@login_required
def api_order_detail(oid):
    # 漏洞:未校验订单归属
    db = get_db()
    row = db.execute(
        "SELECT o.*, s.name AS station_name, s.address AS station_address, "
        "u.username, u.display_name AS user_name, u.phone AS user_phone, u.email AS user_email "
        "FROM orders o JOIN stations s ON s.id=o.station_id JOIN users u ON u.id=o.user_id WHERE o.id=?",
        (oid,),
    ).fetchone()
    if not row:
        return jsonify({"error": "订单不存在", "code": "not_found"}), 404
    return jsonify({"order": dict(row)})


@app.post("/api/orders/<int:oid>/cancel")
@login_required
def api_order_cancel(oid):
    user = current_user()
    db = get_db()
    row = db.execute("SELECT * FROM orders WHERE id=?", (oid,)).fetchone()
    if not row:
        return jsonify({"error": "订单不存在"}), 404
    if user["role"] == "driver" and row["user_id"] != user["id"]:
        return jsonify({"error": "无权限"}), 403
    db.execute("UPDATE orders SET status='cancelled' WHERE id=?", (oid,))
    db.commit()
    return jsonify({"ok": True, "status": "cancelled"})


# ---------------------------------------------------------------- 站点
@app.get("/api/stations")
@login_required
def api_stations():
    rows = [dict(r) for r in get_db().execute("SELECT * FROM stations ORDER BY id").fetchall()]
    return jsonify({"items": rows})


@app.get("/api/stations/<int:sid>")
@login_required
def api_station_detail(sid):
    row = get_db().execute("SELECT * FROM stations WHERE id=?", (sid,)).fetchone()
    if not row:
        return jsonify({"error": "站点不存在"}), 404
    return jsonify({"station": dict(row)})


@app.get("/api/stations/<int:sid>/cover")
@login_required
def api_station_cover(sid):
    # 漏洞:服务端按用户提供的 URL 抓取内容(SSRF)
    url = request.args.get("url") or f"{request.host_url}static/logo.png"
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:  # noqa: S310
            data = resp.read(300000)
            ctype = resp.headers.get_content_type()
        return Response(data, mimetype=ctype)
    except Exception as exc:  # noqa: BLE001
        return jsonify({"error": f"封面拉取失败: {exc}"}), 502


@app.get("/api/stations/search")
@login_required
def api_station_search():
    keyword = request.args.get("keyword", "")
    db = get_db()
    rows = db.execute(
        "SELECT * FROM stations WHERE name LIKE ? OR address LIKE ? ORDER BY id",
        (f"%{keyword}%", f"%{keyword}%"),
    ).fetchall()
    return jsonify({"items": [dict(r) for r in rows], "keyword": keyword})


# ---------------------------------------------------------------- 发票
@app.get("/api/invoices")
@login_required
def api_invoices():
    user = current_user()
    db = get_db()
    if user["role"] in ("admin", "finance"):
        rows = db.execute("SELECT * FROM invoices ORDER BY id").fetchall()
    else:
        rows = db.execute("SELECT * FROM invoices WHERE user_id=? ORDER BY id", (user["id"],)).fetchall()
    return jsonify({"items": [dict(r) for r in rows]})


@app.get("/api/invoices/<int:iid>")
@login_required
def api_invoice_detail(iid):
    # 漏洞:未校验发票归属
    row = get_db().execute(
        "SELECT i.*, u.username, u.display_name AS user_name, u.phone AS user_phone, "
        "u.email AS user_email FROM invoices i JOIN users u ON u.id=i.user_id WHERE i.id=?",
        (iid,),
    ).fetchone()
    if not row:
        return jsonify({"error": "发票不存在"}), 404
    return jsonify({"invoice": dict(row)})


@app.get("/api/invoices/<int:iid>/attachment")
@login_required
def api_invoice_attachment(iid):
    # 漏洞:文件参数未做路径规范化,可目录穿越
    name = request.args.get("file", "default.pdf")
    path = os.path.join(UPLOADS_DIR, name)
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError:
        return jsonify({"error": "附件不存在", "path": path}), 404
    return Response(data, mimetype="application/octet-stream",
                    headers={"Content-Disposition": f'attachment; filename="{os.path.basename(name)}"'})


# ---------------------------------------------------------------- 反馈
@app.get("/api/feedback")
@login_required
def api_feedback_list():
    user = current_user()
    db = get_db()
    if user["role"] in ("admin", "support", "operator"):
        rows = db.execute("SELECT * FROM feedback ORDER BY id").fetchall()
    else:
        rows = db.execute("SELECT * FROM feedback WHERE user_id=? ORDER BY id", (user["id"],)).fetchall()
    return jsonify({"items": [dict(r) for r in rows]})


@app.get("/api/feedback/<int:fid>")
@login_required
def api_feedback_detail(fid):
    # 漏洞:未校验反馈归属
    row = get_db().execute(
        "SELECT f.*, u.display_name AS user_name FROM feedback f JOIN users u ON u.id=f.user_id WHERE f.id=?",
        (fid,),
    ).fetchone()
    if not row:
        return jsonify({"error": "反馈不存在"}), 404
    return jsonify({"feedback": dict(row)})


@app.post("/api/feedback")
@login_required
def api_feedback_create():
    user = current_user()
    data = _json_body()
    content = str(data.get("content", ""))
    category = str(data.get("category", "other"))
    order_id = data.get("order_id")
    contact = str(data.get("contact", user["phone"]))
    if not content:
        return jsonify({"error": "内容不能为空"}), 400
    db = get_db()
    cur = db.execute(
        "INSERT INTO feedback (user_id,order_id,category,content,contact,status,created_at)"
        " VALUES (?,?,?,?,?,'open',datetime('now','localtime'))",
        (user["id"], order_id, category, content, contact),
    )
    db.commit()
    row = db.execute("SELECT * FROM feedback WHERE id=?", (cur.lastrowid,)).fetchone()
    return jsonify({"feedback": dict(row)}), 201


# ---------------------------------------------------------------- 用户与权限
@app.get("/api/users/<int:uid>")
@login_required
def api_user_detail(uid):
    # 漏洞:任意登录用户可读取他人资料(含 API Key)
    row = get_db().execute(
        "SELECT id,username,role,display_name,email,phone,balance,api_key FROM users WHERE id=?", (uid,)
    ).fetchone()
    if not row:
        return jsonify({"error": "用户不存在"}), 404
    return jsonify({"user": dict(row)})


@app.put("/api/profile")
@login_required
def api_profile_update():
    user = current_user()
    data = _json_body()
    # 漏洞:批量赋值,允许修改 role / balance
    fields = {}
    for key in ("display_name", "email", "phone", "role", "balance"):
        if key in data:
            fields[key] = data[key]
    if not fields:
        return jsonify({"error": "没有可更新字段"}), 400
    sets = ", ".join(f"{k}=?" for k in fields)
    db = get_db()
    db.execute(f"UPDATE users SET {sets} WHERE id=?", (*fields.values(), user["id"]))
    db.commit()
    row = db.execute(
        "SELECT id,username,role,display_name,email,phone,balance,api_key FROM users WHERE id=?", (user["id"],)
    ).fetchone()
    return jsonify({"ok": True, "user": dict(row)})


@app.get("/api/admin/users")
@login_required
def api_admin_users():
    # 漏洞:缺少角色校验,普通车主也可访问
    rows = get_db().execute(
        "SELECT id,username,role,display_name,email,phone,balance,api_key FROM users ORDER BY id"
    ).fetchall()
    return jsonify({"items": [dict(r) for r in rows]})


@app.get("/api/admin/api-keys")
@login_required
def api_admin_api_keys():
    # 漏洞:缺少角色校验
    rows = get_db().execute(
        "SELECT k.id,k.key,k.scope,k.active,u.username,u.display_name FROM api_keys k "
        "JOIN users u ON u.id=k.user_id ORDER BY k.id"
    ).fetchall()
    return jsonify({"items": [dict(r) for r in rows]})


@app.get("/api/finance/settlements")
@login_required
def api_finance_settlements():
    # 漏洞:缺少角色校验,结算账户信息泄露给任意登录用户
    rows = get_db().execute(
        "SELECT s.id,s.name,u.display_name AS owner,u.phone AS contact,"
        "s.capacity, ROUND(SUM(o.amount),2) AS settled_amount "
        "FROM stations s JOIN users u ON u.id=s.operator_id "
        "LEFT JOIN orders o ON o.station_id=s.id AND o.status IN ('paid','completed') "
        "GROUP BY s.id ORDER BY s.id"
    ).fetchall()
    items = []
    for r in rows:
        item = dict(r)
        item["settlement_account"] = f"6222 **** **** {8800 + item['id']}"
        item["bank"] = "招商银行北京分行"
        items.append(item)
    return jsonify({"items": items, "period": "2024-10", "total": round(sum(i["settled_amount"] or 0 for i in items), 2)})


# ---------------------------------------------------------------- 文件与集成
@app.get("/api/files/download")
@login_required
def api_file_download():
    # 漏洞:path / name 未做路径规范化,可目录穿越
    name = request.args.get("path") or request.args.get("name") or "avatars/default.txt"
    full = os.path.join(FILES_DIR, name)
    try:
        with open(full, "rb") as fh:
            data = fh.read()
    except OSError:
        return jsonify({"error": "文件不存在", "path": full}), 404
    return Response(data, mimetype="text/plain; charset=utf-8")


@app.get("/api/integrations/fetch")
@login_required
def api_integrations_fetch():
    # 漏洞:服务端请求用户指定 URL(SSRF)
    url = request.args.get("url", "")
    if not url:
        return jsonify({"error": "url 不能为空"}), 400
    try:
        resp = httpx.get(url, timeout=6.0, follow_redirects=True)
        return jsonify({
            "status": resp.status_code,
            "content_type": resp.headers.get("content-type"),
            "body": resp.text[:4000],
        })
    except Exception as exc:  # noqa: BLE001
        return jsonify({"error": f"请求失败: {exc}"}), 502


@app.get("/api/debug/config")
def api_debug_config():
    # 漏洞:未授权暴露敏感配置
    return jsonify({
        "app": "charger-ops",
        "debug": True,
        "secret_key": app.config["SECRET_KEY"],
        "database": app.config["DB_PATH"],
        "smtp": {"host": "smtp.charge.local", "user": "noreply@charge.local", "password": "Mail@2024!"},
        "payment": {"merchant_id": "M20240915", "api_key": "pay_live_9f2c7b1a4e"},
        "integration_token": "ghp_lab_7d1b5e2b9f3a2c8e6a4c",
    })


# ---------------------------------------------------------------- XSS 回连标记
@app.get("/api/xss-hit")
def api_xss_hit():
    token = request.args.get("token", "")
    if token:
        db = get_db()
        db.execute("INSERT INTO xss_hits (token,created_at) VALUES (?,datetime('now','localtime'))", (token,))
        db.commit()
    gif = b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;"
    return Response(gif, mimetype="image/gif")


@app.get("/api/xss-hit/status")
def api_xss_hit_status():
    token = request.args.get("token", "")
    row = get_db().execute("SELECT COUNT(*) AS c FROM xss_hits WHERE token=?", (token,)).fetchone()
    return jsonify({"token": token, "hits": row["c"]})
