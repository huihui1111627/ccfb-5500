"""登录、会话与角色工具。"""
import hashlib
import sqlite3
from functools import wraps

from flask import g, jsonify, redirect, request, session, url_for

from target.app import get_db

ROLE_LABELS = {
    "admin": "管理员",
    "operator": "运营",
    "finance": "财务",
    "support": "客服",
    "driver": "车主",
    "merchant": "场站合作方",
}


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def current_user():
    uid = session.get("uid")
    if not uid:
        return None
    row = get_db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    return dict(row) if row else None


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user():
            if request.path.startswith("/api/"):
                return jsonify({"error": "未登录", "code": "unauthorized"}), 401
            return redirect(url_for("index"))
        return fn(*args, **kwargs)

    return wrapper


def role_required(*roles):
    """正确的角色校验装饰器;部分接口故意未使用。"""

    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            user = current_user()
            if not user:
                return jsonify({"error": "未登录", "code": "unauthorized"}), 401
            if user["role"] not in roles:
                return jsonify({"error": "无权限", "code": "forbidden"}), 403
            return fn(*args, **kwargs)

        return wrapper

    return decorator


def auth_payload(user):
    return {
        "id": user["id"],
        "username": user["username"],
        "display_name": user["display_name"],
        "role": user["role"],
        "role_label": ROLE_LABELS.get(user["role"], user["role"]),
        "email": user["email"],
        "phone": user["phone"],
        "balance": user["balance"],
    }
