"""靶场种子数据:用户、站点、充电桩、订单、发票、反馈、API 密钥。"""
import os
import sqlite3
import hashlib

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL,
    display_name TEXT NOT NULL,
    email TEXT NOT NULL,
    phone TEXT NOT NULL,
    balance REAL NOT NULL DEFAULT 0,
    api_key TEXT
);
CREATE TABLE IF NOT EXISTS stations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    address TEXT NOT NULL,
    city TEXT NOT NULL,
    operator_id INTEGER NOT NULL,
    longitude REAL,
    latitude REAL,
    status TEXT NOT NULL DEFAULT 'online',
    capacity INTEGER NOT NULL DEFAULT 8
);
CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_no TEXT UNIQUE NOT NULL,
    user_id INTEGER NOT NULL,
    station_id INTEGER NOT NULL,
    connector TEXT NOT NULL,
    kwh REAL NOT NULL,
    unit_price REAL NOT NULL,
    amount REAL NOT NULL,
    status TEXT NOT NULL,
    started_at TEXT NOT NULL,
    ended_at TEXT NOT NULL,
    vehicle_plate TEXT,
    remark TEXT
);
CREATE TABLE IF NOT EXISTS invoices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    tax_no TEXT,
    amount REAL NOT NULL,
    status TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS feedback (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    order_id INTEGER,
    category TEXT NOT NULL,
    content TEXT NOT NULL,
    contact TEXT,
    status TEXT NOT NULL DEFAULT 'open',
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS api_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    key TEXT UNIQUE NOT NULL,
    scope TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS xss_hits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    detail TEXT,
    created_at TEXT NOT NULL
);
"""


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


USERS = [
    # username, password, role, display, email, phone, balance, api_key
    ("admin", "Admin@123", "admin", "系统管理员", "admin@charge.local", "13800000001", 0, "ak_admin_9f3a2c"),
    ("operator", "Operator@123", "operator", "运营专员-王芳", "operator@charge.local", "13800000002", 0, "ak_oper_7d1b5e"),
    ("finance", "Finance@123", "finance", "财务专员-李强", "finance@charge.local", "13800000003", 0, "ak_fin_4c8e6a"),
    ("support", "Support@123", "support", "客服专员-赵敏", "support@charge.local", "13800000004", 0, "ak_sup_2b9f3d"),
    ("alice", "Alice@123", "driver", "车主-张伟", "alice@example.com", "13900000001", 386.5, "ak_drv_a1c4e9"),
    ("bob", "Bob@123", "driver", "车主-陈静", "bob@example.com", "13900000002", 122.0, "ak_drv_b7d2f8"),
    ("carol", "Carol@123", "driver", "车主-刘洋", "carol@example.com", "13900000003", 58.0, "ak_drv_c3e6a1"),
    ("merchant", "Merchant@123", "merchant", "场站合作方-阳光能源", "merchant@charge.local", "13800000005", 0, "ak_mer_5f8b2a"),
]

STATIONS = [
    (1, "国贸中心快充站", "朝阳区建国门外大街1号国贸商城B2", "北京", 2, 116.4601, 39.9087, "online", 12),
    (2, "望京SOHO充电站", "朝阳区望京街10号望京SOHO塔3", "北京", 2, 116.4809, 39.9963, "online", 8),
    (3, "中关村软件园超充站", "海淀区东北旺西路8号中关村软件园", "北京", 2, 116.2905, 40.0526, "online", 16),
    (4, "虹桥枢纽P6充电站", "闵行区申贵路1500号虹桥枢纽P6停车场", "上海", 8, 121.3213, 31.1942, "online", 20),
    (5, "深圳湾科技园充电站", "南山区高新南九道9号深圳湾科技园", "深圳", 8, 113.9432, 22.5332, "maintenance", 10),
    (6, "杭州未来科技城站", "余杭区文一西路998号海创园", "杭州", 2, 119.9732, 30.2792, "online", 6),
]


def _orders():
    rows = []
    base = [
        ("alice", 1, "CCS2", 42.6, 1.20, 51.12, "completed", "2024-09-02T08:12:00", "2024-09-02T09:01:00", "京A·88231", "早间通勤补电"),
        ("alice", 3, "CCS2", 55.8, 1.15, 64.17, "completed", "2024-09-08T19:20:00", "2024-09-08T20:25:00", "京A·88231", ""),
        ("alice", 2, "GB/T", 30.2, 1.05, 31.71, "paid", "2024-09-15T12:05:00", "2024-09-15T12:48:00", "京A·88231", "午间快充"),
        ("alice", 4, "CCS2", 61.4, 1.35, 82.89, "completed", "2024-10-03T09:33:00", "2024-10-03T10:42:00", "京A·88231", "出差上海"),
        ("alice", 6, "GB/T", 28.7, 1.00, 28.70, "refunded", "2024-10-21T16:11:00", "2024-10-21T16:40:00", "京A·88231", "设备故障退款"),
        ("bob", 2, "GB/T", 33.9, 1.05, 35.60, "completed", "2024-09-05T07:45:00", "2024-09-05T08:30:00", "京B·66102", ""),
        ("bob", 5, "CCS2", 48.3, 1.25, 60.38, "completed", "2024-09-19T21:02:00", "2024-09-19T22:10:00", "京B·66102", "夜间谷电"),
        ("bob", 3, "CCS2", 25.5, 1.15, 29.33, "paid", "2024-10-11T18:22:00", "2024-10-11T19:05:00", "京B·66102", ""),
        ("bob", 1, "CCS2", 12.4, 1.20, 14.88, "cancelled", "2024-10-28T10:15:00", "2024-10-28T10:22:00", "京B·66102", "超时未启动"),
        ("carol", 6, "GB/T", 36.8, 1.00, 36.80, "completed", "2024-09-22T14:08:00", "2024-09-22T15:12:00", "浙C·77345", ""),
        ("carol", 4, "CCS2", 41.2, 1.35, 55.62, "completed", "2024-10-06T11:30:00", "2024-10-06T12:22:00", "浙C·77345", "节假日出行"),
        ("carol", 5, "CCS2", 18.6, 1.25, 23.25, "cancelled", "2024-10-19T20:47:00", "2024-10-19T20:55:00", "浙C·77345", "扫码失败"),
        ("alice", 1, "CCS2", 22.3, 1.20, 26.76, "completed", "2024-11-04T07:58:00", "2024-11-04T08:31:00", "京A·88231", ""),
        ("bob", 2, "GB/T", 19.8, 1.05, 20.79, "completed", "2024-11-07T13:40:00", "2024-11-07T14:12:00", "京B·66102", ""),
        ("carol", 6, "GB/T", 24.5, 1.00, 24.50, "paid", "2024-11-09T17:05:00", "2024-11-09T17:41:00", "浙C·77345", ""),
    ]
    users = {u[0]: idx + 1 for idx, u in enumerate(USERS)}
    for i, (uname, sid, conn, kwh, price, amount, status, start, end, plate, remark) in enumerate(base, 1):
        rows.append((f"ORD2024{i:05d}", users[uname], sid, conn, kwh, price, amount, status, start, end, plate, remark))
    return rows


INVOICES = [
    ("alice", 1, "个人", "", 51.12, "issued"),
    ("alice", 2, "个人", "", 64.17, "issued"),
    ("alice", 4, "北京某某科技有限公司", "91110105MA01X2Y3Z4", 82.89, "issued"),
    ("bob", 6, "个人", "", 35.60, "issued"),
    ("bob", 7, "个人", "", 60.38, "pending"),
    ("carol", 10, "个人", "", 36.80, "issued"),
    ("carol", 11, "个人", "", 55.62, "pending"),
]

FEEDBACK = [
    ("alice", 5, "charge", "充电中途跳枪,已扣款但未充上电,请核查。", "13900000001", "closed", "2024-10-21T17:02:00"),
    ("bob", 9, "scan", "扫码后一直提示启动中,最后订单被取消。", "13900000002", "open", "2024-10-28T10:31:00"),
    ("carol", 12, "scan", "深圳湾站扫码失败,APP无错误提示。", "13900000003", "open", "2024-10-19T21:05:00"),
    ("alice", 2, "invoice", "发票抬头填写错误,需要重开。", "13900000001", "closed", "2024-09-09T10:12:00"),
]

AUDIT = [
    ("admin", "login", "管理员登录成功", "2024-11-01T09:00:00"),
    ("operator", "station_update", "更新站点 2 容量", "2024-11-02T14:20:00"),
    ("finance", "invoice_review", "审核发票 INV-0004", "2024-11-03T11:05:00"),
    ("support", "feedback_assign", "分配工单 FB-0002", "2024-11-05T16:30:00"),
]


def init_db(path: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    conn = sqlite3.connect(path)
    conn.executescript(SCHEMA)

    for u in USERS:
        conn.execute(
            "INSERT OR IGNORE INTO users (username,password_hash,role,display_name,email,phone,balance,api_key)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (u[0], hash_password(u[1]), u[2], u[3], u[4], u[5], u[6], u[7]),
        )
    for s in STATIONS:
        conn.execute(
            "INSERT OR IGNORE INTO stations (id,name,address,city,operator_id,longitude,latitude,status,capacity)"
            " VALUES (?,?,?,?,?,?,?,?,?)", s,
        )
    for o in _orders():
        conn.execute(
            "INSERT OR IGNORE INTO orders (order_no,user_id,station_id,connector,kwh,unit_price,amount,status,"
            "started_at,ended_at,vehicle_plate,remark) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", o,
        )
    user_ids = {row[0]: row[1] for row in conn.execute("SELECT username,id FROM users")}
    for i, (uname, oid, title, tax_no, amount, status) in enumerate(INVOICES, 1):
        conn.execute(
            "INSERT OR IGNORE INTO invoices (id,order_id,user_id,title,tax_no,amount,status) VALUES (?,?,?,?,?,?,?)",
            (i, oid, user_ids[uname], title, tax_no, amount, status),
        )
    for i, f in enumerate(FEEDBACK, 1):
        conn.execute(
            "INSERT OR IGNORE INTO feedback (id,user_id,order_id,category,content,contact,status,created_at)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (i, user_ids[f[0]], f[1], f[2], f[3], f[4], f[5], f[6]),
        )
    for a in AUDIT:
        conn.execute(
            "INSERT OR IGNORE INTO audit_logs (actor,action,detail,created_at) VALUES (?,?,?,?)", a,
        )
    # api_keys 与用户同步
    for u in USERS:
        uid = conn.execute("SELECT id FROM users WHERE username=?", (u[0],)).fetchone()[0]
        conn.execute(
            "INSERT OR IGNORE INTO api_keys (user_id,key,scope,active) VALUES (?,?,?,1)",
            (uid, u[7], u[2]),
        )
    conn.commit()
    conn.close()


if __name__ == "__main__":
    init_db(os.path.join(BASE_DIR, "data", "charger.db"))
    print("seed done")
