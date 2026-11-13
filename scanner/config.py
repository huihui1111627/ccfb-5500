"""扫描配置与内置载荷/规则。"""
import os
from dataclasses import dataclass, field

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORT_DIR = os.path.join(BASE_DIR, "scanner", "reports")
os.makedirs(REPORT_DIR, exist_ok=True)

DEFAULT_ROLES = {
    "admin": {"username": "admin", "password": "Admin@123"},
    "operator": {"username": "operator", "password": "Operator@123"},
    "driver": {"username": "alice", "password": "Alice@123"},
    "other_driver": {"username": "bob", "password": "Bob@123"},
}

# 垂直越权:低权限角色不应访问的高权限接口
PRIVILEGED_PATHS = [
    ("admin", "/api/admin/users"),
    ("admin", "/api/admin/api-keys"),
    ("finance", "/api/finance/settlements"),
]

# SQL 注入探测:错误/联合/布尔/时间
SQL_ERROR_MARKERS = [
    "SQL syntax", "sqlite3.OperationalError", "no such column", "no such table",
    "unrecognized token", "syntax error", "SQLSTATE", "You have an error in your SQL",
    "near \"", "Incorrect syntax near", "union do not have", "do not have the same number",
]
SQL_PAYLOADS = {
    "error": ["'", "\"", "')", "'))", "\\", "%27"],
    "union": ["' UNION SELECT 1,2,3,4,5,6,7,8,9,10-- -", "' UNION SELECT NULL-- -"],
    "boolean_true": ["' OR '1'='1' -- -", "' OR 1=1 -- -"],
    "boolean_false": ["' AND '1'='2' -- -", "' AND 1=2 -- -"],
    "time": ["' AND 1=randomblob(1000000000) -- -"],
}

# XSS 载荷(带唯一回连 token 以及可被静态匹配的标记)
XSS_PAYLOADS = [
    "XSS<script>window.__XSS_HIT=1;/*{token}*/</script>",
    "\"><img src=x onerror=\"window.__XSS_HIT=1\">",
    "'><svg/onload=\"window.__XSS_HIT=1\">",
]

# SSRF 探针:优先用靶场内的内部端点做回连标记(不需要外部网络)
SSRF_INTERNAL_PROBES = [
    ("/api/debug/config", ["secret_key", "integration_token"]),
    ("/api/admin/users", ["api_key", "username"]),
    ("/api/finance/settlements", ["settlement_account"]),
]
SSRF_FILE_PROBES = [
    ("file:///etc/passwd", "root:"),
]

TRAVERSAL_PAYLOADS = [
    "../../../../../../../../etc/passwd",
    "../../../../../../../etc/passwd",
    "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
    "../../../../../../../../etc/passwd",
    "/etc/passwd",
    "../avatars/default.txt",
]
TRAVERSAL_ABS_MARKERS = ["root:x:0:0", "root:*:0:0", "话术模板"]

SENSITIVE_KEYWORDS = [
    "secret_key", "password", "api_key", "access_key", "private_key", "token",
    "db_password", "smtp", "payment", "integration_token",
]

# 检出基准清单
VULN_CATALOG = {
    "SQLI-01": {"name": "订单列表 SQL 注入", "category": "sqli", "severity": "critical",
                "where": "GET /api/orders 参数 q / sort"},
    "SQLI-02": {"name": "登录处 SQL 注入", "category": "sqli", "severity": "critical",
                "where": "POST /api/auth/login username"},
    "XSS-01": {"name": "帮助中心反射型 XSS", "category": "xss", "severity": "high",
               "where": "GET /help/search keyword"},
    "XSS-02": {"name": "工单存储型 XSS(公告页)", "category": "xss", "severity": "high",
               "where": "POST /api/feedback content → GET /notice"},
    "XSS-03": {"name": "用户档案存储型 XSS", "category": "xss", "severity": "high",
               "where": "PUT /api/profile display_name → GET /profile/<id>"},

    "SSRF-01": {"name": "场站封面 SSRF", "category": "ssrf", "severity": "high",
                "where": "GET /api/stations/<id>/cover url"},
    "SSRF-02": {"name": "合作方数据抓取 SSRF", "category": "ssrf", "severity": "high",
                "where": "GET /api/integrations/fetch url"},
    "TRAV-01": {"name": "发票附件路径穿越", "category": "traversal", "severity": "high",
                "where": "GET /api/invoices/<id>/attachment file"},
    "TRAV-02": {"name": "文件下载路径穿越", "category": "traversal", "severity": "high",
                "where": "GET /api/files/download path"},
    "IDOR-01": {"name": "订单详情 IDOR(水平)", "category": "idor", "severity": "high",
                "where": "GET /api/orders/<id>"},
    "IDOR-02": {"name": "发票详情 IDOR(水平)", "category": "idor", "severity": "high",
                "where": "GET /api/invoices/<id>"},
    "IDOR-03": {"name": "工单详情 IDOR(水平)", "category": "idor", "severity": "high",
                "where": "GET /api/feedback/<id>"},
    "IDOR-04": {"name": "用户档案 IDOR(水平)", "category": "idor", "severity": "high",
                "where": "GET /api/users/<id>"},
    "BAC-01": {"name": "用户列表越权(垂直)", "category": "bvac", "severity": "critical",
               "where": "GET /api/admin/users 任意角色"},
    "BAC-02": {"name": "API 密钥越权(垂直)", "category": "bvac", "severity": "critical",
               "where": "GET /api/admin/api-keys 任意角色"},
    "BAC-03": {"name": "运营结算越权(垂直)", "category": "bvac", "severity": "high",
               "where": "GET /api/finance/settlements 非财务角色"},
    "BAC-04": {"name": "个人资料批量赋值提权", "category": "bvac", "severity": "critical",
               "where": "PUT /api/profile role=admin"},

    "INFO-01": {"name": "调试配置未授权泄露", "category": "info", "severity": "high",
                "where": "GET /api/debug/config"},

}


@dataclass
class ScanConfig:
    target_url: str
    task_name: str = "本地靶场扫描"
    roles: dict = field(default_factory=lambda: dict(DEFAULT_ROLES))
    max_pages: int = 120
    max_depth: int = 4
    rate_limit: float = 8.0        # 全局请求/秒
    concurrency: int = 4
    timeout: float = 10.0
    crawl_spa: bool = True
    check_types: list = field(default_factory=lambda: ["sqli", "xss", "ssrf", "traversal", "idor", "bvac", "info", "redirect"])
    exclude_patterns: list = field(default_factory=lambda: ["/api/auth/logout", "/api/orders/.*/cancel"])
    max_scan_requests: int = 4000
    verify_timeout: float = 15.0
    user_agent: str = "ChargeOps-Scanner/1.0 (+local-lab)"
    report_dir: str = REPORT_DIR
