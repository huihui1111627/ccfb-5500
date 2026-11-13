"""埋点清单映射与检出率/误报率计算。"""
import json
import os
import re

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CATALOG_PATH = os.path.join(BASE_DIR, "benchmark", "vuln_catalog.json")

# (vuln_id, category, path_regex, param_pattern)
MATCHERS = [
    ("SQLI-01", "sqli", r"^/api/orders", r"q|sort|status"),
    ("SQLI-02", "sqli", r"^/api/auth/login$", r"username"),
    ("XSS-01", "xss", r"^/help/search$", r"keyword"),
    ("XSS-02", "xss", r"^(/notice|/api/feedback)$", r"content"),
    ("XSS-03", "xss", r"^(/profile/\d+|/api/profile)$", r"display_name"),
    ("SSRF-01", "ssrf", r"^/api/stations/\d+/cover$", r"url"),
    ("SSRF-02", "ssrf", r"^/api/integrations/fetch$", r"url"),
    ("TRAV-01", "traversal", r"^/api/invoices/\d+/attachment$", r"file"),
    ("TRAV-02", "traversal", r"^/api/files/download$", r"path"),
    ("IDOR-01", "idor", r"^/api/orders/\d+$", r"id"),
    ("IDOR-02", "idor", r"^/api/invoices/\d+$", r"id"),
    ("IDOR-03", "idor", r"^/api/feedback/\d+$", r"id"),
    ("IDOR-04", "idor", r"^/api/users/\d+$", r"id"),
    ("BAC-01", "bvac", r"^/api/admin/users$", r""),
    ("BAC-02", "bvac", r"^/api/admin/api-keys$", r""),
    ("BAC-03", "bvac", r"^/api/finance/settlements$", r""),
    ("BAC-04", "bvac", r"^/api/profile$", r"role"),
    ("INFO-01", "info", r"^/api/debug/config$", r""),
]


def normalize_path(url: str) -> str:
    path = re.sub(r"^https?://[^/]+", "", url or "")
    return path.split("?")[0]


def match_vuln_ids(category: str, url: str, param: str = "", evidence: dict | None = None) -> list[str]:
    """一个发现可能对应多个埋点(如同一接口上不同攻击者角色)。返回全部命中的埋点 ID。"""
    path = normalize_path(url)
    evidence = evidence or {}
    matched = []
    for vuln_id, cat, path_re, param_re in MATCHERS:
        if cat != category:
            continue
        if not re.search(path_re, path):
            continue
        if param_re and not re.search(param_re, param or ""):
            continue
        # BAC-04 批量赋值需要证据里出现 role 提权;其余按路径匹配
        if vuln_id == "BAC-04" and evidence.get("escalated_to") != "admin":
            continue
        matched.append(vuln_id)
    # 存储型 XSS 落库到 sink 页面时,也按其提交入口归类
    if category == "xss" and evidence.get("kind") == "stored":
        submit = evidence.get("submit", "")
        if "feedback" in submit and "XSS-02" not in matched:
            matched.append("XSS-02")
        if "profile" in submit and "XSS-03" not in matched:
            matched.append("XSS-03")
    return matched


def match_vuln_id(category: str, url: str, param: str = "", evidence: dict | None = None):
    ids = match_vuln_ids(category, url, param, evidence)
    return ids[0] if ids else None


def load_catalog() -> dict:
    if os.path.exists(CATALOG_PATH):
        with open(CATALOG_PATH, "r", encoding="utf-8") as fh:
            return json.load(fh)
    return {"items": []}


def metrics(findings: list[dict]) -> dict:
    """findings: [{'vuln_id','status','category','url','param'}]"""
    cat = load_catalog().get("items", [])
    total = len(cat)
    detected_ids = set()
    for f in findings:
        if f.get("status") != "confirmed":
            continue
        detected_ids.update(f.get("vuln_ids") or ([f["vuln_id"]] if f.get("vuln_id") else []))
    missed = [c["id"] for c in cat if c["id"] not in detected_ids]
    covered = total - len(missed)
    confirmed = [f for f in findings if f.get("status") == "confirmed"]
    unmatched = [f for f in confirmed if not f.get("vuln_id")]
    reported = [f for f in findings if f.get("status") in ("confirmed", "suspected", "false_positive")]
    manual_fp = [f for f in findings if f.get("status") == "false_positive"]
    auto_confirmed = confirmed
    fp_count = len(manual_fp) + len(unmatched)
    detection_rate = round(covered / total * 100, 1) if total else 0.0
    fp_rate = round(fp_count / max(len(auto_confirmed) + len(manual_fp), 1) * 100, 1)
    authz_total = len([c for c in cat if c["category"] in ("idor", "bvac")])
    authz_hit = len([c for c in cat if c["category"] in ("idor", "bvac") and c["id"] in detected_ids])
    return {
        "catalog_total": total,
        "detected": covered,
        "missed": missed,
        "detection_rate": detection_rate,
        "confirmed_count": len(auto_confirmed),
        "manual_false_positive": len(manual_fp),
        "unmatched_confirmed": len(unmatched),
        "false_positive_rate": fp_rate,
        "authz_total": authz_total,
        "authz_detected": authz_hit,
        "authz_rate": round(authz_hit / authz_total * 100, 1) if authz_total else 0.0,
        "reported_total": len(reported),
    }
