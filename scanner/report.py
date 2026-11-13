"""报告生成:HTML + JSON,附请求/响应原文,含检出率与误报率。"""
import json
import os
from datetime import datetime

from jinja2 import Environment, FileSystemLoader, select_autoescape

from scanner import catalog
from scanner.config import REPORT_DIR
from scanner.models import Asset, Finding, ScanTask, json_load, new_session


def _severity_order(sev):
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(sev, 5)


def _status_cn(status):
    return {"confirmed": "已确认", "suspected": "疑似", "false_positive": "已标误报"}.get(status, status)


def collect(task_id: int) -> dict:
    s = new_session()
    try:
        task = s.get(ScanTask, task_id)
        if not task:
            return {}
        findings = s.query(Finding).filter_by(task_id=task_id).all()
        assets = s.query(Asset).filter_by(task_id=task_id).all()
        fd = [_finding_dict(f) for f in findings]
        fd.sort(key=lambda x: (_severity_order(x["severity"]), x["category"], x["id"]))
        metrics = catalog.metrics(fd)
        by_category = {}
        for f in fd:
            if f["status"] != "confirmed":
                continue
            by_category.setdefault(f["category"], 0)
            by_category[f["category"]] += 1
        return {
            "task": {
                "id": task.id, "name": task.name, "target_url": task.target_url,
                "status": task.status, "created_at": task.created_at,
                "started_at": task.started_at, "finished_at": task.finished_at,
                "request_count": task.request_count,
            },
            "assets": [{
                "id": a.id, "url": a.url, "method": a.method, "kind": a.kind,
                "role": a.role, "params": json_load(a.params, []), "source": a.source,
            } for a in assets],
            "asset_count": len(assets),
            "api_count": len([a for a in assets if a.kind in ("api", "spa-api", "form")]),
            "findings": fd,
            "metrics": metrics,
            "by_category": by_category,
            "catalog": catalog.load_catalog().get("items", []),
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
    finally:
        s.close()


def _finding_dict(f: Finding) -> dict:
    return {
        "id": f.id, "vuln_id": f.vuln_id, "vuln_ids": json_load(f.vuln_ids, []),
        "category": f.category, "title": f.title,
        "severity": f.severity, "url": f.url, "method": f.method, "param": f.param,
        "role": f.role, "status": f.status, "status_cn": _status_cn(f.status),
        "confidence": f.confidence, "dedup_key": f.dedup_key,
        "evidence": json_load(f.evidence, {}), "verification": json_load(f.verification, {}),
        "occurrences": json_load(f.occurrences, []),
        "request": f.request or "", "response": f.response or "",
        "verify_request": f.verify_request or "", "verify_response": f.verify_response or "",
        "created_at": f.created_at,
    }


def generate_reports(task_id: int) -> dict:
    data = collect(task_id)
    if not data:
        return {}
    json_path = os.path.join(REPORT_DIR, f"scan_{task_id}.json")
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)

    env = Environment(
        loader=FileSystemLoader(os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")),
        autoescape=select_autoescape(["html"]),
    )
    tpl = env.get_template("report.html")
    html = tpl.render(**data)
    html_path = os.path.join(REPORT_DIR, f"scan_{task_id}.html")
    with open(html_path, "w", encoding="utf-8") as fh:
        fh.write(html)
    return {"json": json_path, "html": html_path}
