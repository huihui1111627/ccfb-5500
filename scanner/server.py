"""扫描平台 Web 服务:任务、资产、漏洞、复核、报告。"""
import json
import os

from flask import Flask, abort, jsonify, redirect, render_template, request, send_file, url_for

from scanner import catalog as cat_mod
from scanner.config import DEFAULT_ROLES, REPORT_DIR, VULN_CATALOG
from scanner.engine import _RUNNERS, get_runner
from scanner.models import (
    Asset, CrawlEntry, Finding, ScanTask, Suppression, init_db, json_load, new_session, now_iso,
)
from scanner.report import collect, generate_reports

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["JSON_AS_ASCII"] = False

init_db()

PAGE_SIZE = 50


def _truthy(value) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("1", "true", "on", "yes")


@app.context_processor
def inject_globals():
    return {"now": now_iso()}


@app.template_filter("fromjson")
def fromjson(raw):
    return json_load(raw, [])


# ---------------------------------------------------------------- 任务
@app.route("/")
def index():
    return redirect(url_for("tasks"))


@app.route("/tasks")
def tasks():
    s = new_session()
    try:
        rows = s.query(ScanTask).order_by(ScanTask.id.desc()).all()
        data = []
        for t in rows:
            confirmed = s.query(Finding).filter_by(task_id=t.id, status="confirmed").count()
            suspected = s.query(Finding).filter_by(task_id=t.id, status="suspected").count()
            assets = s.query(Asset).filter_by(task_id=t.id).count()
            data.append({"task": t, "confirmed": confirmed, "suspected": suspected, "assets": assets})
        return render_template("tasks.html", rows=data, vuln_catalog=VULN_CATALOG,
                               default_roles=DEFAULT_ROLES)
    finally:
        s.close()


@app.post("/api/tasks")
def create_task():
    body = request.get_json(silent=True) or request.form
    name = (body.get("name") or "").strip() or "未命名扫描"
    target = (body.get("target_url") or "").strip().rstrip("/") or "http://127.0.0.1:5000"
    roles = DEFAULT_ROLES
    if body.get("roles_json"):
        try:
            roles = json.loads(body["roles_json"])
        except ValueError:
            pass
    scope = {
        "rate_limit": float(body.get("rate_limit") or 8),
        "max_pages": int(body.get("max_pages") or 120),
        "max_depth": int(body.get("max_depth") or 4),
        "crawl_spa": _truthy(body.get("crawl_spa", "1")),
        "check_types": body.getlist("check_types") if hasattr(body, "getlist") else body.get("check_types"),
    }
    if not scope["check_types"]:
        scope["check_types"] = ["sqli", "xss", "ssrf", "traversal", "idor", "bvac", "info", "redirect"]
    s = new_session()
    try:
        task = ScanTask(name=name, target_url=target,
                        auth_config=json.dumps({"roles": roles}, ensure_ascii=False),
                        scope_config=json.dumps(scope, ensure_ascii=False))
        s.add(task)
        s.commit()
        tid = task.id
    finally:
        s.close()
    runner = get_runner(tid, create=True)
    runner.start()
    return jsonify({"ok": True, "task_id": tid})


def _task_or_404(task_id):
    s = new_session()
    try:
        task = s.get(ScanTask, task_id)
        if not task:
            abort(404)
        return {"id": task.id, "name": task.name, "target_url": task.target_url,
                "status": task.status, "stage": task.stage, "progress": task.progress,
                "message": task.message, "request_count": task.request_count,
                "created_at": task.created_at, "started_at": task.started_at,
                "finished_at": task.finished_at}
    finally:
        s.close()


@app.route("/tasks/<int:task_id>")
def task_detail(task_id):
    task = _task_or_404(task_id)
    return render_template("task_detail.html", task=task)


@app.get("/api/tasks")
def api_tasks():
    s = new_session()
    try:
        rows = s.query(ScanTask).order_by(ScanTask.id.desc()).all()
        return jsonify({"items": [{
            "id": t.id, "name": t.name, "target_url": t.target_url, "status": t.status,
            "stage": t.stage, "progress": t.progress, "message": t.message,
            "request_count": t.request_count, "created_at": t.created_at,
        } for t in rows]})
    finally:
        s.close()


@app.get("/api/tasks/<int:task_id>/status")
def api_task_status(task_id):
    s = new_session()
    try:
        t = s.get(ScanTask, task_id)
        if not t:
            return jsonify({"error": "not found"}), 404
        counts = {
            "confirmed": s.query(Finding).filter_by(task_id=task_id, status="confirmed").count(),
            "suspected": s.query(Finding).filter_by(task_id=task_id, status="suspected").count(),
            "false_positive": s.query(Finding).filter_by(task_id=task_id, status="false_positive").count(),
            "assets": s.query(Asset).filter_by(task_id=task_id).count(),
        }
        return jsonify({
            "id": t.id, "status": t.status, "stage": t.stage, "progress": t.progress,
            "message": t.message, "request_count": t.request_count, "counts": counts,
        })
    finally:
        s.close()


@app.post("/api/tasks/<int:task_id>/pause")
def api_pause(task_id):
    runner = get_runner(task_id)
    if not runner or not runner.thread or not runner.thread.is_alive():
        return jsonify({"error": "任务未在运行"}), 400
    runner.pause_scan()
    return jsonify({"ok": True, "status": "paused"})


@app.post("/api/tasks/<int:task_id>/resume")
def api_resume(task_id):
    runner = get_runner(task_id)
    if runner and runner.pause and runner.thread and runner.thread.is_alive():
        runner.resume_scan()
        return jsonify({"ok": True, "status": "running"})
    # 断点续扫:重新起线程,已完成的阶段会被跳过
    runner = get_runner(task_id, create=True)
    runner.start()
    return jsonify({"ok": True, "status": "resumed"})


@app.post("/api/tasks/<int:task_id>/stop")
def api_stop(task_id):
    runner = get_runner(task_id)
    if runner:
        runner.stop_scan()
    return jsonify({"ok": True, "status": "stopped"})


@app.delete("/api/tasks/<int:task_id>")
def api_delete_task(task_id):
    s = new_session()
    try:
        task = s.get(ScanTask, task_id)
        if task:
            s.delete(task)
            s.commit()
        return jsonify({"ok": True})
    finally:
        s.close()


# ---------------------------------------------------------------- 资产
@app.route("/assets")
def assets_page():
    task_id = request.args.get("task_id", type=int)
    s = new_session()
    try:
        tasks_list = s.query(ScanTask).order_by(ScanTask.id.desc()).all()
        q = s.query(Asset)
        if task_id:
            q = q.filter_by(task_id=task_id)
        kind = request.args.get("kind")
        if kind:
            q = q.filter_by(kind=kind)
        assets = q.order_by(Asset.id).limit(500).all()
        return render_template("assets.html", assets=assets, tasks_list=tasks_list,
                               task_id=task_id, kind=kind)
    finally:
        s.close()


# ---------------------------------------------------------------- 漏洞
@app.route("/findings")
def findings_page():
    task_id = request.args.get("task_id", type=int)
    status = request.args.get("status")
    category = request.args.get("category")
    s = new_session()
    try:
        tasks_list = s.query(ScanTask).order_by(ScanTask.id.desc()).all()
        q = s.query(Finding)
        if task_id:
            q = q.filter_by(task_id=task_id)
        if status:
            q = q.filter_by(status=status)
        if category:
            q = q.filter_by(category=category)
        rows = q.order_by(Finding.id).all()
        items = []
        for f in rows:
            items.append({
                "f": f, "evidence": json_load(f.evidence, {}),
                "verification": json_load(f.verification, {}),
                "occurrences": json_load(f.occurrences, []),
            })
        all_findings = [_dict(f) for f in s.query(Finding).filter_by(task_id=task_id).all()] if task_id else []
        metrics = cat_mod.metrics(all_findings) if task_id else None
        return render_template("findings.html", items=items, tasks_list=tasks_list,
                               task_id=task_id, status=status, category=category,
                               metrics=metrics, categories=_categories(s, task_id))
    finally:
        s.close()


@app.get("/api/findings")
def api_findings():
    task_id = request.args.get("task_id", type=int)
    s = new_session()
    try:
        q = s.query(Finding)
        if task_id:
            q = q.filter_by(task_id=task_id)
        return jsonify({"items": [_dict(f) for f in q.order_by(Finding.id).all()]})
    finally:
        s.close()


def _dict(f):
    return {
        "id": f.id, "vuln_id": f.vuln_id, "vuln_ids": json_load(f.vuln_ids, []),
        "category": f.category, "title": f.title,
        "severity": f.severity, "url": f.url, "method": f.method, "param": f.param,
        "role": f.role, "status": f.status, "confidence": f.confidence,
        "dedup_key": f.dedup_key, "occurrences": json_load(f.occurrences, []),
        "verification": json_load(f.verification, {}),
    }


def _categories(s, task_id):
    q = s.query(Finding.category)
    if task_id:
        q = q.filter_by(task_id=task_id)
    return sorted({row[0] for row in q.all()})


# ---------------------------------------------------------------- 复核
@app.route("/review")
def review_page():
    task_id = request.args.get("task_id", type=int)
    s = new_session()
    try:
        tasks_list = s.query(ScanTask).order_by(ScanTask.id.desc()).all()
        q = s.query(Finding).filter(Finding.status.in_(["confirmed", "suspected"]))
        if task_id:
            q = q.filter_by(task_id=task_id)
        rows = q.order_by(Finding.category, Finding.id).all()
        items = []
        for f in rows:
            items.append({
                "f": f, "evidence": json_load(f.evidence, {}),
                "verification": json_load(f.verification, {}),
                "occurrences": json_load(f.occurrences, []),
            })
        suppress_host = None
        if task_id:
            t = s.get(ScanTask, task_id)
            if t:
                from urllib.parse import urlsplit
                suppress_host = urlsplit(t.target_url).hostname
        suppressed = []
        if suppress_host:
            suppressed = [{"key": x.dedup_key, "reason": x.reason, "at": x.created_at}
                          for x in s.query(Suppression).filter_by(host=suppress_host).all()]
        return render_template("review.html", items=items, tasks_list=tasks_list,
                               task_id=task_id, suppressed=suppressed, suppressed_count=len(suppressed))
    finally:
        s.close()


@app.post("/api/findings/<int:fid>/false-positive")
def mark_false_positive(fid):
    body = request.get_json(silent=True) or request.form
    reason = body.get("reason", "")
    s = new_session()
    try:
        f = s.get(Finding, fid)
        if not f:
            abort(404)
        task = s.get(ScanTask, f.task_id)
        from urllib.parse import urlsplit
        host = urlsplit(task.target_url).hostname
        f.status = "false_positive"
        f.note = reason
        f.updated_at = now_iso()
        exists = s.query(Suppression).filter_by(host=host, dedup_key=f.dedup_key).first()
        if not exists:
            s.add(Suppression(host=host, dedup_key=f.dedup_key, category=f.category,
                              reason=reason, finding_id=f.id))
        s.commit()
        return jsonify({"ok": True, "message": "已标记误报,后续同主机扫描将跳过该 key"})
    finally:
        s.close()


@app.post("/api/findings/<int:fid>/reopen")
def reopen_finding(fid):
    s = new_session()
    try:
        f = s.get(Finding, fid)
        if not f:
            abort(404)
        task = s.get(ScanTask, f.task_id)
        from urllib.parse import urlsplit
        host = urlsplit(task.target_url).hostname
        f.status = "suspected" if not json_load(f.verification, {}).get("confirmed") else "confirmed"
        f.updated_at = now_iso()
        sup = s.query(Suppression).filter_by(host=host, dedup_key=f.dedup_key).first()
        if sup:
            s.delete(sup)
        s.commit()
        return jsonify({"ok": True})
    finally:
        s.close()


@app.post("/api/findings/<int:fid>/reverify")
def reverify_finding(fid):
    """对单条发现重新发起验证(复核页手动触发)。"""
    from scanner.config import ScanConfig
    from scanner.detectors import Candidate
    from scanner.http import HttpEngine, PauseController
    from scanner.session import SessionManager
    from scanner.verify import Verifier

    s = new_session()
    try:
        f = s.get(Finding, fid)
        if not f:
            abort(404)
        task = s.get(ScanTask, f.task_id)
        sc = json_load(task.scope_config, {})
        cfg = ScanConfig(target_url=task.target_url)
        cfg.roles = json_load(task.auth_config, {}).get("roles") or cfg.roles
        if sc.get("rate_limit"):
            cfg.rate_limit = float(sc["rate_limit"])
        pause = PauseController()
        engine = HttpEngine(cfg, pause)
        try:
            sessions = SessionManager(engine, cfg)
            sessions.login_all()
            cand = Candidate(
                category=f.category, title=f.title, severity=f.severity, url=f.url or "",
                method=f.method or "GET", param=f.param or "", role=f.role or "",
                evidence=json_load(f.evidence, {}), dedup_key=f.dedup_key,
            )
            verifier = Verifier(engine, cfg, sessions)
            ok, detail = getattr(verifier, f"_verify_{f.category}", lambda c: (False, {"reason": "无验证器"}))(cand)
            f.verification = json.dumps({"confirmed": ok, **detail}, ensure_ascii=False)
            f.status = "confirmed" if ok else "suspected"
            f.verify_request = getattr(cand, "verify_request", "")
            f.verify_response = getattr(cand, "verify_response", "")
            f.updated_at = now_iso()
            s.commit()
            return jsonify({"ok": True, "confirmed": ok, "detail": detail})
        finally:
            engine.close()
    finally:
        s.close()


# ---------------------------------------------------------------- 报告
@app.route("/reports")
def reports_page():
    task_id = request.args.get("task_id", type=int)
    s = new_session()
    try:
        tasks_list = s.query(ScanTask).order_by(ScanTask.id.desc()).all()
        data = None
        if task_id:
            data = collect(task_id)
        files = []
        for name in sorted(os.listdir(REPORT_DIR), reverse=True):
            if name.endswith((".html", ".json")):
                files.append({"name": name, "size": os.path.getsize(os.path.join(REPORT_DIR, name))})
        return render_template("reports.html", tasks_list=tasks_list, task_id=task_id,
                               data=data, files=files)
    finally:
        s.close()


@app.post("/api/tasks/<int:task_id>/report")
def api_generate_report(task_id):
    paths = generate_reports(task_id)
    return jsonify({"ok": bool(paths), **paths})


@app.get("/reports/<int:task_id>/<fmt>")
def report_file(task_id, fmt):
    if fmt not in ("html", "json"):
        abort(404)
    path = os.path.join(REPORT_DIR, f"scan_{task_id}.{fmt}")
    if not os.path.exists(path):
        generate_reports(task_id)
    if not os.path.exists(path):
        abort(404)
    return send_file(path, as_attachment=False, mimetype="text/html" if fmt == "html" else "application/json")


@app.get("/reports/download/<name>")
def report_download(name):
    safe = os.path.basename(name)
    path = os.path.join(REPORT_DIR, safe)
    if not os.path.exists(path):
        abort(404)
    return send_file(path, as_attachment=True)


@app.get("/api/benchmark")
def api_benchmark():
    s = new_session()
    try:
        task_id = request.args.get("task_id", type=int)
        rows = s.query(Finding)
        if task_id:
            rows = rows.filter_by(task_id=task_id)
        data = [_dict(f) for f in rows.all()]
        result = cat_mod.metrics(data)
        result["catalog"] = cat_mod.load_catalog().get("items", [])
        return jsonify(result)
    finally:
        s.close()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000, debug=False)
