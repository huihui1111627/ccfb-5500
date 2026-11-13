"""去重合并 + 扫描编排。

流程:登录各角色 → 爬取(含 SPA)→ 落资产 → 注入类检测 → 越权检测 → 复核验证 → 落库。
Stage 可断点续扫:state 记录已完成阶段与已测参数组合。
"""
import json
import threading
import time
import traceback
import urllib.parse

from scanner import catalog
from scanner.config import ScanConfig
from scanner.crawler import Crawler, DiscoveredRequest
from scanner.detectors import Detectors
from scanner.http import HttpEngine, PauseController, ScanStopped
from scanner.models import Asset, CrawlEntry, Finding, ScanTask, Suppression, json_load, new_session, now_iso
from scanner.session import SessionManager
from scanner.verify import Verifier

STAGES = ["login", "crawl", "inject", "authz", "verify", "report"]


def dedupe_candidates(candidates):
    """同一漏洞多参数命中合并为一条,参数记入 occurrences。"""
    merged: dict[str, object] = {}
    for c in candidates:
        # 主参数本身也算一次命中,这样报告能完整展示合并了哪些参数
        if c.param and not any(o.get("param") == c.param for o in c.occurrences):
            c.occurrences.insert(0, {"param": c.param, "payload": (c.evidence or {}).get("payload", "")})
        key = c.dedup_key or f"{c.category}|{c.url}|{c.param}"
        if key in merged:
            base = merged[key]
            base.add_occurrence(c.param, (c.evidence or {}).get("payload", ""))
            if not base.response and c.response:
                base.response = c.response
            continue
        merged[key] = c
    return list(merged.values())


class ScanRunner:
    def __init__(self, task_id: int):
        self.task_id = task_id
        self.pause: PauseController | None = None
        self.thread: threading.Thread | None = None
        self.config: ScanConfig | None = None
        self.engine: HttpEngine | None = None

    # ------------------------------------------------------------ 控制
    def start(self):
        if self.thread and self.thread.is_alive():
            return False
        self.pause = PauseController()
        _RUNNERS[self.task_id] = self
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        return True

    def pause_scan(self):
        if self.pause:
            self.pause.pause()
        _update_task(self.task_id, status="paused")

    def resume_scan(self):
        if self.pause:
            self.pause.resume()
        _update_task(self.task_id, status="running")

    def stop_scan(self):
        if self.pause:
            self.pause.stop()
        _update_task(self.task_id, status="stopped", finished_at=now_iso())
        if self.engine:
            self.engine.close()

    # ------------------------------------------------------------ 主流程
    def _run(self):
        s = new_session()
        try:
            task = s.get(ScanTask, self.task_id)
            if not task:
                return
            cfg = self._build_config(task)
            self.config = cfg
            _update_task(self.task_id, status="running", started_at=task.started_at or now_iso(), stage="login", progress=2,
                         message="初始化会话")
            state = json_load(task.state, {})
            stages_done = set(state.get("stages_done", []))

            self.engine = HttpEngine(cfg, self.pause, on_request=self._on_request)
            sessions = SessionManager(self.engine, cfg)
            sessions.login_all()
            working = sessions.working_roles()
            _update_task(self.task_id, progress=6, message=f"登录成功角色:{', '.join(working)}")
            if not working:
                _update_task(self.task_id, status="failed", message="所有角色登录失败", finished_at=now_iso())
                return

            # ---------- 爬取
            if "crawl" not in stages_done:
                _update_task(self.task_id, stage="crawl", progress=10, message="开始爬取")
                crawler = Crawler(self.engine, cfg, sessions)
                primary = "admin" if "admin" in working else working[0]
                requests = crawler.run(primary_role=primary)
                self._emit_note(f"爬虫完成:共 {len(requests)} 条,SPA 泄露 {getattr(crawler, 'spa_count', 0)} 条")
                self._store_assets(requests, crawler)
                self._store_crawl_entries(requests)
                self._set_state(stages_done | {"login", "crawl"}, {"crawl_count": len(requests)})
            else:
                requests = self._load_crawl_entries()
                _update_task(self.task_id, progress=55, message=f"续扫:复用已抓取 {len(requests)} 条资产")

            # ---------- 注入类检测
            candidates = []
            if "inject" not in stages_done:
                _update_task(self.task_id, stage="inject", progress=58, message="注入/XSS/SSRF/穿越检测")
                det = Detectors(self.engine, cfg, sessions)
                det.on_progress = lambda m: _update_task(self.task_id, message=m)
                det.run_injection(requests)
                det.run_stored_xss(sessions)
                candidates = det.candidates
                self._persist_candidates(candidates)
                self._set_state(stages_done | {"inject"}, {"inject_candidates": len(candidates)})
            else:
                candidates = self._load_candidates()

            # ---------- 越权检测
            if "authz" not in stages_done:
                _update_task(self.task_id, stage="authz", progress=72, message="水平/垂直越权检测(换角色重放)")
                det = Detectors(self.engine, cfg, sessions)
                det.on_progress = lambda m: _update_task(self.task_id, message=m)
                det.run_authz(requests)
                candidates.extend(det.candidates)
                candidates = dedupe_candidates(candidates)
                self._set_state(stages_done | {"authz"}, {"all_candidates": len(candidates)})
                self._persist_candidates(candidates)
            else:
                candidates = self._load_candidates()

            if self.pause and self.pause.stopped:
                raise ScanStopped()

            # ---------- 复核
            if "verify" not in stages_done:
                _update_task(self.task_id, stage="verify", progress=84,
                             message=f"复现验证 {len(candidates)} 条疑似")
                verifier = Verifier(self.engine, cfg, sessions)
                suspicious = self._filter_suppressed(candidates)
                verified = verifier.verify_all(suspicious, progress=lambda m, v: _update_task(self.task_id, message=m))
                self._persist_findings(verified, sessions)
                self._set_state(stages_done | {"verify"}, {})
            else:
                _update_task(self.task_id, stage="verify", progress=88, message="续扫:复用已完成的复核结果")

            # ---------- 报告
            _update_task(self.task_id, stage="report", progress=96, message="生成报告")
            from scanner.report import generate_reports
            generate_reports(self.task_id)
            _update_task(self.task_id, status="completed", stage="done", progress=100,
                         message=f"完成:请求 {self.engine.request_count} 次", finished_at=now_iso(),
                         request_count=self.engine.request_count)
        except ScanStopped:
            _update_task(self.task_id, status="stopped", message="扫描已停止", finished_at=now_iso())
        except Exception as exc:  # noqa: BLE001
            _update_task(self.task_id, status="failed",
                         message=f"{type(exc).__name__}: {exc}\n{traceback.format_exc()[-1500:]}")
        finally:
            try:
                s.close()
            except Exception:  # noqa: BLE001
                pass
            if self.engine:
                self.engine.close()

    def _build_config(self, task) -> ScanConfig:
        auth = json_load(task.auth_config, {})
        scope = json_load(task.scope_config, {})
        cfg = ScanConfig(target_url=task.target_url)
        if auth.get("roles"):
            cfg.roles = auth["roles"]
        for key in ("max_pages", "max_depth", "rate_limit", "concurrency", "timeout",
                    "crawl_spa", "check_types", "exclude_patterns", "max_scan_requests"):
            if key in scope and scope[key] not in (None, ""):
                setattr(cfg, key, scope[key])
        return cfg

    def _emit_note(self, msg):
        _update_task(self.task_id, message=msg)

    def _on_request(self, method, url, status):
        if self.engine and self.engine.request_count % 5 == 0:
            _update_task(self.task_id, request_count=self.engine.request_count)

    # ------------------------------------------------------------ 持久化
    def _store_assets(self, requests, crawler):
        s = new_session()
        try:
            existing = {(a.method, a.url) for a in s.query(Asset).filter_by(task_id=self.task_id)}
            for req in requests[:800]:
                if (req.method, req.url) in existing:
                    continue
                s.add(Asset(
                    task_id=self.task_id, url=req.url, method=req.method, kind=req.kind,
                    source=req.source, params=json.dumps(req.params, ensure_ascii=False),
                    role=req.role, fingerprint=req.template(),
                ))
            s.commit()
        finally:
            s.close()

    def _store_crawl_entries(self, requests):
        s = new_session()
        try:
            s.query(CrawlEntry).filter_by(task_id=self.task_id).delete()
            for req in requests:
                s.add(CrawlEntry(
                    task_id=self.task_id, method=req.method, url=req.url,
                    template=req.template(), headers=json.dumps(req.headers, ensure_ascii=False),
                    body=req.body, role=req.role, kind=req.kind,
                ))
            s.commit()
        finally:
            s.close()

    def _load_crawl_entries(self):
        s = new_session()
        try:
            rows = s.query(CrawlEntry).filter_by(task_id=self.task_id).all()
            out = []
            for r in rows:
                out.append(DiscoveredRequest(
                    method=r.method, url=r.url, kind=r.kind, role=r.role,
                    params=[], headers=json_load(r.headers, {}), body=r.body or "", source="replay",
                ))
            # params 需要重建
            for req in out:
                parsed = urllib.parse.urlsplit(req.url)
                req.params = [{"in": "query", "name": k, "value": v[0] if v else ""}
                              for k, v in urllib.parse.parse_qs(parsed.query).items()]
                if req.body:
                    try:
                        jb = json.loads(req.body)
                        if isinstance(jb, dict):
                            req.params += [{"in": "body", "name": k, "value": str(v)} for k, v in jb.items()]
                    except ValueError:
                        pass
            return out
        finally:
            s.close()

    def _load_candidates(self):
        from scanner.detectors import Candidate
        s = new_session()
        try:
            rows = s.query(Finding).filter_by(task_id=self.task_id).all()
            out = []
            for r in rows:
                out.append(Candidate(
                    category=r.category, title=r.title, severity=r.severity, url=r.url or "",
                    method=r.method or "GET", param=r.param or "", role=r.role or "",
                    evidence=json_load(r.evidence, {}), request=r.request or "", response=r.response or "",
                    dedup_key=r.dedup_key or "", vuln_id=r.vuln_id or "",
                    occurrences=json_load(r.occurrences, []),
                ))
            return out
        finally:
            s.close()

    def _filter_suppressed(self, candidates):
        s = new_session()
        try:
            task = s.get(ScanTask, self.task_id)
            host = urllib.parse.urlsplit(task.target_url).hostname
            keys = {r.dedup_key for r in s.query(Suppression).filter_by(host=host).all()}
            kept, skipped = [], 0
            for c in candidates:
                if c.dedup_key in keys:
                    skipped += 1
                    continue
                kept.append(c)
            if skipped:
                _update_task(self.task_id, message=f"跳过 {skipped} 条已标记误报")
            return kept
        finally:
            s.close()

    def _add_finding_rows(self, candidates):
        """把候选写入 findings(未复核),供断点续扫与页面展示。"""
        s = new_session()
        try:
            s.query(Finding).filter_by(task_id=self.task_id).delete()
            for c in candidates:
                vuln_ids = catalog.match_vuln_ids(c.category, c.url, c.param, c.evidence)
                s.add(Finding(
                    task_id=self.task_id, vuln_id=vuln_ids[0] if vuln_ids else None,
                    vuln_ids=json.dumps(vuln_ids, ensure_ascii=False),
                    category=c.category, title=c.title,
                    severity=c.severity, url=c.url, method=c.method, param=c.param, role=c.role,
                    status="suspected", confidence=c.confidence, dedup_key=c.dedup_key,
                    evidence=json.dumps(c.evidence, ensure_ascii=False),
                    request=c.request, response=c.response,
                    occurrences=json.dumps(c.occurrences, ensure_ascii=False),
                ))
            s.commit()
        finally:
            s.close()

    def _persist_findings(self, candidates, sessions):
        s = new_session()
        try:
            s.query(Finding).filter_by(task_id=self.task_id).delete()
            host = urllib.parse.urlsplit(self.config.target_url).hostname
            suppressed = {r.dedup_key for r in s.query(Suppression).filter_by(host=host).all()}
            for c in candidates:
                if c.dedup_key in suppressed:
                    continue
                vuln_ids = catalog.match_vuln_ids(c.category, c.url, c.param, c.evidence)
                status = "confirmed" if (c.verification or {}).get("confirmed") else "suspected"
                s.add(Finding(
                    task_id=self.task_id, vuln_id=vuln_ids[0] if vuln_ids else None,
                    vuln_ids=json.dumps(vuln_ids, ensure_ascii=False),
                    category=c.category, title=c.title,
                    severity=c.severity, url=c.url, method=c.method, param=c.param, role=c.role,
                    status=status, confidence=c.confidence, dedup_key=c.dedup_key,
                    evidence=json.dumps(c.evidence, ensure_ascii=False),
                    request=c.request, response=c.response,
                    verify_request=getattr(c, "verify_request", "") or "",
                    verify_response=getattr(c, "verify_response", "") or "",
                    verification=json.dumps(c.verification or {}, ensure_ascii=False),
                    occurrences=json.dumps(c.occurrences, ensure_ascii=False),
                ))
            s.commit()
        finally:
            s.close()

    def _persist_candidates(self, candidates):
        self._add_finding_rows(candidates)

    def _set_state(self, stages_done, extra):
        s = new_session()
        try:
            task = s.get(ScanTask, self.task_id)
            state = json_load(task.state, {})
            state["stages_done"] = sorted(stages_done)
            state.update(extra)
            task.state = json.dumps(state, ensure_ascii=False)
            s.commit()
        finally:
            s.close()


_RUNNERS: dict[int, ScanRunner] = {}
_LOCK = threading.Lock()


def get_runner(task_id, create=False):
    with _LOCK:
        runner = _RUNNERS.get(task_id)
        if runner is None and create:
            runner = ScanRunner(task_id)
            _RUNNERS[task_id] = runner
        return runner


def _update_task(task_id, **fields):
    s = new_session()
    try:
        task = s.get(ScanTask, task_id)
        if not task:
            return
        for k, v in fields.items():
            setattr(task, k, v)
        s.commit()
    finally:
        s.close()
