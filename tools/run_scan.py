#!/usr/bin/env python3
"""命令行扫描入口 —— 不依赖 Web 界面,直接跑一次完整扫描并输出报告。

用法:
    python3 tools/run_scan.py --target http://127.0.0.1:5000 --rate 8
    python3 tools/run_scan.py --target http://127.0.0.1:5000 --no-spa --check sqli,xss,idor,bvac
"""
import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.config import DEFAULT_ROLES
from scanner.engine import ScanRunner
from scanner.models import Finding, ScanTask, init_db, new_session
from scanner.report import collect, generate_reports


def main():
    parser = argparse.ArgumentParser(description="ChargeOps 本地靶场安全扫描器")
    parser.add_argument("--target", required=True, help="目标地址,如 http://127.0.0.1:5000")
    parser.add_argument("--name", default="CLI 扫描")
    parser.add_argument("--rate", type=float, default=8.0, help="全局限速(请求/秒)")
    parser.add_argument("--max-pages", type=int, default=120)
    parser.add_argument("--no-spa", action="store_true", help="跳过 Playwright SPA 抓取")
    parser.add_argument("--check", default="", help="逗号分隔的检测类型:sqli,xss,ssrf,traversal,idor,bvac,info")
    parser.add_argument("--wait", action="store_true", default=True)
    args = parser.parse_args()

    init_db()
    check_types = [c.strip() for c in args.check.split(",") if c.strip()] or [
        "sqli", "xss", "ssrf", "traversal", "idor", "bvac", "info"]
    s = new_session()
    task = ScanTask(
        name=args.name, target_url=args.target.rstrip("/"),
        auth_config=json.dumps({"roles": DEFAULT_ROLES}, ensure_ascii=False),
        scope_config=json.dumps({
            "rate_limit": args.rate, "max_pages": args.max_pages,
            "crawl_spa": not args.no_spa, "check_types": check_types,
        }, ensure_ascii=False),
    )
    s.add(task)
    s.commit()
    task_id = task.id
    s.close()

    runner = ScanRunner(task_id)
    runner.start()
    print(f"[+] 任务 #{task_id} 已启动,限速 {args.rate} req/s,目标 {args.target}")
    while runner.thread and runner.thread.is_alive():
        time.sleep(2)
        s = new_session()
        t = s.get(ScanTask, task_id)
        print(f"    {t.status:<10} {t.progress:>3}%  {t.stage:<8} {t.message[:60]}", flush=True)
        s.close()

    s = new_session()
    t = s.get(ScanTask, task_id)
    final_status = t.status
    s.close()

    generate_reports(task_id)
    data = collect(task_id)
    print("\n" + "=" * 72)
    print(f"任务状态: {final_status}")
    print(f"资产: {data['asset_count']} 条(接口 {data['api_count']} 条)")
    m = data["metrics"]
    print(f"埋点检出率: {m['detection_rate']}%  ({m['detected']}/{m['catalog_total']})")
    print(f"越权检出率: {m['authz_rate']}%  ({m['authz_detected']}/{m['authz_total']})")
    print(f"已确认漏洞: {m['confirmed_count']}    误报率: {m['false_positive_rate']}%")
    if m["missed"]:
        print(f"漏报: {', '.join(m['missed'])}")
    print("-" * 72)
    for f in data["findings"]:
        if f["status"] != "confirmed":
            continue
        occ = f" [合并 {len(f['occurrences'])} 个参数]" if len(f["occurrences"]) > 1 else ""
        print(f"  [{f['severity']:<8}] {f['vuln_id'] or '-':<8} {f['title']}{occ}")
    print("=" * 72)
    print(f"报告: scanner/reports/scan_{task_id}.html")
    print(f"      scanner/reports/scan_{task_id}.json")


if __name__ == "__main__":
    main()
