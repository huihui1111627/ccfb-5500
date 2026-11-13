#!/usr/bin/env python3
"""基准评测:对给定任务计算检出率/漏报/误报率,并可选地把结果写回基准文件。

用法:
    python3 tools/benchmark.py --task 3
    python3 tools/benchmark.py --task 3 --json
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner import catalog
from scanner.models import Finding, init_db, json_load, new_session


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--task", type=int, required=True)
    parser.add_argument("--json", action="store_true", help="输出 JSON")
    args = parser.parse_args()

    init_db()
    s = new_session()
    rows = s.query(Finding).filter_by(task_id=args.task).all()
    findings = [{
        "id": f.id, "vuln_id": f.vuln_id, "vuln_ids": json_load(f.vuln_ids, []),
        "category": f.category, "status": f.status, "url": f.url, "param": f.param,
        "role": f.role,
    } for f in rows]
    s.close()

    m = catalog.metrics(findings)
    cat = catalog.load_catalog().get("items", [])
    result = {
        "task_id": args.task,
        "metrics": m,
        "coverage": [],
    }
    for item in cat:
        hit = any((item["id"] in (f.get("vuln_ids") or [f.get("vuln_id")]))
                  and f["status"] == "confirmed" for f in findings)
        result["coverage"].append({"id": item["id"], "name": item["name"],
                                   "category": item["category"], "detected": hit})

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return

    print(f"任务 #{args.task} 基准评测")
    print(f"  埋点总数        : {m['catalog_total']}")
    print(f"  检出            : {m['detected']}")
    print(f"  漏报            : {len(m['missed'])}  {', '.join(m['missed']) or '-'}")
    print(f"  检出率          : {m['detection_rate']}%")
    print(f"  越权检出率      : {m['authz_rate']}%  ({m['authz_detected']}/{m['authz_total']})")
    print(f"  已确认          : {m['confirmed_count']}")
    print(f"  未匹配埋点的确认: {m['unmatched_confirmed']}")
    print(f"  人工误报        : {m['manual_false_positive']}")
    print(f"  误报率          : {m['false_positive_rate']}%")
    print("\n逐项覆盖:")
    for c in result["coverage"]:
        print(f"  [{'✓' if c['detected'] else '✗'}] {c['id']:<8} {c['name']}")


if __name__ == "__main__":
    main()
