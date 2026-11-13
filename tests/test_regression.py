"""靶场与扫描器核心逻辑的回归测试(不依赖运行中的服务)。

    python3 -m unittest discover -s tests -v
"""
import json
import os
import sys
import unittest

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)


class TargetVulnerabilityTest(unittest.TestCase):
    """用 Flask test client 验证每个埋点确实可被触发。"""

    @classmethod
    def setUpClass(cls):
        from target.app import app
        cls.app = app
        cls.app.config["TESTING"] = True

    def client(self):
        return self.app.test_client()

    def login(self, client, username, password):
        return client.post("/api/auth/login", json={"username": username, "password": password})

    def test_login_sqli(self):
        c = self.client()
        r = c.post("/api/auth/login", json={"username": "'", "password": "x"})
        self.assertEqual(r.status_code, 500)
        self.assertIn("db_error", r.get_json()["code"])

    def test_orders_sqli(self):
        c = self.client()
        self.login(c, "alice", "Alice@123")
        r = c.get("/api/orders", query_string={"q": "')", "status": "", "sort": "id"})
        self.assertEqual(r.status_code, 500)
        r2 = c.get("/api/orders?q=&status=&sort=id%20desc")
        self.assertEqual(r2.status_code, 500)

    def test_reflected_xss(self):
        c = self.client()
        r = c.get("/help/search?keyword=%3Cscript%3Ealert(1)%3C/script%3E")
        self.assertIn(b"<script>alert(1)</script>", r.data)

    def test_stored_xss_feedback(self):
        c = self.client()
        self.login(c, "alice", "Alice@123")
        payload = "<img src=x onerror=alert(1)>"
        c.post("/api/feedback", json={"content": payload, "category": "other"})
        r = c.get("/notice")
        self.assertIn(payload.encode(), r.data)

    def test_stored_xss_profile(self):
        c = self.client()
        self.login(c, "alice", "Alice@123")
        payload = "<svg onload=alert(1)>"
        c.put("/api/profile", json={"display_name": payload})
        r = c.get("/profile/5")
        self.assertIn(payload.encode(), r.data)
        c.put("/api/profile", json={"display_name": "车主-张伟"})

    def test_ssrf_internal(self):
        c = self.client()
        self.login(c, "admin", "Admin@123")
        r = c.get("/api/integrations/fetch?url=http://127.0.0.1:5000/api/debug/config")
        self.assertEqual(r.status_code, 200)
        self.assertIn("secret_key", r.get_json()["body"])

    def test_traversal(self):
        c = self.client()
        self.login(c, "admin", "Admin@123")
        r = c.get("/api/files/download?path=../../../../../../../../etc/passwd")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"root:", r.data)

    def test_idor_order(self):
        c = self.client()
        self.login(c, "alice", "Alice@123")   # alice uid=5
        r = c.get("/api/orders/6")            # bob 的订单
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["order"]["username"], "bob")

    def test_idor_invoice_user_feedback(self):
        c = self.client()
        self.login(c, "alice", "Alice@123")
        self.assertEqual(c.get("/api/invoices/4").status_code, 200)
        self.assertEqual(c.get("/api/feedback/2").status_code, 200)
        r = c.get("/api/users/6")
        self.assertEqual(r.status_code, 200)
        self.assertIn("api_key", r.get_json()["user"])

    def test_vertical_bac(self):
        c = self.client()
        self.login(c, "alice", "Alice@123")
        for path in ("/api/admin/users", "/api/admin/api-keys", "/api/finance/settlements"):
            self.assertEqual(c.get(path).status_code, 200, path)

    def test_mass_assignment(self):
        c = self.client()
        self.login(c, "alice", "Alice@123")
        r = c.put("/api/profile", json={"role": "admin"})
        self.assertEqual(r.get_json()["user"]["role"], "admin")
        c.put("/api/profile", json={"role": "driver"})

    def test_debug_config_unauth(self):
        c = self.client()
        r = c.get("/api/debug/config")
        self.assertEqual(r.status_code, 200)
        self.assertIn("secret_key", r.get_json())

    def test_correct_controls_still_work(self):
        """非漏洞路径:未登录应 401,取消他人订单应 403。"""
        c = self.client()
        self.assertEqual(c.get("/api/orders").status_code, 401)
        self.login(c, "alice", "Alice@123")
        self.assertEqual(c.post("/api/orders/6/cancel").status_code, 403)


class ScannerLogicTest(unittest.TestCase):
    def test_catalog_has_18_items(self):
        from scanner import catalog
        items = catalog.load_catalog()["items"]
        self.assertEqual(len(items), 18)

    def test_match_vuln_ids(self):
        from scanner import catalog
        self.assertIn("IDOR-01", catalog.match_vuln_ids("idor", "http://x/api/orders/6", "id"))
        self.assertIn("TRAV-02", catalog.match_vuln_ids("traversal", "http://x/api/files/download?path=a", "path"))
        self.assertEqual(catalog.match_vuln_ids("bvac", "http://x/api/profile", "role",
                                                {"escalated_to": "admin"}), ["BAC-04"])
        self.assertEqual(catalog.match_vuln_ids("bvac", "http://x/api/profile", "role", {}), [])

    def test_metrics(self):
        from scanner import catalog
        findings = [
            {"vuln_id": "SQLI-01", "vuln_ids": ["SQLI-01"], "status": "confirmed", "category": "sqli"},
            {"vuln_id": "SQLI-01", "vuln_ids": ["SQLI-01"], "status": "confirmed", "category": "sqli"},
            {"vuln_id": None, "vuln_ids": [], "status": "confirmed", "category": "xss"},
            {"vuln_id": "BAC-01", "vuln_ids": ["BAC-01"], "status": "false_positive", "category": "bvac"},
        ]
        m = catalog.metrics(findings)
        self.assertEqual(m["detected"], 1)
        self.assertEqual(m["confirmed_count"], 3)
        self.assertEqual(m["manual_false_positive"], 1)
        self.assertEqual(m["unmatched_confirmed"], 1)
        # (1 人工误报 + 1 未匹配) / (3 确认 + 1 人工误报)
        self.assertEqual(m["false_positive_rate"], 50.0)
        self.assertEqual(m["missed"], [i["id"] for i in catalog.load_catalog()["items"] if i["id"] != "SQLI-01"])

    def test_dedupe_merges_params(self):
        from scanner.detectors import Candidate
        from scanner.engine import dedupe_candidates
        a = Candidate(category="sqli", title="t", severity="critical", url="http://x/api/orders?q=&sort=id",
                      method="GET", param="q", dedup_key="sqli|http://x/api/orders")
        a.add_occurrence("q", "'")
        b = Candidate(category="sqli", title="t", severity="critical", url="http://x/api/orders?q=&sort=id",
                      method="GET", param="sort", dedup_key="sqli|http://x/api/orders")
        b.add_occurrence("sort", "'")
        merged = dedupe_candidates([a, b])
        self.assertEqual(len(merged), 1)
        self.assertEqual({o["param"] for o in merged[0].occurrences}, {"q", "sort"})

    def test_verify_payload_rebuild(self):
        from scanner.detectors import Candidate
        from scanner.verify import _rebuild_url
        c = Candidate(category="sqli", title="t", severity="high", url="http://x/api/orders?q=&sort=id",
                      method="GET", param="q")
        url = _rebuild_url(c, "' OR 1=1 -- -")
        self.assertIn("q=%27+OR+1%3D1", url)
        self.assertIn("sort=id", url)


if __name__ == "__main__":
    unittest.main(verbosity=2)
