"""Veri hattı birim testleri (ağa çıkmaz): python -m unittest pipeline/test_fetch_data.py"""
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import sys
sys.path.insert(0, str(Path(__file__).parent))
import fetch_data as fd  # noqa: E402

KEV = {"catalogVersion": "2026.10.30", "vulnerabilities": [
    {"cveID": f"CVE-2020-{1000 + i}", "dateAdded": "2026-10-20", "dueDate": "2026-11-10", "knownRansomwareCampaignUse": "Known" if i % 2 else "Unknown",
     "vendorProject": "Acme", "product": f"Router{i}", "vulnerabilityName": "x"} for i in range(120)]}


def nvd_vuln(cid, pub, score=9.8, sev="CRITICAL", cpe="cpe:2.3:a:acme_corp:web_server:1.0:*:*:*:*:*:*:*"):
    return {"cve": {"id": cid, "published": f"{pub}T10:00:00.000", "descriptions": [{"lang": "en", "value": "Remote code execution in Web Server " * 8}],
                    "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {"baseScore": score, "baseSeverity": sev}}]},
                    "weaknesses": [{"description": [{"value": "CWE-78"}]}],
                    "configurations": [{"nodes": [{"cpeMatch": [{"criteria": cpe}]}]}]}}


def fake_get_json(url, headers=None, tries=4):
    if "known_exploited" in url:
        return KEV
    if "hasKev" in url:
        return {"totalResults": 1, "vulnerabilities": [nvd_vuln("CVE-2020-1001", "2020-05-01", 7.5, "HIGH")]}
    if "resultsPerPage=1&" in url or url.endswith("resultsPerPage=1"):
        return {"totalResults": 812, "vulnerabilities": [{}]}
    return {"totalResults": 2, "vulnerabilities": [nvd_vuln("CVE-2026-0001", "2026-10-30"), nvd_vuln("CVE-2026-0002", "2026-10-29", 5.3, "MEDIUM")]}


class Pipeline(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        mock.patch.object(fd.time, "sleep", lambda s: None).start()
        self.addCleanup(mock.patch.stopall)

    def test_normal_run(self):
        with mock.patch.object(fd, "get_json", side_effect=fake_get_json):
            self.assertEqual(fd.run(self.tmp, 10), 0)
        cves = json.loads((self.tmp / "cves.json").read_text())
        ids = {i["id"]: i for i in cves["items"]}
        self.assertIn("CVE-2026-0001", ids)
        self.assertEqual(ids["CVE-2020-1001"]["kev"]["rw"], True)        # KEV bayrağı + fidye
        self.assertIsNone(ids["CVE-2026-0001"]["kev"])
        self.assertEqual(ids["CVE-2026-0001"]["vp"], ["acme corp/web server"])
        self.assertTrue(ids["CVE-2026-0001"]["desc"].endswith("…"))       # 200 karakterle kısaltma
        trend = json.loads((self.tmp / "trend.json").read_text())
        self.assertEqual(len(trend["weeks"]), 12)
        self.assertEqual(trend["weeks"][0]["total"], 812)
        self.assertEqual(len(trend["history"]), 1)                       # snapshot birikti
        meta = json.loads((self.tmp / "meta.json").read_text())
        self.assertTrue(meta["sources"]["nvd"]["ok"] and meta["sources"]["kev"]["ok"])

    def test_nvd_down_keeps_previous_data(self):
        with mock.patch.object(fd, "get_json", side_effect=fake_get_json):
            fd.run(self.tmp, 10)
        def nvd_down(url, headers=None, tries=4):
            if "known_exploited" in url:
                return KEV
            raise RuntimeError("İstek başarısız: HTTPError: 503")
        with mock.patch.object(fd, "get_json", side_effect=nvd_down):
            self.assertEqual(fd.run(self.tmp, 10), 1)                    # kısmi başarı
        meta = json.loads((self.tmp / "meta.json").read_text())
        self.assertFalse(meta["sources"]["nvd"]["ok"])
        self.assertIn("503", meta["sources"]["nvd"]["error"])
        self.assertIn("nvd", meta["lastSuccess"])                         # son başarılı çekim korunur
        cves = json.loads((self.tmp / "cves.json").read_text())
        self.assertGreaterEqual(len(cves["items"]), 3)                    # önceki kayıtlar korunur
        trend = json.loads((self.tmp / "trend.json").read_text())
        self.assertEqual(len(trend["weeks"]), 12)

    def test_everything_down_without_previous_fails(self):
        with mock.patch.object(fd, "get_json", side_effect=RuntimeError("ağ yok")):
            self.assertEqual(fd.run(self.tmp, 10), 2)

    def test_api_key_never_written(self):
        with mock.patch.object(fd, "API_KEY", "GIZLI-ANAHTAR"), mock.patch.object(fd, "get_json", side_effect=fake_get_json):
            fd.run(self.tmp, 10)
        for p in self.tmp.rglob("*.json"):
            self.assertNotIn("GIZLI-ANAHTAR", p.read_text())


if __name__ == "__main__":
    unittest.main()
