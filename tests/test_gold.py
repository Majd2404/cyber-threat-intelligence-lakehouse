
"""Tests for the Gold vulnerability intelligence transformation."""

import json
import tempfile
import unittest
from pathlib import Path

from src.transformation.gold import build_gold, parse_score


class TestGoldTransformation(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.input_dir = self.root / "silver"
        self.output_dir = self.root / "gold"
        self.input_dir.mkdir()

    def tearDown(self):
        self.temp_dir.cleanup()

    def write_jsonl(self, filename, records):
        path = self.input_dir / filename
        with path.open("w", encoding="utf-8") as file:
            for record in records:
                file.write(json.dumps(record) + "\n")

    def read_gold(self):
        path = self.output_dir / "vulnerability_intelligence.jsonl"
        with path.open(encoding="utf-8") as file:
            return [json.loads(line) for line in file if line.strip()]

    def test_joins_all_three_sources_by_cve_id(self):
        self.write_jsonl("nvd.jsonl", [{
            "cve_id": "CVE-2025-1001",
            "description": "Test vulnerability",
            "published_at": "2025-01-01",
            "cvss_score": 9.8,
            "severity": "CRITICAL",
        }])
        self.write_jsonl("kev.jsonl", [{
            "cve_id": "CVE-2025-1001",
            "vendor": "Example",
            "product": "Example Product",
            "date_added": "2025-01-02",
            "due_date": "2025-02-01",
            "known_ransomware_campaign_use": "Unknown",
        }])
        self.write_jsonl("epss.jsonl", [{
            "cve_id": "CVE-2025-1001",
            "epss_score": 0.75,
            "epss_percentile": 0.95,
            "score_date": "2025-01-03",
        }])

        counts = build_gold(self.input_dir, self.output_dir)
        records = self.read_gold()

        self.assertEqual(len(records), 1)
        record = records[0]

        self.assertEqual(record["cve_id"], "CVE-2025-1001")
        self.assertEqual(record["description"], "Test vulnerability")
        self.assertEqual(record["vendor"], "Example")
        self.assertEqual(record["cvss_score"], 9.8)
        self.assertEqual(record["epss_score"], 0.75)
        self.assertTrue(record["has_nvd_data"])
        self.assertTrue(record["has_kev_data"])
        self.assertTrue(record["has_epss_data"])
        self.assertTrue(record["is_known_exploited"])
        self.assertEqual(counts["gold_records"], 1)

    def test_keeps_records_missing_from_other_sources(self):
        self.write_jsonl("nvd.jsonl", [{
            "cve_id": "CVE-2025-1002",
            "cvss_score": 8.0,
            "severity": "HIGH",
        }])
        self.write_jsonl("kev.jsonl", [{
            "cve_id": "CVE-2025-1003",
            "vendor": "Example",
        }])
        self.write_jsonl("epss.jsonl", [{
            "cve_id": "CVE-2025-1004",
            "epss_score": 0.8,
            "epss_percentile": 0.9,
            "score_date": "2025-01-03",
        }])

        build_gold(self.input_dir, self.output_dir)
        records = {r["cve_id"]: r for r in self.read_gold()}

        self.assertEqual(len(records), 3)

        self.assertTrue(records["CVE-2025-1002"]["has_nvd_data"])
        self.assertFalse(records["CVE-2025-1002"]["has_kev_data"])

        self.assertFalse(records["CVE-2025-1003"]["has_nvd_data"])
        self.assertTrue(records["CVE-2025-1003"]["has_kev_data"])

        self.assertFalse(records["CVE-2025-1004"]["has_nvd_data"])
        self.assertTrue(records["CVE-2025-1004"]["has_epss_data"])

    def test_selects_latest_epss_observation(self):
        self.write_jsonl("nvd.jsonl", [])
        self.write_jsonl("kev.jsonl", [])
        self.write_jsonl("epss.jsonl", [
            {
                "cve_id": "CVE-2025-1005",
                "epss_score": 0.2,
                "epss_percentile": 0.4,
                "score_date": "2025-01-01",
            },
            {
                "cve_id": "CVE-2025-1005",
                "epss_score": 0.8,
                "epss_percentile": 0.95,
                "score_date": "2025-01-10",
            },
        ])

        build_gold(self.input_dir, self.output_dir)
        records = self.read_gold()

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["epss_score"], 0.8)
        self.assertEqual(records[0]["epss_score_date"], "2025-01-10")

    def test_handles_invalid_scores(self):
        self.assertIsNone(parse_score(None))
        self.assertIsNone(parse_score("invalid"))
        self.assertEqual(parse_score("0.75"), 0.75)

        self.write_jsonl("nvd.jsonl", [{
            "cve_id": "CVE-2025-1006",
            "cvss_score": "invalid",
        }])
        self.write_jsonl("kev.jsonl", [])
        self.write_jsonl("epss.jsonl", [{
            "cve_id": "CVE-2025-1006",
            "epss_score": "invalid",
            "epss_percentile": None,
            "score_date": "2025-01-01",
        }])

        build_gold(self.input_dir, self.output_dir)
        record = self.read_gold()[0]

        self.assertIsNone(record["cvss_score"])
        self.assertIsNone(record["epss_score"])
        self.assertIsNone(record["epss_percentile"])
        self.assertEqual(record["priority"], "LOW")

    def test_applies_current_priority_rules(self):
        self.write_jsonl("nvd.jsonl", [
            {"cve_id": "CVE-2025-1007", "cvss_score": 9.5},
            {"cve_id": "CVE-2025-1008", "cvss_score": 7.5},
            {"cve_id": "CVE-2025-1009", "cvss_score": 4.0},
        ])
        self.write_jsonl("kev.jsonl", [])
        self.write_jsonl("epss.jsonl", [
            {
                "cve_id": "CVE-2025-1008",
                "epss_score": 0.2,
                "epss_percentile": 0.5,
                "score_date": "2025-01-01",
            },
            {
                "cve_id": "CVE-2025-1009",
                "epss_score": 0.6,
                "epss_percentile": 0.9,
                "score_date": "2025-01-01",
            },
        ])

        build_gold(self.input_dir, self.output_dir)
        records = {r["cve_id"]: r["priority"] for r in self.read_gold()}

        self.assertEqual(records["CVE-2025-1007"], "HIGH")
        self.assertEqual(records["CVE-2025-1008"], "MEDIUM")
        self.assertEqual(records["CVE-2025-1009"], "HIGH")


if __name__ == "__main__":
    unittest.main()
