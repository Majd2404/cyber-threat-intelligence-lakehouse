
import json
import tempfile
import unittest
from pathlib import Path

from src.transformation.silver import (
    deduplicate,
    extract_epss,
    extract_kev,
    extract_nvd,
    normalize_cve,
    transform,
)


class SilverTransformationTests(unittest.TestCase):

    def test_normalize_cve(self):
        self.assertEqual(normalize_cve(" cve-2026-19820 "), "CVE-2026-19820")
        self.assertIsNone(normalize_cve("not-a-cve"))
        self.assertIsNone(normalize_cve(None))

    def test_extract_nvd(self):
        record = {
            "payload": {
                "cve": {
                    "id": "CVE-2026-19820",
                    "descriptions": [
                        {"lang": "en", "value": "Example vulnerability"}
                    ],
                    "metrics": {
                        "cvssMetricV40": [{
                            "cvssData": {"baseScore": 7.8},
                            "baseSeverity": "HIGH",
                        }]
                    },
                    "weaknesses": [],
                }
            }
        }

        result = extract_nvd(record)

        self.assertEqual(result["cve_id"], "CVE-2026-19820")
        self.assertEqual(result["cvss_score"], 7.8)
        self.assertEqual(result["severity"], "HIGH")

    def test_extract_kev(self):
        record = {
            "payload": {
                "cveID": "CVE-2015-5477",
                "vendorProject": "ISC",
                "product": "BIND",
                "vulnerabilityName": " Example vulnerability ",
            }
        }

        result = extract_kev(record)

        self.assertEqual(result["cve_id"], "CVE-2015-5477")
        self.assertEqual(result["vendor"], "ISC")
        self.assertEqual(result["vulnerability_name"], "Example vulnerability")

    def test_extract_epss_valid_score(self):
        record = {
            "payload": {
                "cve": "CVE-2026-75980",
                "epss": "0.25",
                "percentile": "0.90",
                "date": "2026-10-10",
            }
        }

        result = extract_epss(record)

        self.assertEqual(result["epss_score"], 0.25)
        self.assertEqual(result["epss_percentile"], 0.90)

    def test_extract_epss_rejects_out_of_range_scores(self):
        for score in ("-0.1", "1.1", "invalid"):
            with self.subTest(score=score):
                record = {
                    "payload": {
                        "cve": "CVE-2026-75980",
                        "epss": score,
                        "percentile": "0.5",
                        "date": "2026-10-10",
                    }
                }
                self.assertIsNone(extract_epss(record))

    def test_extract_epss_rejects_invalid_percentile(self):
        record = {
            "payload": {
                "cve": "CVE-2026-75980",
                "epss": "0.5",
                "percentile": "1.5",
                "date": "2026-10-10",
            }
        }

        self.assertIsNone(extract_epss(record))

    def test_deduplicate_keeps_last_record(self):
        records = [
            {"cve_id": "CVE-2026-19820", "severity": "LOW"},
            {"cve_id": "CVE-2026-19820", "severity": "HIGH"},
        ]

        result = deduplicate(records, ("cve_id",))

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["severity"], "HIGH")

    def test_transform_creates_three_silver_files(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            bronze = root / "raw"
            silver = root / "silver"
            bronze.mkdir()

            samples = {
                "nvd.jsonl": {
                    "payload": {
                        "cve": {
                            "id": "CVE-2026-19820",
                            "descriptions": [],
                            "metrics": {},
                            "weaknesses": [],
                        }
                    }
                },
                "kev.jsonl": {
                    "payload": {"cveID": "CVE-2015-5477"}
                },
                "epss.jsonl": {
                    "payload": {
                        "cve": "CVE-2026-75980",
                        "epss": "0.25",
                        "percentile": "0.90",
                        "date": "2026-10-10",
                    }
                },
            }

            for filename, record in samples.items():
                (bronze / filename).write_text(
                    json.dumps(record) + "\n",
                    encoding="utf-8",
                )

            counts = transform(bronze, silver)

            self.assertEqual(counts, {"nvd": 1, "kev": 1, "epss": 1})
            self.assertTrue((silver / "nvd.jsonl").exists())
            self.assertTrue((silver / "kev.jsonl").exists())
            self.assertTrue((silver / "epss.jsonl").exists())


if __name__ == "__main__":
    unittest.main()
