import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from src.ingestion.clients import fetch_nvd, fetch_epss
from src.ingestion.run import main


class IngestionTests(unittest.TestCase):
    def test_sample_pipeline_lands_three_sources(self):
        with tempfile.TemporaryDirectory() as directory:
            counts = main(["--mode", "sample", "--output", directory])
            self.assertEqual(counts, {"nvd": 2, "kev": 1, "epss": 2})
            for name, count in counts.items():
                entries = (Path(directory) / f"{name}.jsonl").read_text().splitlines()
                self.assertEqual(len(entries), count)
                self.assertEqual(json.loads(entries[0])["source"], name)

    def test_nvd_window_validation(self):
        with self.assertRaises(ValueError):
            fetch_nvd("2026-01-01", "2026-08-01")

    @patch("src.ingestion.clients.fetch_json")
    def test_epss_deduplicates_ids(self, mock_fetch):
        mock_fetch.return_value = {"data": [{"cve": "CVE-2021-44228"}]}
        output = fetch_epss(["CVE-2021-44228", "CVE-2021-44228"])
        self.assertEqual(len(output), 1)
        self.assertEqual(mock_fetch.call_count, 1)

    @patch("src.ingestion.clients.time.sleep")
    @patch("src.ingestion.clients.fetch_json")
    def test_nvd_pagination(self, mock_fetch, _sleep):
        mock_fetch.side_effect = [
            {"totalResults": 3, "vulnerabilities": [{"cve": {"id": "A"}}, {"cve": {"id": "B"}}]},
            {"totalResults": 3, "vulnerabilities": [{"cve": {"id": "C"}}]},
        ]
        output = fetch_nvd("2026-09-01", "2026-09-03", page_size=2)
        self.assertEqual(len(output), 3)
        self.assertEqual(mock_fetch.call_args_list[1].args[1]["startIndex"], 2)


if __name__ == "__main__":
    unittest.main()
