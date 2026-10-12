import tempfile
import unittest
from pathlib import Path

from storage import (
	get_assessment,
	get_triage_status,
	list_assessments,
	save_assessment,
	update_triage,
)


def assessment(target: str = "https://example.test/") -> dict:
	return {
		"target": target,
		"final_url": target,
		"checked_at": "2026-10-12T12:00:00+00:00",
		"status_code": 200,
		"elapsed_ms": 80,
		"redirects": 0,
		"score": 76,
		"findings": [{
			"title": "HSTS header is missing",
			"severity": "Medium",
			"category": "Transport security",
			"evidence": "No HSTS header was present.",
			"remediation": "Add Strict-Transport-Security.",
		}],
	}


class StorageTests(unittest.TestCase):
	def setUp(self) -> None:
		self.temp_dir = tempfile.TemporaryDirectory()
		self.db_path = Path(self.temp_dir.name) / "test.db"

	def tearDown(self) -> None:
		self.temp_dir.cleanup()

	def test_assessment_round_trips_with_open_triage(self) -> None:
		assessment_id = save_assessment(assessment(), self.db_path)
		loaded = get_assessment(assessment_id, self.db_path)
		history = list_assessments(db_path=self.db_path)

		self.assertEqual(loaded["score"], 76)
		self.assertEqual(loaded["findings"][0]["triage_status"], "Open")
		self.assertEqual(history[0]["finding_count"], 1)
		self.assertEqual(history[0]["open_count"], 1)

	def test_triage_status_persists_across_repeat_assessments(self) -> None:
		first_id = save_assessment(assessment(), self.db_path)
		first_finding = get_assessment(first_id, self.db_path)["findings"][0]
		update_triage(first_finding["fingerprint"], "Acknowledged", self.db_path)

		second_id = save_assessment(assessment("https://example.test/account"), self.db_path)
		second_finding = get_assessment(second_id, self.db_path)["findings"][0]

		self.assertEqual(second_finding["triage_status"], "Acknowledged")
		self.assertEqual(get_triage_status(first_finding["fingerprint"], self.db_path), "Acknowledged")

	def test_invalid_triage_status_is_rejected(self) -> None:
		with self.assertRaises(ValueError):
			update_triage("fingerprint", "Deferred", self.db_path)


if __name__ == "__main__":
	unittest.main()