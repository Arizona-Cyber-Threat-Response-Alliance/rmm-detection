import unittest

from reporting import SUMMARY_SCHEMA_VERSION, build_summary_payload, normalize_summary
from source import NormalizedEntry


class TestReporting(unittest.TestCase):
    def test_normalize_summary_adds_defaults(self):
        result = normalize_summary({})
        self.assertEqual(result["summary_schema_version"], SUMMARY_SCHEMA_VERSION)
        self.assertIn("generated_at", result)
        self.assertEqual(result["counts"]["selected"], 0)
        self.assertEqual(result["sync_plan"]["status"], "not_applicable")
        self.assertEqual(result["prevalence_stats"]["status"], "skipped")

    def test_build_summary_payload_counts(self):
        desired = [
            NormalizedEntry(domain="example.com", tool="A", priority=True),
            NormalizedEntry(domain="-invalid.com", tool="B", priority=False),
        ]
        result = build_summary_payload(
            desired=desired,
            stats={"tools_total": 2},
            stage="report",
            action="none",
            dry_run=True,
            sync_plan={"create": 1, "update": 0, "delete": 0, "unchanged": 1},
            prevalence_stats={"status": "skipped"},
        )
        self.assertEqual(result["counts"]["selected"], 2)
        self.assertEqual(result["counts"]["safe"], 1)
        self.assertEqual(result["counts"]["unsafe"], 1)
        self.assertEqual(result["counts"]["priority_hits"], 1)


if __name__ == "__main__":
    unittest.main()
