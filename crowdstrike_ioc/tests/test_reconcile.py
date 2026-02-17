import unittest
from unittest.mock import patch

from crowdstrike_api import IndicatorPayload
from reconcile import sync
from source import NormalizedEntry


class TestReconcile(unittest.TestCase):
    def test_indicator_payload_to_api(self):
        payload = IndicatorPayload(
            type="domain",
            value="example.com",
            action="none",
            severity="informational",
            source="autormmdetect_lolrmm",
            description="desc",
            tags=["a"],
            platforms=["windows"],
            id="abc",
        )
        out = payload.to_api()
        self.assertEqual(out["value"], "example.com")
        self.assertEqual(out["id"], "abc")
        self.assertEqual(out["platforms"], ["windows"])

    @patch("reconcile.iter_managed_iocs")
    def test_sync_dry_run_reports_update(self, mock_iter):
        mock_iter.return_value = [
            {
                "id": "ioc1",
                "type": "domain",
                "value": "example.com",
                "action": "detect",
                "severity": "informational",
                "source": "autormmdetect_lolrmm",
                "description": "old",
                "applied_globally": True,
                "tags": ["autormmdetect"],
                "platforms": ["windows"],
            }
        ]
        desired = [
            NormalizedEntry(
                domain="example.com",
                tool="ScreenConnect",
                tools=["ScreenConnect"],
                description="new",
                priority=True,
            )
        ]

        result = sync(
            client=object(),
            desired=desired,
            dry_run=True,
            retrodetects=False,
            prune=False,
            action="none",
            platforms=["windows", "mac", "linux"],
        )

        self.assertEqual(result["create"], 0)
        self.assertEqual(result["update"], 1)
        self.assertEqual(result["delete"], 0)


if __name__ == "__main__":
    unittest.main()
