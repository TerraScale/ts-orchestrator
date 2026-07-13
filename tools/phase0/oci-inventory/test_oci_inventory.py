#!/usr/bin/env python3
import importlib.util
import json
from pathlib import Path
import unittest


MODULE_PATH = Path(__file__).with_name("oci_inventory.py")
SPEC = importlib.util.spec_from_file_location("oci_inventory", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class SanitizationTests(unittest.TestCase):
    def test_fixture_removes_identifiers_addresses_names_and_secret_fields(self):
        fixture = json.loads((Path(__file__).parent / "fixtures" / "sensitive-response.json").read_text())
        sanitized = MODULE.sanitize(fixture)
        encoded = json.dumps(sanitized, sort_keys=True)
        MODULE.assert_sanitized(sanitized)
        self.assertNotIn("ocid1.", encoded)
        self.assertNotIn("203.0.113.10", encoded)
        self.assertNotIn("customer-production", encoded)
        self.assertNotIn("do-not-emit", encoded)
        self.assertIn("sha256:", encoded)

    def test_category_state_fails_closed_on_partial_permission(self):
        result = MODULE.category_result(2, 3, 2, 1, 0)
        self.assertEqual("permission-denied", result["state"])
        self.assertEqual(2, result["minimum_observed_count"])

    def test_no_mutating_or_secret_retrieval_command_is_allowlisted(self):
        commands = "\n".join(MODULE.COMMAND_TEMPLATES).lower()
        for forbidden in (" create", " update", " delete", " terminate", " start", " stop", "secret-bundle", "pulumi"):
            self.assertNotIn(forbidden, commands)
        self.assertFalse(MODULE.OciReadOnly._allowed(("compute", "instance", "terminate", "--instance-id", "fixture")))
        self.assertFalse(MODULE.OciReadOnly._allowed(("secrets", "secret-bundle", "get", "--secret-id", "fixture")))

    def test_report_states_are_closed_vocabulary(self):
        for attempted, succeeded, denied, failed in ((0, 0, 0, 0), (1, 1, 0, 0), (1, 0, 1, 0), (1, 0, 0, 1)):
            self.assertIn(MODULE.category_result(0, attempted, succeeded, denied, failed)["state"], MODULE.ALLOWED_STATES)

    def test_discovery_failure_never_claims_oke_or_cost_evidence(self):
        import datetime as dt
        end = dt.datetime(2026, 7, 13, tzinfo=dt.timezone.utc)
        report = MODULE.discovery_failure_report(end - dt.timedelta(days=7), end, "region-subscriptions", "permission-denied")
        self.assertFalse(report["oke_absence_proven"])
        self.assertFalse(report["cost_window"]["seven_day_residual_bill_established"])
        self.assertEqual("not-queried", report["categories"]["oke-clusters"]["state"])
        MODULE.assert_sanitized(report)


if __name__ == "__main__":
    unittest.main()
