import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import qualify


class DeployRetryTests(unittest.TestCase):
    def lab(self, responses):
        lab = object.__new__(qualify.Lab)
        lab.operator = Mock(side_effect=responses)
        lab.intent = Mock(side_effect=lambda record, generation, name: Path(name))
        lab.wait = Mock(side_effect=lambda label, probe, **options: probe())
        lab.note = Mock()
        lab.capture_cluster_diagnostics = Mock()
        return lab

    def test_pre_acceptance_fence_uses_new_operation_once(self):
        lab = self.lab([
            {"operationId": "fc-one-node-loss-2", "fingerprint": "first", "status": "submitted"},
            {"status": "rejected", "error": qualify.PRE_ACCEPTANCE_FENCED,
             "authorityEpoch": 1},
            {"operationId": "fc-one-node-loss-epoch-retry-2", "fingerprint": "second",
             "status": "submitted"},
            {"status": "accepted", "authorityEpoch": 2},
        ])

        qualify.Lab.deploy(lab, {}, 2, "one-node-loss")

        self.assertEqual([call.args[2] for call in lab.intent.call_args_list],
                         ["one-node-loss", "one-node-loss-epoch-retry"])
        self.assertEqual(lab.operator.call_count, 4)
        self.assertEqual([call.kwargs["operation_id"] for call in lab.note.call_args_list
                          if call.args[0] == "terminal_receipt"], ["fc-one-node-loss-2"])

    def test_other_rejections_do_not_retry(self):
        lab = self.lab([
            {"operationId": "fc-one-node-loss-2", "fingerprint": "first", "status": "submitted"},
            {"status": "rejected", "error": "artifact is not admitted"},
        ])

        with self.assertRaisesRegex(RuntimeError, "artifact is not admitted"):
            qualify.Lab.deploy(lab, {}, 2, "one-node-loss")

        self.assertEqual(lab.intent.call_count, 1)
        self.assertEqual(lab.operator.call_count, 2)

    def test_second_fence_is_terminal(self):
        lab = self.lab([
            {"operationId": "fc-one-node-loss-2", "fingerprint": "first", "status": "submitted"},
            {"status": "rejected", "error": qualify.PRE_ACCEPTANCE_FENCED},
            {"operationId": "fc-one-node-loss-epoch-retry-2", "fingerprint": "second",
             "status": "submitted"},
            {"status": "rejected", "error": qualify.PRE_ACCEPTANCE_FENCED},
        ])

        with self.assertRaisesRegex(RuntimeError, qualify.PRE_ACCEPTANCE_FENCED):
            qualify.Lab.deploy(lab, {}, 2, "one-node-loss")

        self.assertEqual(lab.intent.call_count, 2)
        self.assertEqual(len([call for call in lab.note.call_args_list
                              if call.args[0] == "terminal_receipt"]), 2)

    def test_retry_intent_omits_epoch_for_current_lease_observation(self):
        lab = object.__new__(qualify.Lab)
        with tempfile.TemporaryDirectory() as directory:
            lab.stage = Path(directory)
            record = {"source": {}, "digest": "artifact", "manifestDigest": "manifest"}
            path = qualify.Lab.intent(lab, record, 2, "one-node-loss-epoch-retry")
            intent = json.loads(path.read_text())

        self.assertEqual(intent["operationId"], "fc-one-node-loss-epoch-retry-2")
        self.assertNotIn("authorityEpoch", intent)


class HostStatusDiagnosticTests(unittest.TestCase):
    def test_host_status_is_curated_and_session_current_is_derived(self):
        captured_at = datetime(2026, 9, 24, 12, 0, tzinfo=timezone.utc)
        expiry = (captured_at + timedelta(seconds=20)).isoformat()
        statuses = [{
            "registration": {"node": "host-a", "environment": "test", "roles": ["terrabase"],
                             "generation": 1, "capacity": {"cpu": 2, "memory_bytes": 256, "disk_bytes": 512},
                             "public_key": "secret-public-key"},
            "session_expires_at": expiry, "verified": False,
            "reports": [{"role": "terrabase", "generation": 1, "state": "running",
                         "digest": "a" * 64, "epoch": 2, "observed_at": expiry,
                         "session_id": "secret-session-id", "error": "free text"}],
        }]

        curated = qualify.curated_host_statuses(statuses, captured_at)

        self.assertTrue(curated[0]["session_current"])
        self.assertEqual(curated[0]["reports"][0]["digest_prefix"], "a" * 12)
        self.assertNotIn("secret", json.dumps(curated))
        statuses[0]["session_expires_at"] = (captured_at - timedelta(seconds=1)).isoformat()
        self.assertFalse(qualify.curated_host_statuses(statuses, captured_at)[0]["session_current"])

    def test_operator_failure_stays_nonfatal_and_does_not_dump_output(self):
        lab = object.__new__(qualify.Lab)
        with tempfile.TemporaryDirectory() as directory:
            lab.logs = Path(directory)
            lab.binary = Path(directory) / "terrascale-orchestrator"
            lab.operator_config = Path(directory) / "operator.json"
            lab.host_status_diagnostics_captured = set()
            lab.note = Mock()
            with patch.object(qualify, "run", return_value=SimpleNamespace(
                    returncode=1, stdout="secret-output", stderr="secret-error")):
                qualify.Lab.capture_host_status(lab, "early-pending")
            snapshot = json.loads((lab.logs / "host-status-early-pending.json").read_text())

        self.assertEqual(snapshot["status"], "operator_failed")
        self.assertEqual(snapshot["exit_code"], 1)
        self.assertNotIn("secret", json.dumps(snapshot))


if __name__ == "__main__":
    unittest.main()
