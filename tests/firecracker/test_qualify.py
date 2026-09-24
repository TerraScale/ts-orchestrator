import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

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


if __name__ == "__main__":
    unittest.main()
