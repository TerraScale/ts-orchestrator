import json
import hashlib
import ipaddress
import os
import stat
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, call, patch

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

    def test_operator_hosts_event_omits_raw_session_id(self):
        lab = object.__new__(qualify.Lab)
        lab.binary = Path("/tmp/unused-fc-operator")
        lab.operator_config = Path("/tmp/unused-fc-config")
        lab.note = Mock()
        statuses = [{"registration": {"node": "host-a"},
                     "session_expires_at": (datetime.now(timezone.utc) + timedelta(seconds=25)).isoformat(),
                     "reports": [{"role": "terrabase", "session_id": "secret-session-id"}]}]

        with patch.object(qualify, "run", return_value=SimpleNamespace(
                returncode=0, stdout=json.dumps(statuses), stderr="")):
            self.assertEqual(lab.operator("hosts"), statuses)

        logged = json.dumps(lab.note.call_args.kwargs)
        self.assertNotIn("secret-session-id", logged)
        self.assertIn("session_id_hash", logged)

    def test_failed_operator_probe_records_stage_before_raising_without_host_secrets(self):
        lab = object.__new__(qualify.Lab)
        lab.binary = Path("/tmp/unused-fc-operator")
        lab.operator_config = Path("/tmp/unused-fc-config")
        lab.note = Mock()
        with patch.object(qualify, "run", return_value=SimpleNamespace(
                returncode=1, stdout='{"session_id":"secret-session-id"}',
                stderr="context deadline exceeded")) as command:
            with self.assertRaisesRegex(RuntimeError, "context deadline exceeded"):
                lab.host_session("v1", timeout=4.5,
                                 stage="same-process-host-session-renewal")

        self.assertEqual(command.call_args.kwargs, {"timeout": 4.5, "allow_failure": True})
        event = lab.note.call_args
        self.assertEqual(event.args, ("operator",))
        self.assertEqual(event.kwargs["stage"], "same-process-host-session-renewal")
        self.assertEqual(event.kwargs["exit_code"], 1)
        self.assertEqual(event.kwargs["failure"], "exit_nonzero")
        self.assertEqual(event.kwargs["stderr"], "context deadline exceeded")
        self.assertGreaterEqual(event.kwargs["elapsed_seconds"], 0)
        self.assertNotIn("secret-session-id", json.dumps(event.kwargs))

    def test_operator_subprocess_timeout_records_bounded_stderr(self):
        lab = object.__new__(qualify.Lab)
        lab.binary = Path("/tmp/unused-fc-operator")
        lab.operator_config = Path("/tmp/unused-fc-config")
        lab.note = Mock()
        timeout = subprocess.TimeoutExpired(["operator", "hosts"], 5,
                                            stderr=b"context deadline exceeded")
        with patch.object(qualify, "run", side_effect=timeout):
            with self.assertRaises(subprocess.TimeoutExpired):
                lab.operator("hosts", timeout=5, stage="same-process-host-session-renewal")

        event = lab.note.call_args
        self.assertEqual(event.kwargs["failure"], "subprocess_timeout")
        self.assertEqual(event.kwargs["timeout_seconds"], 5)
        self.assertEqual(event.kwargs["stderr"], "context deadline exceeded")


class FaultAndLeaseTests(unittest.TestCase):
    def test_connected_controller_parses_four_column_ss_output(self):
        lab = object.__new__(qualify.Lab)
        lab.addresses = {"host": "198.19.7.14", "c1": "198.19.7.11",
                         "c2": "198.19.7.12", "c3": "198.19.7.13"}
        lab.ssh = Mock(return_value=SimpleNamespace(stdout=(
            "0 0 198.19.7.14:48232 198.19.7.11:4222\n"
            "0 0 198.19.7.14:22 198.19.7.1:49300\n")))

        self.assertEqual(lab.connected_controller(), "c1")
        lab.ssh.assert_called_once_with("host", "ss -Hnt state established", timeout=10)

    def test_host_unit_enforces_native_supervisor_boundary(self):
        unit = qualify.Lab.guest_unit("host", "host")
        service = unit.split("[Service]\n", 1)[1].split("\n[Install]", 1)[0]
        directives = dict(line.split("=", 1) for line in service.splitlines() if "=" in line)
        prestarts = [line.split("=", 1)[1] for line in service.splitlines()
                     if line.startswith("ExecStartPre=")]
        clock_gate = (f"/bin/sh -c 'while ! test -f {qualify.CLOCK_READY}; "
                      "do sleep 0.1; done'")

        self.assertEqual(directives["User"], "root")
        self.assertEqual(directives["Group"], "root")
        self.assertEqual(directives["NoNewPrivileges"], "yes")
        self.assertEqual(directives["Delegate"], "yes")
        self.assertEqual(directives["DelegateSubgroup"], "supervisor")
        capabilities = directives["CapabilityBoundingSet"].split()
        self.assertEqual(capabilities,
                         ["CAP_CHOWN", "CAP_KILL", "CAP_SETUID", "CAP_SETGID", "CAP_SETPCAP"])
        capability_numbers = {"CAP_CHOWN": 0, "CAP_KILL": 5, "CAP_SETGID": 6,
                              "CAP_SETUID": 7, "CAP_SETPCAP": 8}
        self.assertEqual(sum(1 << capability_numbers[name] for name in capabilities), 0x1e1)
        self.assertEqual(directives["AmbientCapabilities"], "")
        self.assertEqual(directives["TimeoutStartSec"], "180")
        self.assertEqual(prestarts,
                         ["/usr/bin/install -d -o 2000 -g 2000 -m 0700 /run/ts-orch-workload",
                          clock_gate])
        controller_unit = qualify.Lab.guest_unit("c1", "run")
        self.assertNotIn("CapabilityBoundingSet=", controller_unit)
        self.assertNotIn("DelegateSubgroup=", controller_unit)
        self.assertIn("TimeoutStartSec=180\n", controller_unit)
        self.assertEqual([line.split("=", 1)[1] for line in controller_unit.splitlines()
                          if line.startswith("ExecStartPre=")], [clock_gate])

    def test_read_only_host_status_requires_current_bound_running_report(self):
        lab = object.__new__(qualify.Lab)
        expiry = (datetime.now(timezone.utc) + timedelta(seconds=25)).isoformat()
        lab.operator = Mock(return_value=[{"verified": False, "session_expires_at": expiry,
                                           "reports": [{"role": qualify.ROLE, "state": "running",
                                                        "generation": 2, "session_id": "opaque-id",
                                                        "epoch": 4}]}])

        session = lab.host_session("v2")

        self.assertEqual(session["session_id"], "opaque-id")
        self.assertFalse(session["reader_verified"])
        lab.operator.return_value[0]["reports"][0]["session_id"] = ""
        with self.assertRaisesRegex(RuntimeError, "bound to a session"):
            lab.host_session("v2")

    def test_blackhole_is_scoped_and_cleanup_deletes_only_owned_table(self):
        lab = object.__new__(qualify.Lab)
        lab.addresses = {"host": "198.19.7.14", "c1": "198.19.7.11"}
        lab.created_nft_tables = []
        lab.created_links = []
        lab.mounted = []
        lab.vms = {}
        lab.images = Path("/tmp/unused-fc-images")
        lab.secrets = Path("/tmp/unused-fc-secrets")
        lab.stage = Path("/tmp/unused-fc-stage")
        lab.sudo = Mock(return_value=SimpleNamespace(returncode=0, stderr=""))
        lab.note = Mock()

        with patch.object(qualify.secrets, "token_hex", return_value="abcde12345"), \
                patch.object(qualify.shutil, "rmtree"):
            table = lab.blackhole_host_controller("c1")
            errors = lab.cleanup()

        self.assertEqual(errors, [])
        self.assertEqual(table, "tsfcabcde12345")
        self.assertEqual(lab.created_nft_tables, [])
        calls = [call.args for call in lab.sudo.call_args_list]
        self.assertEqual(calls[0], ("nft", "add", "table", "bridge", table))
        self.assertIn(("nft", "delete", "table", "bridge", table), calls)
        self.assertEqual(len([call for call in calls if call[:3] == ("nft", "add", "rule")]), 2)
        self.assertTrue(all("198.19.7.14" in call and "198.19.7.11" in call
                            for call in calls if call[:3] == ("nft", "add", "rule")))

    def test_partial_blackhole_creation_keeps_table_for_exact_cleanup(self):
        lab = object.__new__(qualify.Lab)
        lab.addresses = {"host": "198.19.7.14", "c1": "198.19.7.11"}
        lab.created_nft_tables = []
        lab.sudo = Mock(side_effect=[SimpleNamespace(returncode=0), RuntimeError("rule failed")])

        with patch.object(qualify.secrets, "token_hex", return_value="abcde12345"):
            with self.assertRaisesRegex(RuntimeError, "rule failed"):
                lab.blackhole_host_controller("c1")

        self.assertEqual(lab.created_nft_tables, ["tsfcabcde12345"])

    def test_verified_lease_event_parser_reads_default_slog_and_ignores_neighbors(self):
        lab = object.__new__(qualify.Lab)
        at = datetime(2026, 9, 24, 12, 0, 1, tzinfo=timezone.utc)
        expiry = (at + timedelta(seconds=30)).isoformat().replace("+00:00", "Z")
        session_hash = hashlib.sha256(b"opaque-id").hexdigest()[:32]
        renewal = (f"2026/09/24 12:00:01 INFO host session accepted phase=renew "
                   f"session_id_hash={session_hash} epoch=2 expires_at={expiry}")

        def journal_entry(observed_at, message):
            return {"__REALTIME_TIMESTAMP": str(int(observed_at.timestamp() * 1_000_000)),
                    "MESSAGE": message}

        entries = [
            journal_entry(at, renewal),
            journal_entry(at, renewal.replace("INFO host session accepted", "WARN host session accepted")),
            journal_entry(at, renewal.replace("host session accepted", "host session exchange recovered")),
            journal_entry(at, renewal.replace("2026/09/24 12:00:01", "2026/02/31 12:00:01")),
            journal_entry(at, renewal.replace(f"session_id_hash={session_hash}", "session_id_hash=not-a-digest")),
            journal_entry(at, renewal.replace("epoch=2", "epoch=2 epoch=3")),
            journal_entry(at, renewal.replace(f"session_id_hash={session_hash} ", "")),
            journal_entry(at, (f'time=2026-09-24T12:00:01Z level=INFO msg="host session accepted" '
                               f'phase=renew session_id_hash={session_hash} epoch=2 expires_at={expiry}')),
            journal_entry(at - timedelta(seconds=2), renewal),
        ]
        lab.ssh = Mock(return_value=SimpleNamespace(
            stdout="\n".join(json.dumps(entry) for entry in entries) + "\n"))

        events = lab.verified_lease_events(at - timedelta(seconds=1))

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["expires_at"], at + timedelta(seconds=30))
        self.assertEqual(events[0]["session_id_hash"], session_hash)
        self.assertEqual(events[0]["phase"], "renew")
        self.assertNotIn("opaque-id", json.dumps(entries))

    def test_fence_event_binds_latest_signed_lease_before_expiry(self):
        lab = object.__new__(qualify.Lab)
        lab.note = Mock()
        expiry = datetime(2026, 9, 24, 12, 0, 30, tzinfo=timezone.utc)
        expiry_text = expiry.isoformat().replace("+00:00", "Z")
        since = expiry - timedelta(seconds=20)
        session_hash = hashlib.sha256(b"opaque-id").hexdigest()[:32]
        failed = {"__REALTIME_TIMESTAMP": str(int((expiry - timedelta(seconds=15)).timestamp() * 1_000_000)),
                  "MESSAGE": "2026/09/24 12:00:15 WARN host session exchange deferred "
                             "stage=renew cause_class=unavailable endpoint=host.lab.fc remaining_seconds=15"}
        fence_at = expiry - timedelta(seconds=4.5)
        fenced = {"__REALTIME_TIMESTAMP": str(int(fence_at.timestamp() * 1_000_000)),
                  "MESSAGE": (f"2026/09/24 12:00:25 INFO host session fenced "
                              f"session_id_hash={session_hash} epoch=3 expires_at={expiry_text} "
                              "cause_class=reserve_exhausted")}
        wrong_hash = dict(fenced, MESSAGE=fenced["MESSAGE"].replace(
            f"session_id_hash={session_hash}", "session_id_hash=" + "0" * 32))
        wrong_epoch = dict(fenced, MESSAGE=fenced["MESSAGE"].replace("epoch=3", "epoch=4"))
        legacy_format = dict(fenced, MESSAGE=(f'time=2026-09-24T12:00:25Z level=INFO '
                                              f'msg="host session fenced" session_id_hash={session_hash} '
                                              f'epoch=3 expires_at={expiry_text} '
                                              'cause_class=reserve_exhausted'))
        lab.ssh = Mock(return_value=SimpleNamespace(returncode=0, stdout=(
            "\n".join(json.dumps(entry) for entry in
                      (failed, wrong_hash, wrong_epoch, legacy_format, fenced)) + "\n")))

        lab.host_renewal_failure_evidence(since, session_hash, 3, expiry)

        self.assertEqual(lab.note.call_args.kwargs["fence_cause_class"], "reserve_exhausted")
        self.assertEqual(lab.note.call_args.kwargs["actual_fence_started_at"],
                         (expiry - timedelta(seconds=4.5)).isoformat())
        for entry, expected_epoch, expected_expiry in (
                (wrong_hash, 3, expiry), (wrong_epoch, 3, expiry),
                (fenced, 3, expiry + timedelta(seconds=1)), (legacy_format, 3, expiry)):
            with self.subTest(entry=entry["MESSAGE"]):
                lab.ssh.return_value = SimpleNamespace(
                    returncode=0, stdout=json.dumps(failed) + "\n" + json.dumps(entry) + "\n")
                with self.assertRaisesRegex(RuntimeError, "matching fence"):
                    lab.host_renewal_failure_evidence(since, session_hash, expected_epoch, expected_expiry)


class RenewalDeadlineTests(unittest.TestCase):
    @staticmethod
    def lab():
        lab = object.__new__(qualify.Lab)
        fault_at = datetime.now(timezone.utc)
        original_expiry = fault_at + timedelta(seconds=25)
        renewed_expiry = original_expiry + timedelta(seconds=5)
        first_session = {"session_id": "opaque-session", "expires_at": original_expiry}
        renewed_session = {"session_id": "opaque-session", "expires_at": renewed_expiry,
                           "report": {"epoch": 2}}
        native = {"agent_pid": "940", "agent_state": "S:123", "invocation": "unit-1",
                  "workload_pid": "1209", "workload_state": "S:456",
                  "workload_alive": True, "marker": "v1"}
        event = {"at": fault_at + timedelta(seconds=1), "expires_at": renewed_expiry,
                 "session_id_hash": hashlib.sha256(b"opaque-session").hexdigest()[:32],
                 "epoch": 2, "phase": "renew"}
        lab.host_session = Mock(return_value=renewed_session)
        lab.native_observation = Mock(return_value=native)
        lab.verified_lease_events = Mock(return_value=[event])
        lab.note = Mock()
        return lab, fault_at, first_session, native

    def test_each_renewal_command_uses_the_same_remaining_25_second_deadline(self):
        lab, fault_at, first_session, native = self.lab()
        lab.wait = Mock(side_effect=lambda _label, probe, **_options: probe())
        with patch.object(qualify.time, "monotonic", side_effect=[100, 123, 124.5, 124.8, 124.9]):
            lab.wait_same_process_renewal(first_session, native, "c2", fault_at)

        self.assertEqual(lab.wait.call_args.kwargs["deadline"], 125)
        self.assertEqual(lab.host_session.call_args.kwargs,
                         {"timeout": 2, "stage": "same-process-host-session-renewal"})
        self.assertEqual(lab.native_observation.call_args.kwargs, {"timeout": 0.5})
        self.assertAlmostEqual(lab.verified_lease_events.call_args.kwargs["timeout"], 0.2)
        self.assertEqual(lab.note.call_args.args[0], "host_session_renewed_on_surviving_quorum")

    def test_late_completed_probe_cannot_certify_and_renewal_log_is_diagnostic_only(self):
        lab, fault_at, first_session, native = self.lab()

        def timeout_after_probe(_label, probe, **_options):
            self.assertFalse(probe())
            raise TimeoutError("renewal deadline passed")

        lab.wait = Mock(side_effect=timeout_after_probe)
        with patch.object(qualify.time, "monotonic", side_effect=[100, 101, 102, 103, 126]):
            with self.assertRaisesRegex(TimeoutError, "renewal deadline passed"):
                lab.wait_same_process_renewal(first_session, native, "c2", fault_at)

        self.assertEqual([call.args[0] for call in lab.note.call_args_list],
                         ["host_renewal_timeout_diagnostics"])
        self.assertEqual(lab.note.call_args.kwargs["status"], "ok")
        self.assertEqual(len(lab.note.call_args.kwargs["renewals"]), 1)
        self.assertEqual(lab.verified_lease_events.call_args.kwargs["timeout"], 5)

    def test_guest_renewal_diagnostic_cannot_replace_failed_operator_status(self):
        lab, fault_at, first_session, native = self.lab()
        lab.host_session.side_effect = RuntimeError("operator hosts: context deadline exceeded")
        with patch.object(qualify.time, "monotonic", side_effect=[100, 101, 102, 126]), \
                patch.object(qualify.time, "sleep"):
            with self.assertRaisesRegex(TimeoutError, "same-process-host-session-renewal"):
                lab.wait_same_process_renewal(first_session, native, "c2", fault_at)

        self.assertEqual(lab.host_session.call_args.kwargs["timeout"], 5)
        lab.native_observation.assert_not_called()
        self.assertEqual([call.args[0] for call in lab.note.call_args_list],
                         ["host_renewal_timeout_diagnostics"])
        self.assertEqual(len(lab.note.call_args.kwargs["renewals"]), 1)


class NativeCgroupPathTests(unittest.TestCase):
    service = "/system.slice/ts-orch.service"
    path = ("/system.slice/ts-orch.service/"
            "terrascale-host-f2f2e59c89f0cea0/terrabase")

    def test_r4_native_role_path_is_bound_to_unit_and_populated(self):
        qualify.validate_native_cgroup_path(self.path, self.service)
        lab = object.__new__(qualify.Lab)
        lab.ssh = Mock(return_value=SimpleNamespace(stdout="populated 1\nfrozen 0\n"))

        self.assertFalse(lab.cgroup_empty(self.path, self.service))
        command = lab.ssh.call_args.args[1]
        self.assertIn("systemctl show ts-orch.service -p ControlGroup --value", command)
        self.assertIn('test ! -L "$entry"', command)
        self.assertIn("grep -qw memory " + "/sys/fs/cgroup" + self.service +
                      "/cgroup.controllers", command)
        self.assertIn('test ! -s "$parent/cgroup.procs"', command)
        self.assertIn('grep -qw memory "$parent/cgroup.subtree_control"', command)
        self.assertIn("/sys/fs/cgroup" + self.path.rsplit("/", 1)[0], command)
        self.assertIn(self.path + "/cgroup.events", command)
        self.assertIn("elif test -e /sys/fs/cgroup" + self.path + "; then exit 5", command)
        lab.ssh.return_value = SimpleNamespace(stdout="populated 0\nfrozen 0\n")
        self.assertTrue(lab.cgroup_empty(self.path, self.service))
        lab.ssh.return_value = SimpleNamespace(stdout="populated 0\npopulated 1\n")
        with self.assertRaisesRegex(RuntimeError, "no populated state"):
            lab.cgroup_empty(self.path, self.service)

    def test_traversal_and_other_role_paths_are_rejected(self):
        invalid = [
            (self.path.replace("/system.slice/", "/system.slice/../"), self.service),
            (self.path.replace("/ts-orch.service/", "/ts-orch.service/./"), self.service),
            (self.path.replace("terrascale-host-", "terrascale.host-"), self.service),
            (self.path.replace("f2f2e59c89f0cea0", "g2f2e59c89f0cea0"), self.service),
            (self.path.replace("/terrabase", "/other"), self.service),
            (self.path.replace("/terrascale-host-", "/supervisor/terrascale-host-"),
             self.service),
            (self.path + "/child", self.service),
            (self.path, "/system.slice/other.service"),
            (self.path, "/system.slice/../ts-orch.service"),
        ]
        for path, service in invalid:
            with self.subTest(path=path, service=service):
                with self.assertRaisesRegex(ValueError, "invalid native workload cgroup path"):
                    qualify.validate_native_cgroup_path(path, service)

    def test_observation_binds_workload_start_time_and_agent_unit(self):
        output = ("agent_pid=1353\nagent_state=S:3500\n"
                  f"agent_cgroup={self.service}/supervisor\nservice_cgroup={self.service}\n"
                  "invocation=valid-invocation\nworkload_pid=1391\n"
                  "workload_state_before=S:3537\nworkload_state=S:3537\n"
                  f"workload_cgroup={self.path}\nmarker=v1\n")
        lab = object.__new__(qualify.Lab)
        lab.ssh = Mock(return_value=SimpleNamespace(stdout=output))

        observed = lab.native_observation()

        self.assertTrue(observed["workload_alive"])
        self.assertEqual(observed["workload_cgroup"], self.path)
        self.assertEqual(observed["agent_cgroup"], self.service + "/supervisor")
        lab.ssh.return_value = SimpleNamespace(stdout=output.replace(
            "workload_state=S:3537", "workload_state=missing"))
        exited = lab.native_observation()
        self.assertFalse(exited["workload_alive"])
        self.assertEqual(exited["workload_cgroup"], "")
        lab.ssh.return_value = SimpleNamespace(stdout=output.replace(
            "workload_state_before=S:3537", "workload_state_before=missing"))
        with self.assertRaisesRegex(RuntimeError, "PID changed"):
            lab.native_observation()
        lab.ssh.return_value = SimpleNamespace(stdout=output.replace(
            "workload_state=S:3537", "workload_state=S:9999"))
        with self.assertRaisesRegex(RuntimeError, "PID changed"):
            lab.native_observation()
        for wrong_agent in (self.service, self.service + "/other",
                            "/system.slice/other.service/supervisor"):
            with self.subTest(agent_cgroup=wrong_agent):
                lab.ssh.return_value = SimpleNamespace(stdout=output.replace(
                    f"agent_cgroup={self.service}/supervisor", f"agent_cgroup={wrong_agent}"))
                with self.assertRaisesRegex(RuntimeError, "not in its systemd supervisor subgroup"):
                    lab.native_observation()
        lab.ssh.return_value = SimpleNamespace(stdout=output.replace(
            f"workload_cgroup={self.path}",
            f"workload_cgroup={self.service}/supervisor/terrabase"))
        with self.assertRaisesRegex(ValueError, "invalid native workload cgroup path"):
            lab.native_observation()


class ChronyControlTests(unittest.TestCase):
    def test_control_socket_uses_a_private_root_owned_run_directory(self):
        lab = object.__new__(qualify.Lab)
        directory = Path("/run/ts-orch-fc-chrony.aB1cD2eF")
        lab.chrony_control_dir = None
        lab.sudo = Mock(return_value=SimpleNamespace(stdout=str(directory) + "\n"))
        owned = SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=0)
        with patch.object(qualify.Path, "lstat", return_value=owned):
            self.assertEqual(lab.chrony_socket_path(), directory / "chronyd.sock")
        lab.sudo.assert_called_once_with("mktemp", "-d", "-p", "/run",
                                         "ts-orch-fc-chrony.XXXXXXXX")
        self.assertEqual(lab.chrony_control_dir, directory)

        with patch.object(qualify.Path, "lstat", return_value=SimpleNamespace(
                st_mode=stat.S_IFDIR | 0o700, st_uid=1000)):
            with self.assertRaisesRegex(RuntimeError, "root-owned"):
                lab.chrony_socket_path()
        lab.sudo.return_value = SimpleNamespace(stdout="/tmp/ts-orch-fc-chrony.aB1cD2eF\n")
        with self.assertRaisesRegex(RuntimeError, "invalid private Chrony"):
            lab.chrony_socket_path()

    def test_foreground_chrony_uses_root_socket_and_cleanup_removes_only_owned_path(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = object.__new__(qualify.Lab)
            lab.root = Path(directory)
            lab.stage = lab.root / "stage"
            lab.logs = lab.root / "logs"
            lab.images = lab.root / "images"
            lab.secrets = lab.root / "secrets"
            for path in (lab.stage, lab.logs, lab.images, lab.secrets):
                path.mkdir()
            lab.subnet = ipaddress.ip_network("198.19.7.0/24")
            control_dir = Path("/run/ts-orch-fc-chrony.aB1cD2eF")
            socket = control_dir / "chronyd.sock"
            lab.chrony_socket_path = Mock(return_value=socket)
            lab.chrony_control_dir = control_dir
            lab.note = Mock()
            lab.wait = Mock(side_effect=lambda _label, predicate, **_kwargs: predicate())
            lab.created_nft_tables = []
            lab.created_links = []
            lab.mounted = []
            lab.vms = {}
            lab.session_probe_process = None
            lab.sudo = Mock(return_value=SimpleNamespace(returncode=0, stderr=""))
            process = Mock(pid=1234, returncode=0)
            process.poll.return_value = None

            def command_result(command, **_kwargs):
                if command[:3] == ["sudo", "-n", str(qualify.CHRONYC)]:
                    self.assertEqual(command[3:], ["-n", "-h", str(socket), "sources"])
                    return SimpleNamespace(returncode=0, stdout="^* remote 0 0 0\n")
                if command[:4] == ["sudo", "-n", "ss", "-H"]:
                    return SimpleNamespace(returncode=0, stdout="UNCONN 0 0 198.19.7.1:123 0.0.0.0:*\n")
                self.assertEqual(command, [str(qualify.CHRONYD), "-p", "-f",
                                           str(lab.stage / "chrony.conf")])
                return SimpleNamespace(returncode=0, stdout="")

            with patch.object(qualify, "run", side_effect=command_result), \
                    patch.object(qualify.subprocess, "Popen", return_value=process) as spawned, \
                    patch.object(qualify, "digest", return_value="pinned"):
                lab.start_chrony()

            config = (lab.stage / "chrony.conf").read_text()
            self.assertIn(f"bindcmdaddress {socket}\ncmdport 0\n", config)
            self.assertIn("bindaddress 198.19.7.1\nallow 198.19.7.0/24\nport 123\n", config)
            self.assertNotIn("local stratum", config)
            self.assertEqual(spawned.call_args.args[0],
                             ["sudo", "-n", str(qualify.CHRONYD), "-x", "-d", "-4", "-f",
                              str(lab.stage / "chrony.conf")])
            self.assertEqual(lab.cleanup(), [])
            lab.sudo.assert_any_call("rm", "-f", "--", str(socket), allow_failure=True)
            lab.sudo.assert_any_call("rmdir", "--", str(control_dir), allow_failure=True)
            self.assertIsNone(lab.chrony_control_dir)


class ClockReadinessTests(unittest.TestCase):
    @staticmethod
    def lab(measurements):
        lab = object.__new__(qualify.Lab)
        lab.ssh = Mock(return_value=SimpleNamespace(returncode=0))
        lab.measure_guest_clock = Mock(side_effect=measurements)
        lab.note = Mock()
        return lab

    def test_measurement_uses_monotonic_elapsed_for_uncertainty(self):
        lab = object.__new__(qualify.Lab)
        lab.ssh = Mock(return_value=SimpleNamespace(stdout="100150000000"))
        lab.guest_clock_upper_ns = {}
        lab.note = Mock()
        with patch.object(qualify.time, "time_ns", side_effect=[100_000_000_000, 100_300_000_000]), \
                patch.object(qualify.time, "monotonic_ns",
                             side_effect=[0, 1_000_000, 300_000_000, 301_000_000]):
            offset, uncertainty = lab.measure_guest_clock("c1")

        self.assertEqual((offset, uncertainty), (0, 151_500_000))
        self.assertEqual(lab.guest_clock_upper_ns["c1"], uncertainty)

    def test_host_realtime_steps_cannot_release_service(self):
        for after in (98_000_000_000, 102_000_000_000):
            with self.subTest(after=after):
                lab = object.__new__(qualify.Lab)
                lab.ssh = Mock(return_value=SimpleNamespace(stdout="100000000000"))
                lab.wait = Mock(return_value=True)
                lab.guest_clock_upper_ns = {}
                lab.note = Mock()
                with patch.object(qualify.time, "time_ns",
                                  side_effect=[100_000_000_000, after]), \
                        patch.object(qualify.time, "monotonic_ns",
                                     side_effect=[0, 1_000_000, 300_000_000, 301_000_000]):
                    with self.assertRaisesRegex(RuntimeError, "lab host clock changed"):
                        lab.wait_synchronized_guest_clock("c1")

                self.assertEqual(lab.ssh.call_count, 1)
                self.assertNotIn("c1", lab.guest_clock_upper_ns)

    def test_impossible_monotonic_interval_is_rejected(self):
        lab = object.__new__(qualify.Lab)
        lab.ssh = Mock(return_value=SimpleNamespace(stdout="100000000000"))
        lab.guest_clock_upper_ns = {}
        lab.note = Mock()
        with patch.object(qualify.time, "time_ns", side_effect=[100_000_000_000] * 2), \
                patch.object(qualify.time, "monotonic_ns",
                             side_effect=[0, 1_000_000, 500_000, 2_000_000]):
            with self.assertRaisesRegex(RuntimeError, "monotonic clock changed"):
                lab.measure_guest_clock("c1")

        self.assertNotIn("c1", lab.guest_clock_upper_ns)

    def test_real_timesync_and_kernel_probe_release_service(self):
        lab = self.lab([(-100_000_000, 100_000_000), (-100_000_000, 100_000_000)])
        lab.ssh.side_effect = [
            SimpleNamespace(returncode=0),
            SimpleNamespace(returncode=0, stdout='{"healthy":true,"kernel_maxerror_us":1000}'),
            SimpleNamespace(returncode=0),
        ]
        lab.wait = Mock(side_effect=lambda _label, probe, **_options: probe())

        lab.release_synchronized_guest_clock("c1")

        commands = [call.args[1] for call in lab.ssh.call_args_list]
        self.assertIn("systemd-timesyncd.service", commands[1])
        self.assertIn("ts-orch-clockprobe", commands[1])
        self.assertEqual(commands[2], f"/usr/bin/install -m 0600 /dev/null {qualify.CLOCK_READY}")
        self.assertFalse(any("date -u --set=" in command for command in commands))

    def test_unhealthy_kernel_probe_never_releases_service(self):
        lab = self.lab([])
        lab.ssh.side_effect = [SimpleNamespace(returncode=0),
                               SimpleNamespace(returncode=1, stdout='{"healthy":false}')]
        def require_ready(_label, probe, **_options):
            if not probe():
                raise TimeoutError("NTP clock stayed unhealthy")
        lab.wait = Mock(side_effect=require_ready)
        with self.assertRaisesRegex(TimeoutError, "NTP clock"):
            lab.release_synchronized_guest_clock("c1")
        self.assertEqual(lab.ssh.call_count, 2)

    def test_existing_service_refuses_clock_release(self):
        lab = self.lab([(-1_414_932_418, 139_698_286)])
        lab.ssh.return_value = SimpleNamespace(returncode=1)

        with self.assertRaisesRegex(RuntimeError, "before NTP clock readiness"):
            lab.release_synchronized_guest_clock("c1")

        lab.measure_guest_clock.assert_not_called()

    def test_ssh_waits_for_clock_before_runtime(self):
        lab = object.__new__(qualify.Lab)
        order = []
        lab.wait = Mock(side_effect=lambda label, probe, **options: order.append(label))
        lab.release_synchronized_guest_clock = Mock(side_effect=lambda name: order.append(f"ntp-{name}"))

        lab.wait_ssh("c1")

        self.assertEqual(order, ["ssh-c1", "ntp-c1", "service-c1"])

    def test_later_check_keeps_strict_one_second_bound(self):
        lab = self.lab([(900_000_000, 100_000_001)])

        with self.assertRaisesRegex(RuntimeError, "over one second"):
            lab.check_guest_clocks()
        lab.ssh.assert_not_called()

    def test_broker_closure_budget_includes_clock_jump_and_health_ssh(self):
        lab = object.__new__(qualify.Lab)
        elapsed = [0.0]
        with tempfile.TemporaryDirectory() as directory:
            lab.logs = Path(directory)
            lab.secrets = Path(directory)
            lab.natsdiag = Path(directory) / "natsdiag"
            lab.addresses = {"c1": "198.19.1.11"}
            lab.note = Mock()
            lab.wait = Mock(return_value=True)

            def slow_ssh(_name, command, **_options):
                if "date -u --set=" in command:
                    elapsed[0] += 12
                    return SimpleNamespace(returncode=0)
                if "ts-orch-clockprobe" in command:
                    elapsed[0] += 10
                    return SimpleNamespace(returncode=1, stdout='{"healthy":false}')
                return SimpleNamespace(returncode=0)

            lab.ssh = Mock(side_effect=slow_ssh)
            with patch.object(qualify.subprocess, "Popen", return_value=Mock()), \
                    patch.object(qualify.time, "monotonic", side_effect=lambda: elapsed[0]):
                with self.assertRaisesRegex(TimeoutError, "20-second fault budget"):
                    lab.verify_broker_clock_gate()

            self.assertEqual(lab.ssh.call_count, 2)
            self.assertEqual(lab.wait.call_count, 1)


class FirecrackerHarnessResourceTests(unittest.TestCase):
    def test_recovered_kernel_and_rootfs_are_explicitly_pinned(self):
        self.assertEqual(qualify.DEFAULT_KERNEL.name, "vmlinux-6.1.186")
        self.assertEqual(qualify.DEFAULT_ROOTFS.name, "rootfs-noble-20260911.ext4")
        self.assertEqual(qualify.KERNEL_SHA,
                         "586a02db8ea1fd331d45efa6ebf502fff21ceddfedf010ef70ba389b8e095523")
        self.assertEqual(qualify.ROOTFS_SHA,
                         "a6c1cb9c712d8bb9e67b05dd8f46b7e88827250b445e76015e6bb536a15e1af6")

    def test_preflight_still_rejects_asset_hash_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            kernel = Path(directory) / "kernel"
            kernel.write_bytes(b"unverified kernel")
            rootfs = Path(directory) / "rootfs"
            rootfs.write_bytes(b"unverified rootfs")

            with self.assertRaisesRegex(RuntimeError, "SHA-256 mismatch"):
                qualify.preflight(SimpleNamespace(kernel=kernel, rootfs=rootfs))

    def test_api_socket_path_uses_short_private_directory_with_long_run_dir(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            durable_root = parent / ("durable-" + "x" * 180)
            durable_root.mkdir()
            socket_dir = parent / "tsfc-a1b2c3"
            socket_dir.mkdir(mode=0o700)
            vm = qualify.VM(SimpleNamespace(root=durable_root, socket_dir=socket_dir),
                            "host", "198.19.1.14", "tap0", parent / "rootfs.ext4")

            self.assertEqual(vm.socket, socket_dir / "host.sock")
            self.assertLessEqual(len(os.fsencode(vm.socket)),
                                 qualify.MAX_UNIX_SOCKET_PATH_BYTES)
            self.assertGreater(len(os.fsencode(durable_root / "vms" / "host" / "api.sock")),
                               qualify.MAX_UNIX_SOCKET_PATH_BYTES)

    def test_api_socket_path_rejects_paths_over_unix_limit(self):
        too_long = Path("/tmp") / ("x" * qualify.MAX_UNIX_SOCKET_PATH_BYTES)
        with self.assertRaisesRegex(ValueError, "socket path is too long"):
            qualify.firecracker_socket_path(too_long, "host")

    def test_socket_cleanup_unlinks_only_owned_path_and_does_not_recurse(self):
        with tempfile.TemporaryDirectory() as directory:
            socket_dir = Path(directory) / "sockets"
            socket_dir.mkdir()
            owned_socket = socket_dir / "host.sock"
            unrelated = socket_dir / "leave-me"
            owned_socket.touch()
            unrelated.touch()
            vm = SimpleNamespace(process=None, socket=owned_socket)

            errors = qualify.cleanup_owned_sockets({"host": vm}, socket_dir)

            self.assertFalse(owned_socket.exists())
            self.assertTrue(unrelated.exists())
            self.assertEqual(len(errors), 1)
            self.assertIn("empty Firecracker API socket directory", errors[0])

    def test_socket_cleanup_keeps_socket_while_owned_process_group_runs(self):
        with tempfile.TemporaryDirectory() as directory:
            socket_dir = Path(directory) / "sockets"
            socket_dir.mkdir()
            owned_socket = socket_dir / "host.sock"
            owned_socket.touch()
            vm = SimpleNamespace(name="host", process=SimpleNamespace(pid=1234),
                                 socket=owned_socket)

            errors = qualify.cleanup_owned_sockets({"host": vm}, socket_dir)

            self.assertTrue(owned_socket.exists())
            self.assertEqual(errors, [
                "keep Firecracker API sockets until host is confirmed stopped"])

    def test_failed_qualification_cleanup_preserves_guest_images(self):
        lab = object.__new__(qualify.Lab)
        lab.session_probe_process = None
        lab.created_nft_tables = []
        lab.vms = {}
        lab.mounted = []
        lab.chrony_process = None
        lab.chrony_control_dir = None
        lab.created_links = []
        lab.images = Path("/tmp/failed-run/images")
        lab.secrets = Path("/tmp/failed-run/secrets")
        lab.stage = Path("/tmp/failed-run/stage")
        lab.note = Mock()

        with patch.object(qualify.shutil, "rmtree") as remove_tree:
            errors = qualify.Lab.cleanup(lab, preserve_images=True)

        self.assertEqual(errors, [])
        self.assertNotIn(call(lab.images, ignore_errors=True),
                         remove_tree.call_args_list)
        lab.note.assert_called_once_with(
            "guest_images_retained", path=str(lab.images), reason="qualification_failed")

    def test_process_group_signals_finish_before_the_leader_is_reaped(self):
        operations = []
        process = Mock(pid=1234, returncode=None)
        process.wait.side_effect = lambda **options: operations.append(("reap", options))

        with patch.object(qualify.os, "getpgid", return_value=1234), \
                patch.object(qualify.os, "killpg",
                             side_effect=lambda pgid, sig: operations.append(("signal", pgid, sig))), \
                patch.object(qualify, "wait_child_without_reaping",
                             side_effect=lambda child, timeout: operations.append(("wait", child, timeout))), \
                patch.object(qualify, "wait_for_process_group_quiescence",
                             side_effect=lambda pgid, timeout:
                             operations.append(("quiescent", pgid, timeout))):
            qualify.stop_process_group(process, timeout=1)

        self.assertEqual(operations, [
            ("signal", 1234, qualify.signal.SIGTERM),
            ("wait", process, 1),
            ("signal", 1234, qualify.signal.SIGKILL),
            ("quiescent", 1234, 1),
            ("reap", {"timeout": 1}),
        ])

    def test_cleanup_refuses_to_signal_a_reaped_process_group_leader(self):
        process = Mock(pid=1234, returncode=0)

        with patch.object(qualify.os, "getpgid") as getpgid, \
                patch.object(qualify.os, "killpg") as killpg:
            with self.assertRaisesRegex(RuntimeError, "reaped before group cleanup"):
                qualify.stop_process_group(process)

        getpgid.assert_not_called()
        killpg.assert_not_called()

    def test_live_group_member_timeout_keeps_leader_unreaped(self):
        process = Mock(pid=1234, returncode=None)

        with patch.object(qualify.os, "getpgid", return_value=1234), \
                patch.object(qualify.os, "killpg") as killpg, \
                patch.object(qualify, "wait_child_without_reaping", return_value=True), \
                patch.object(qualify, "live_process_group_members", return_value=[5678]), \
                patch.object(qualify.time, "monotonic", side_effect=[10, 11]), \
                patch.object(qualify.time, "sleep"):
            with self.assertRaisesRegex(TimeoutError, "still has live members"):
                qualify.stop_process_group(process, timeout=1)

        self.assertEqual(killpg.call_args_list, [
            call(1234, qualify.signal.SIGTERM), call(1234, qualify.signal.SIGKILL)])
        process.wait.assert_not_called()
        self.assertIsNone(process.returncode)

    def test_child_exit_probe_observes_without_reaping(self):
        process = Mock(pid=1234, returncode=None)
        result = SimpleNamespace(si_pid=1234)

        with patch.object(qualify.os, "waitid", return_value=result) as waitid:
            self.assertTrue(qualify.child_exited_without_reaping(process))

        waitid.assert_called_once_with(qualify.os.P_PID, 1234,
                                       qualify.os.WEXITED | qualify.os.WNOHANG | qualify.os.WNOWAIT)
        process.wait.assert_not_called()

    def test_process_group_kills_term_ignoring_child_before_reaping_leader(self):
        child_program = (
            "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); "
            "print('ready', flush=True); time.sleep(60)")
        leader_program = (
            "import subprocess,sys,time; "
            "child=subprocess.Popen([sys.executable,'-c',sys.argv[1]], "
            "stdout=subprocess.PIPE,text=True); "
            "assert child.stdout.readline().strip() == 'ready'; "
            "print(child.pid, flush=True); time.sleep(60)")
        leader = subprocess.Popen([sys.executable, "-c", leader_program, child_program],
                                  stdout=subprocess.PIPE, text=True, start_new_session=True)
        assert leader.stdout is not None
        child_pid = int(leader.stdout.readline().strip())

        original_wait = qualify.wait_for_process_group_quiescence

        def verify_group_before_reap(pgid, timeout):
            original_wait(pgid, timeout)
            self.assertIsNone(leader.returncode)
            for process_pid in (leader.pid, child_pid):
                try:
                    state = Path(f"/proc/{process_pid}/stat").read_text().rsplit(")", 1)[1].split()[0]
                except FileNotFoundError:
                    state = None
                self.assertIn(state, (None, "Z", "X"))

        try:
            with patch.object(qualify, "wait_for_process_group_quiescence",
                             side_effect=verify_group_before_reap):
                qualify.stop_process_group(leader, timeout=2)
            self.assertIsNotNone(leader.returncode)
        finally:
            leader.stdout.close()


if __name__ == "__main__":
    unittest.main()
