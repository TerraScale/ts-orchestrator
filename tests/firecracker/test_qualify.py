import json
import hashlib
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

    def test_verified_lease_event_parser_uses_only_accepted_message(self):
        lab = object.__new__(qualify.Lab)
        at = datetime(2026, 9, 24, 12, 0, 1, tzinfo=timezone.utc)
        expiry = (at + timedelta(seconds=30)).isoformat()
        session_hash = hashlib.sha256(b"opaque-id").hexdigest()[:32]
        entry = {"__REALTIME_TIMESTAMP": str(int(at.timestamp() * 1_000_000)),
                 "MESSAGE": (f'time=2026-09-24T12:00:01Z level=INFO msg="host session accepted" '
                             f'phase=renew session_id_hash={session_hash} epoch=2 expires_at={expiry}')}
        lab.ssh = Mock(return_value=SimpleNamespace(stdout=json.dumps(entry) + "\n"))

        events = lab.verified_lease_events(at - timedelta(seconds=1))

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["expires_at"], at + timedelta(seconds=30))
        self.assertEqual(events[0]["session_id_hash"], session_hash)
        self.assertNotIn("opaque-id", json.dumps(entry))

    def test_fence_event_binds_latest_signed_lease_before_expiry(self):
        lab = object.__new__(qualify.Lab)
        lab.note = Mock()
        expiry = datetime(2026, 9, 24, 12, 0, 30, tzinfo=timezone.utc)
        since = expiry - timedelta(seconds=20)
        session_hash = hashlib.sha256(b"opaque-id").hexdigest()[:32]
        failed = {"__REALTIME_TIMESTAMP": str(int((expiry - timedelta(seconds=15)).timestamp() * 1_000_000)),
                  "MESSAGE": 'time=2026-09-24T12:00:15Z level=WARN msg="host session exchange deferred" stage=renew'}
        fenced = {"__REALTIME_TIMESTAMP": str(int((expiry - timedelta(seconds=4.5)).timestamp() * 1_000_000)),
                  "MESSAGE": (f'time=2026-09-24T12:00:25.5Z level=INFO msg="host session fenced" '
                              f'session_id_hash={session_hash} epoch=3 expires_at={expiry.isoformat()} '
                              'cause_class=reserve_exhausted')}
        lab.ssh = Mock(return_value=SimpleNamespace(returncode=0, stdout=(
            json.dumps(failed) + "\n" + json.dumps(fenced) + "\n")))

        lab.host_renewal_failure_evidence(since, session_hash, 3, expiry)

        self.assertEqual(lab.note.call_args.kwargs["fence_cause_class"], "reserve_exhausted")
        self.assertEqual(lab.note.call_args.kwargs["actual_fence_started_at"],
                         (expiry - timedelta(seconds=4.5)).isoformat())
        with self.assertRaisesRegex(RuntimeError, "matching fence"):
            lab.host_renewal_failure_evidence(since, "0" * 32, 3, expiry)


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
                  f"agent_cgroup={self.service}\nservice_cgroup={self.service}\n"
                  "invocation=valid-invocation\nworkload_pid=1391\n"
                  "workload_state_before=S:3537\nworkload_state=S:3537\n"
                  f"workload_cgroup={self.path}\nmarker=v1\n")
        lab = object.__new__(qualify.Lab)
        lab.ssh = Mock(return_value=SimpleNamespace(stdout=output))

        observed = lab.native_observation()

        self.assertTrue(observed["workload_alive"])
        self.assertEqual(observed["workload_cgroup"], self.path)
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
        lab.ssh.return_value = SimpleNamespace(stdout=output.replace(
            f"agent_cgroup={self.service}", "agent_cgroup=/user.slice/other.service"))
        with self.assertRaisesRegex(RuntimeError, "not in its systemd service cgroup"):
            lab.native_observation()


class ClockCalibrationTests(unittest.TestCase):
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
                lab.ssh = Mock(side_effect=[SimpleNamespace(returncode=0),
                                            SimpleNamespace(stdout="100000000000")])
                lab.guest_clock_upper_ns = {}
                lab.note = Mock()
                with patch.object(qualify.time, "time_ns",
                                  side_effect=[100_000_000_000, after]), \
                        patch.object(qualify.time, "monotonic_ns",
                                     side_effect=[0, 1_000_000, 300_000_000, 301_000_000]):
                    with self.assertRaisesRegex(RuntimeError, "lab host clock changed"):
                        lab.calibrate_guest_clock("c1")

                self.assertEqual(lab.ssh.call_count, 2)
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

    def test_step_remeasures_before_releasing_service(self):
        lab = self.lab([(-1_414_932_418, 139_698_286), (-100_000_000, 100_000_000)])
        with patch.object(qualify.time, "time_ns", return_value=1_000_000_000_123_456_789):
            lab.calibrate_guest_clock("c1")

        commands = [call.args[1] for call in lab.ssh.call_args_list]
        self.assertEqual(commands, [
            f'test ! -e {qualify.CLOCK_READY} && '
            'test "$(systemctl show -p MainPID --value ts-orch.service)" = 0',
            "date -u --set=@1000000000.123456789 >/dev/null",
            f"/usr/bin/install -m 0600 /dev/null {qualify.CLOCK_READY}",
        ])
        self.assertEqual(lab.measure_guest_clock.call_count, 2)
        self.assertEqual(lab.note.call_args.args[0], "guest_clock_released")

    def test_failed_remeasurement_never_releases_service(self):
        lab = self.lab([(-1_414_932_418, 139_698_286)] * 4)
        with patch.object(qualify.time, "time_ns", return_value=1_000_000_000_123_456_789):
            with self.assertRaisesRegex(RuntimeError, "over one second"):
                lab.calibrate_guest_clock("c1")

        commands = [call.args[1] for call in lab.ssh.call_args_list]
        self.assertEqual(len([command for command in commands if command.startswith("date -u --set=")]), 3)
        self.assertNotIn(f"/usr/bin/install -m 0600 /dev/null {qualify.CLOCK_READY}", commands)

    def test_existing_service_refuses_clock_step(self):
        lab = self.lab([(-1_414_932_418, 139_698_286)])
        lab.ssh.return_value = SimpleNamespace(returncode=1)

        with self.assertRaisesRegex(RuntimeError, "before clock calibration"):
            lab.calibrate_guest_clock("c1")

        lab.measure_guest_clock.assert_not_called()

    def test_ssh_calibrates_before_waiting_for_runtime(self):
        lab = object.__new__(qualify.Lab)
        order = []
        lab.wait = Mock(side_effect=lambda label, probe, **options: order.append(label))
        lab.calibrate_guest_clock = Mock(side_effect=lambda name: order.append(f"calibrate-{name}"))

        lab.wait_ssh("c1")

        self.assertEqual(order, ["ssh-c1", "calibrate-c1", "service-c1"])

    def test_later_check_keeps_strict_one_second_bound(self):
        lab = self.lab([(900_000_000, 100_000_001)])

        with self.assertRaisesRegex(RuntimeError, "over one second"):
            lab.check_guest_clocks()

        lab.ssh.assert_not_called()


if __name__ == "__main__":
    unittest.main()
