import hashlib
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import types
import unittest
from unittest.mock import patch

import qualify


class ProductionDriverContractTests(unittest.TestCase):
    def test_run_enters_private_network_namespace_after_host_checks(self):
        class Reexec(Exception):
            pass

        with patch.object(qualify.os.path, "samefile", return_value=True), \
                patch.object(qualify.os, "geteuid", return_value=0), \
                patch.object(qualify, "check_network_collision") as collision, \
                patch.object(qualify, "command", return_value=types.SimpleNamespace(stdout="yes\n")) as clock, \
                patch.object(qualify.shutil, "which", return_value="/bin/unshare"), \
                patch.object(qualify.os, "execv", side_effect=Reexec) as execv:
            with self.assertRaises(Reexec):
                qualify.ensure_run_network_namespace(True)
        collision.assert_called_once_with()
        clock.assert_called_once_with("timedatectl", "show", "-p", "NTPSynchronized", "--value")
        argv = execv.call_args.args[1]
        self.assertEqual(argv[:3], ["/bin/unshare", "--net", "--"])
        self.assertEqual(argv[3], qualify.sys.executable)
        self.assertEqual(argv[4], str(Path(qualify.__file__).resolve()))

    def test_prepared_only_and_already_isolated_do_not_reenter_namespace(self):
        with patch.object(qualify.os.path, "samefile", return_value=False), \
                patch.object(qualify.os, "execv") as execv:
            qualify.ensure_run_network_namespace(False)
            qualify.ensure_run_network_namespace(True)
        execv.assert_not_called()

    def test_network_requires_private_namespace_and_raises_loopback_first(self):
        run = qualify.Qualification(types.SimpleNamespace(run=True))
        try:
            with patch.object(qualify.os.path, "samefile", return_value=True), \
                    patch.object(qualify, "command") as command:
                with self.assertRaisesRegex(RuntimeError, "private namespace"):
                    run.network()
                command.assert_not_called()
            with patch.object(qualify.os.path, "samefile", return_value=False), \
                    patch.object(qualify, "command") as command, \
                    patch.object(run, "firewall"):
                run.network()
                self.assertEqual(command.call_args_list[0].args,
                                 ("ip", "link", "set", "lo", "up"))
        finally:
            shutil.rmtree(run.root)

    def test_ntp_response_echoes_client_transmit_and_uses_server_mode(self):
        request = bytearray(48)
        request[0] = 0x23
        request[40:48] = b"client01"
        answer = qualify.ntp_response(bytes(request), 1700000000.25)
        self.assertEqual(len(answer), 48)
        self.assertEqual(answer[0] & 7, 4)
        self.assertEqual(answer[1], 2)
        self.assertEqual(answer[24:32], b"client01")
        with self.assertRaises(ValueError):
            qualify.ntp_response(b"short", 1700000000)

    def test_audit_rejects_writes_and_unlisted_routes(self):
        requests = ([{"method": "GET", "host": "169.254.169.254", "requestUri": path,
                      "status": 200, "listed": True} for path in sorted(qualify.IMDS_PATHS)] +
                    [{"method": "POST", "host": "auth.sa-saopaulo-1.oraclecloud.com", "status": 200,
                      "listed": True}] +
                    [{"method": "GET", "host": "iaas.sa-saopaulo-1.oraclecloud.com",
                      "requestUri": f"/compute/{index}", "status": 200, "listed": True}
                     for index in range(3)] +
                    [{"method": "GET", "host": "objectstorage.sa-saopaulo-1.oraclecloud.com", "status": 200,
                      "listed": True}])
        audit = {"unknownSources": 0, "slots": {slot: {"requests": requests.copy(), "overflow": 0}
                                              for slot in qualify.SLOTS}}
        self.assertEqual(qualify.check_audit(audit), {slot: 11 for slot in qualify.SLOTS})
        audit["slots"]["seed-a"]["requests"].append(
            {"method": "PUT", "host": "objectstorage.sa-saopaulo-1.oraclecloud.com",
             "status": 405, "listed": False})
        with self.assertRaises(RuntimeError):
            qualify.check_audit(audit)
        audit["slots"]["seed-a"]["requests"].pop()
        audit["slots"]["seed-a"]["requests"][0]["status"] = 404
        with self.assertRaises(RuntimeError):
            qualify.check_audit(audit)

    def test_audit_requires_distinct_metadata_and_compute_reads(self):
        requests = ([{"method": "GET", "host": "169.254.169.254", "requestUri": "/opc/v2/instance/id",
                      "status": 200, "listed": True}] * 6 +
                    [{"method": "POST", "host": "auth.sa-saopaulo-1.oraclecloud.com", "status": 200,
                      "listed": True}] +
                    [{"method": "GET", "host": "iaas.sa-saopaulo-1.oraclecloud.com",
                      "requestUri": "/compute/1", "status": 200, "listed": True}] * 3 +
                    [{"method": "GET", "host": "objectstorage.sa-saopaulo-1.oraclecloud.com",
                      "status": 200, "listed": True}])
        audit = {"unknownSources": 0, "slots": {slot: {"requests": requests, "overflow": 0}
                                              for slot in qualify.SLOTS}}
        with self.assertRaises(RuntimeError):
            qualify.check_audit(audit)

    def test_pinned_file_detects_change(self):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / "input"
            file.write_bytes(b"pinned")
            expected = hashlib.sha256(b"pinned").hexdigest()
            self.assertEqual(qualify.require_pinned_file(file, expected), file)
            file.write_bytes(b"changed")
            with self.assertRaises(ValueError):
                qualify.require_pinned_file(file, expected)

    def test_firewall_scopes_peer_ports_and_drops_all_other_vm_traffic(self):
        programs = []

        def capture(*args, **kwargs):
            if args[:3] == ("nft", "list", "table"):
                return types.SimpleNamespace(returncode=1, stdout="", stderr="")
            self.assertEqual(args[:3], ("nft", "-f", "-"))
            programs.append(kwargs["input_text"])
            return types.SimpleNamespace(returncode=0, stdout="", stderr="")

        with patch.object(qualify, "command", side_effect=capture):
            run = qualify.Qualification(types.SimpleNamespace(run=False))
            try:
                run.firewall()
            finally:
                shutil.rmtree(run.root)
        self.assertEqual(len(programs), 2)
        self.assertIn("tcp dport { 4222, 6222 } accept", programs[1])
        self.assertIn("ether type arp accept", programs[1])
        self.assertIn("169.254.169.254 tcp dport 80 counter accept", programs[1])
        self.assertIn("10.44.0.1 udp dport 123 counter accept", programs[1])
        self.assertIn("counter drop", programs[0])
        self.assertIn("counter drop", programs[1])
        self.assertNotIn("policy drop", programs[0])  # host traffic is unaffected

    def test_vm_stop_closes_serial_after_process_exit_races_with_signal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            vm = qualify.VM("controller-a", "tap0", root / "root.ext4", root / "kernel",
                            root / "firecracker", root, root / "ssh-key", root / "known-hosts")
            vm.socket.touch()
            vm.serial = (root / "serial.log").open("wb")

            class ExitingProcess:
                pid = 12345
                exited = False

                def poll(self):
                    return 0 if self.exited else None

                def wait(self, timeout):
                    self.exited = True
                    return 0

            vm.process = ExitingProcess()
            with patch.object(qualify.os, "killpg", side_effect=ProcessLookupError):
                vm.stop()
            self.assertIsNone(vm.process)
            self.assertIsNone(vm.serial)
            self.assertFalse(vm.socket.exists())

    def test_cleanup_kills_simulator_that_ignores_term(self):
        run = qualify.Qualification(types.SimpleNamespace(run=False))

        class StuckSimulator:
            pid = 12345
            killed = False

            def poll(self):
                return -signal.SIGKILL if self.killed else None

            def wait(self, timeout):
                if not self.killed:
                    raise subprocess.TimeoutExpired("simulator", timeout)
                return -signal.SIGKILL

        run.simulator = StuckSimulator()

        def signal_process(pid, sig):
            if sig == signal.SIGKILL:
                run.simulator.killed = True

        try:
            with patch.object(qualify.os, "killpg", side_effect=signal_process):
                self.assertEqual(run.cleanup(), ["simulator required SIGKILL during cleanup"])
            self.assertTrue(run.simulator.killed)
        finally:
            shutil.rmtree(run.root)

    def test_failed_run_retains_ntp_and_owned_firewall_counters(self):
        run = qualify.Qualification(types.SimpleNamespace(run=False))

        class NTP:
            requests = {slot: 2 for slot in qualify.SLOTS}
            counts = {slot: 0 for slot in qualify.SLOTS}
            send_errors = {slot: 0 for slot in qualify.SLOTS}
            unknown = 0

            def close(self):
                pass

        run.ntp = NTP()
        run.created_tables = [("bridge", "tspr_test")]
        rules = ("table bridge tspr_test {\n"
                 "udp dport 123 counter packets 6 bytes 288 accept\n"
                 "counter packets 1 bytes 48 drop\n}\n")

        def nft(*args, **kwargs):
            if args[:3] == ("nft", "list", "table"):
                return types.SimpleNamespace(stdout=rules)
            self.assertEqual(args[:3], ("nft", "delete", "table"))
            return types.SimpleNamespace(stdout="")

        try:
            with patch.object(qualify, "command", side_effect=nft):
                self.assertEqual(run.cleanup(), [])
            self.assertEqual(run.report["ntpRequests"], NTP.requests)
            self.assertEqual(run.report["ntpReplies"], NTP.counts)
            self.assertEqual(run.report["firewallDrops"], 1)
            self.assertIn("counter packets 6 bytes 288 accept",
                          (run.root / "firewall-bridge.txt").read_text())
            self.assertEqual(run.report["firewallCounterFiles"], {"bridge": "firewall-bridge.txt"})
        finally:
            shutil.rmtree(run.root)

    def test_reboot_accepts_ssh_disconnect_only_after_new_boot_and_invocation(self):
        run = qualify.Qualification(types.SimpleNamespace(run=False))
        run.report["serviceIdentity"] = {slot: {"uid": 1000, "gid": 1000}
                                         for slot in qualify.SLOTS}

        class RebootingVM:
            def __init__(self):
                self.rebooted = False

            def boot(self):
                pass

            def wait_ssh(self, *, different_boot_id=None):
                return "boot-new" if different_boot_id else "boot-old"

            def health(self, uid, gid):
                return {"bootId": "boot-new" if self.rebooted else "boot-old",
                        "controllerInvocation": "inv-new" if self.rebooted else "inv-old"}

            def ssh(self, script, *, timeout, check):
                self.rebooted = True
                raise subprocess.TimeoutExpired("ssh", timeout)

        run.vms = {slot: RebootingVM() for slot in qualify.SLOTS}
        try:
            run.run_vms()
            self.assertEqual(set(run.report["guests"]), set(qualify.SLOTS))
            self.assertTrue(all(run.report["guests"][slot]["restart"]["bootId"] == "boot-new"
                                for slot in qualify.SLOTS))
        finally:
            shutil.rmtree(run.root)

    def test_health_failure_names_initial_stage_and_collects_safe_diagnostics(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            vm = qualify.VM("controller-a", "tap0", root / "root.ext4", root / "kernel",
                            root / "firecracker", root, root / "ssh-key", root / "known-hosts")
            responses = [types.SimpleNamespace(returncode=1, stdout="",
                                               stderr="failed-stage=ntp-synchronized\n"),
                         types.SimpleNamespace(returncode=0, stdout="[clock]\nno\n",
                                               stderr="")]
            with patch.object(vm, "ssh", side_effect=responses) as ssh, \
                    patch.object(qualify.time, "monotonic", side_effect=[0, 0, 301]), \
                    patch.object(qualify.time, "sleep"):
                with self.assertRaisesRegex(TimeoutError, "failed-stage=ntp-synchronized") as raised:
                    vm.health(988, 988)
            self.assertIn("guest diagnostics:\n[clock]\nno", str(raised.exception))
            self.assertEqual(ssh.call_count, 2)
            self.assertIn("|| fail ntp-synchronized", ssh.call_args_list[0].args[0])
            self.assertIn("SYSLOG_IDENTIFIER=systemd", ssh.call_args.args[0])


if __name__ == "__main__":
    unittest.main()
