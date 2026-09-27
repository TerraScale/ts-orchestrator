"""Contract checks for the external M0 OCI caller's fail-closed joins."""

from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest import mock


SOURCE = Path(__file__).resolve().parents[2] / "scripts/ci/m0_oci_real_caller.py"
LOADER = importlib.util.spec_from_file_location("m0_oci_real_caller", SOURCE)
assert LOADER is not None and LOADER.loader is not None
CALLER = importlib.util.module_from_spec(LOADER)
LOADER.loader.exec_module(CALLER)


class RealCallerJoinTests(unittest.TestCase):
    def setUp(self) -> None:
        self.scope = {"cluster_id": "a" * 32, "tenant_id": "tenant", "database_id": "database",
                      "shard_id": 1}
        self.a = {"seat_id": "seat-a", "member_id": "member-a", "incarnation": "a" * 32}
        self.b = {"seat_id": "seat-b", "member_id": "member-b", "incarnation": "b" * 32}
        self.spec = {"scope": self.scope, "placement_database_id": "placement-db",
                     "partition_id": "partition-a", "members": [self.a, self.b]}
        binding = {**self.scope, "member_id": self.a["member_id"],
                   "incarnation": self.a["incarnation"]}
        oci = {"instance_id": "ocid1.instance.a", "region": "GRU", "owner": "terrascale",
               "fleet_generation": 1, "create_key": "a"}
        self.status = {"verified": False,
            "session_expires_at": (datetime.now(timezone.utc) + timedelta(minutes=1)).isoformat(),
            "registration": {
            "cell": "gru", "node": "node-a", "environment": "production", "managed_member": {
                "scope": binding, "host_attempt": 1}, "managed_oci": oci,
            "managed_placement": {"database_id": "placement-db", "partition_id": "partition-a",
                                  "seat_id": "seat-a"}},
            "reports": [{"cell": "gru", "environment": "production", "node": "node-a",
                         "role": "terrabase", "state": "running",
                         "digest": "c" * 64,
                         "observed_at": datetime.now(timezone.utc).isoformat(),
                         "managed": {"member": {"scope": binding, "host_attempt": 1},
                                     "oci": oci, "authority": {"epoch": 1},
                                     "process_pid": 123, "process_boot_id": "boot-a",
                                     "storage_recovered": True,
                                     "listener_ready": True, "serving_proof": {
                                         "serving": True, "listeners": {"client": True,
                                                                          "replication": True},
                                         "scope": binding, "authority": {"epoch": 1},
                                         "process": {"pid": 123, "start_nonce": "boot-a"},
                                         "replication": {
                                             "peer_member_id": "member-b",
                                             "peer_incarnation": "b" * 32,
                                             "current_authenticated": True,
                                             "local_source_sequence": 3,
                                             "peer_durable_sequence": 3,
                                             "peer_applied_sequence": 3,
                                             "local_inbox_durable_sequence": 2,
                                             "local_inbox_applied_sequence": 2}}}}]}

    def test_current_report_requires_exact_oci_and_signed_member(self) -> None:
        result = CALLER.member_report([self.status], self.spec, self.a, self.b, "gru",
                                      "ocid1.instance.a", "c" * 64)
        self.assertEqual(result["serving_proof"]["replication"]["peer_applied_sequence"], 3)
        with self.assertRaises(CALLER.QualificationError):
            CALLER.member_report([self.status], self.spec, self.a, self.b, "gru",
                                 "ocid1.instance.foreign", "c" * 64)
        self.status["registration"]["cell"] = "sfo"
        with self.assertRaises(CALLER.QualificationError):
            CALLER.member_report([self.status], self.spec, self.a, self.b, "gru",
                                 "ocid1.instance.a", "c" * 64)
        self.status["registration"]["cell"] = "gru"
        self.status["registration"]["managed_oci"]["region"] = "SFO"
        with self.assertRaises(CALLER.QualificationError):
            CALLER.member_report([self.status], self.spec, self.a, self.b, "gru",
                                 "ocid1.instance.a", "c" * 64)
        self.status["registration"]["managed_oci"]["region"] = "GRU"
        self.status["reports"][0]["cell"] = "sfo"
        with self.assertRaises(CALLER.QualificationError):
            CALLER.member_report([self.status], self.spec, self.a, self.b, "gru",
                                 "ocid1.instance.a", "c" * 64)
        self.status["reports"][0]["cell"] = "gru"
        self.status["reports"][0]["managed"]["serving_proof"]["replication"]["current_authenticated"] = False
        with self.assertRaises(CALLER.QualificationError):
            CALLER.member_report([self.status], self.spec, self.a, self.b, "gru",
                                 "ocid1.instance.a", "c" * 64)

    def test_customer_token_must_match_verified_envelope_commitments(self) -> None:
        import base64
        import hashlib

        token_id = b"i" * 16
        secret = b"s" * 32
        encoded_id = base64.urlsafe_b64encode(token_id).decode().rstrip("=")
        token = "tbk1." + encoded_id + "." + base64.urlsafe_b64encode(secret).decode().rstrip("=")
        ca = "CA PEM"
        reply = {"customer": {"token_id": encoded_id,
                              "verifier_sha256": hashlib.sha256(
                                  b"TB-APIKEY-V1\0" + token_id + secret).hexdigest(),
                              "https_ca_sha256": hashlib.sha256(ca.encode()).hexdigest()}}
        self.assertEqual(CALLER.customer_material(reply, {"version": 1, "token": token,
                                                          "https_ca_pem": ca}), (token, ca))
        with self.assertRaises(CALLER.QualificationError):
            CALLER.customer_material(reply, {"version": 1, "token": token,
                                             "https_ca_pem": "different CA"})

    def test_forward_maps_reject_unknown_duplicate_and_noncanonical_endpoints(self) -> None:
        target_a = ("10.251.0.21", 9465)
        target_b = ("10.251.0.22", 9465)
        with self.assertRaises(CALLER.QualificationError):
            CALLER.forwards(["10.251.0.21:9465=127.0.0.1:19465"],
                            {target_a, target_b}, 9465, True)
        for value in ("10.251.0.23:9465=127.0.0.1:19465",
                      "010.251.0.21:9465=127.0.0.1:19465",
                      "10.251.0.21:9465=0.0.0.0:19465"):
            with self.subTest(value=value), self.assertRaises(CALLER.QualificationError):
                CALLER.forwards([value], {target_a, target_b}, 9465, False)
        with self.assertRaises(CALLER.QualificationError):
            CALLER.forwards(["10.251.0.21:9465=127.0.0.1:19465"] * 2,
                            {target_a}, 9465, True)

    def test_operator_hosts_receives_exact_repeatable_nats_forwards(self) -> None:
        flags = ["10.251.0.11:4222=127.0.0.1:14222",
                 "10.251.0.12:4222=127.0.0.1:14223"]
        with mock.patch.object(CALLER.subprocess, "run", return_value=SimpleNamespace(
                returncode=0, stdout=b"[]")) as invoke:
            self.assertEqual(CALLER.hosts(Path("/tmp/operator"), Path("/tmp/operator.json"), flags), [])
        self.assertEqual(invoke.call_args.args[0], [
            "/tmp/operator", "operator", "hosts", "--config", "/tmp/operator.json",
            "--nats-forward", flags[0], "--nats-forward", flags[1]])

    def test_bootstrap_receipt_requires_clean_qualified_source_and_binary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            binary, receipt = Path(directory) / "ts-bootstrap", Path(directory) / "receipt.json"
            header = bytearray(20)
            header[:6] = b"\x7fELF\x02\x01"
            header[18:20] = (62).to_bytes(2, "little")
            binary.write_bytes(header)
            binary_sha = hashlib.sha256(binary.read_bytes()).hexdigest()
            source = "a" * 40
            tree = "b" * 40
            digest = "c" * 64
            retained = {}
            for name in ("build_command", "build_log", "test_command", "test_log"):
                evidence_path = Path(directory) / name
                evidence_path.write_text(f"retained {name}\n")
                retained[name] = evidence_path
            record = {
                "schema": "terrascale.bootstrap.local-build.v1",
                "repository": "TerraScale/ts-orchestrator",
                "source_revision": source, "source_tree": tree,
                "source_clean_before": True, "source_clean_after": True,
                "go_version": "go1.27.1", "go_mod_sha256": digest,
                "go_sum_sha256": digest, "goos": "linux", "goarch": "amd64",
                "cgo_enabled": False, "binary_name": "ts-bootstrap",
                "binary_sha256": binary_sha, "binary_bytes": binary.stat().st_size,
                "vcs_revision": source, "vcs_modified": False,
                "elf_machine": "Advanced Micro Devices X86-64",
                "has_interp": False, "has_needed": False,
                "build_exit": 0,
                "build_command_sha256": hashlib.sha256(retained["build_command"].read_bytes()).hexdigest(),
                "build_log_sha256": hashlib.sha256(retained["build_log"].read_bytes()).hexdigest(),
                "test_exit": 0,
                "test_command_sha256": hashlib.sha256(retained["test_command"].read_bytes()).hexdigest(),
                "test_log_sha256": hashlib.sha256(retained["test_log"].read_bytes()).hexdigest(),
            }
            self.assertEqual(set(record), CALLER.BOOTSTRAP_RECEIPT_FIELDS)
            receipt.write_text(json.dumps(record))
            receipt_sha = hashlib.sha256(receipt.read_bytes()).hexdigest()
            with mock.patch.object(CALLER.subprocess, "run", side_effect=[
                    SimpleNamespace(returncode=0, stdout=f"go1.27.1\nCGO_ENABLED=0\n"
                                    f"vcs.revision={source}\nvcs.modified=false\n"),
                    SimpleNamespace(returncode=0, stdout="ELF has no dynamic loader")]):
                result = CALLER.bootstrap_provenance(receipt, receipt_sha, binary, binary_sha,
                                                     {"source_revision": source, "source_tree": tree,
                                                      "go_mod_sha256": digest,
                                                      "go_sum_sha256": digest}, retained)
            self.assertEqual(result["sha256"], receipt_sha)
            retained["build_log"].write_text("tampered log\n")
            with self.assertRaises(CALLER.QualificationError):
                CALLER.bootstrap_provenance(receipt, receipt_sha, binary, binary_sha,
                                            {"source_revision": source, "source_tree": tree,
                                             "go_mod_sha256": digest,
                                             "go_sum_sha256": digest}, retained)
            retained["build_log"].write_text("retained build_log\n")
            record["vcs_modified"] = True
            receipt.write_text(json.dumps(record))
            with self.assertRaises(CALLER.QualificationError):
                CALLER.bootstrap_provenance(receipt, hashlib.sha256(receipt.read_bytes()).hexdigest(),
                                            binary, binary_sha,
                                            {"source_revision": source, "source_tree": tree,
                                             "go_mod_sha256": digest,
                                             "go_sum_sha256": digest}, retained)

    def test_real_loopback_tcp_preserves_signed_ip_tls_and_host(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cert, key = Path(directory) / "cert.pem", Path(directory) / "key.pem"
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                            "-days", "1", "-keyout", str(key), "-out", str(cert),
                            "-subj", "/CN=10.251.0.21", "-addext", "subjectAltName=IP:10.251.0.21"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
            server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_context.load_cert_chain(str(cert), str(key))
            listener = socket.socket()
            listener.bind(("127.0.0.1", 0))
            listener.listen(2)
            received = []

            def serve() -> None:
                try:
                    for _ in range(2):
                        accepted, _ = listener.accept()
                        try:
                            with server_context.wrap_socket(accepted, server_side=True) as connection:
                                request = connection.recv(4096)
                                received.append(request)
                                response = b'{"version":1,"state":"absent"}'
                                connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: " +
                                                   str(len(response)).encode() +
                                                   b"\r\nConnection: close\r\n\r\n" + response)
                        except ssl.SSLError:
                            pass
                finally:
                    listener.close()

            thread = threading.Thread(target=serve, daemon=True)
            thread.start()
            local = ("127.0.0.1", listener.getsockname()[1])
            client_context = ssl.create_default_context(cadata=cert.read_text())
            self.assertEqual(CALLER.request(("10.251.0.21", 9465), local, client_context,
                                            "test-token", "GET", "/point")["state"], "absent")
            with self.assertRaises(ssl.SSLCertVerificationError):
                CALLER.request(("10.251.0.22", 9465), local, client_context,
                               "test-token", "GET", "/point")
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive())
            self.assertIn(b"Host: 10.251.0.21:9465", received[0])
            self.assertIn(b"Authorization: Bearer test-token", received[0])


if __name__ == "__main__":
    unittest.main()
