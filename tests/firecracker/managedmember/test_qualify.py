"""Fail-closed checks for the two-member Firecracker driver contract."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


_SPEC = importlib.util.spec_from_file_location("managed_member_qualify", Path(__file__).with_name("qualify.py"))
assert _SPEC is not None and _SPEC.loader is not None
qualify = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(qualify)


class InputContractTests(unittest.TestCase):
    def test_firecracker_resource_routes_match_valid_body_ids(self) -> None:
        lab = SimpleNamespace(socket_dir=Path("/tmp"), images=Path("/private/images"),
                              taps={"a": "tap_a", "b": "tap_b"})
        for member in ("a", "b"):
            requests = qualify.VM(lab, member).resource_requests()
            with self.subTest(member=member):
                self.assertEqual([route for route, _ in requests],
                                 ["/drives/rootfs", "/drives/managed_volume", "/network-interfaces/eth0"])
                self.assertEqual([body["drive_id"] for _, body in requests[:2]],
                                 ["rootfs", "managed_volume"])
                self.assertEqual(requests[2][1]["iface_id"], "eth0")
                self.assertEqual(requests[1][1]["path_on_host"],
                                 str(lab.images / f"{member}-volume.ext4"))
                self.assertEqual(requests[2][1]["host_dev_name"], lab.taps[member])
                self.assertEqual(requests[2][1]["guest_mac"], qualify.GUEST_MACS[member])
        for bad_id in ("managed-volume", "managed/volume", "", "volumé"):
            with self.subTest(bad_id=bad_id):
                with self.assertRaisesRegex(qualify.QualificationError, "resource ID"):
                    qualify.firecracker_drive_request(bad_id, Path("/private/volume.ext4"), False)
                with self.assertRaisesRegex(qualify.QualificationError, "resource ID"):
                    qualify.firecracker_network_request(bad_id, "tap_a", qualify.GUEST_MACS["a"])
        vm = qualify.VM(lab, "a")
        with (mock.patch.object(vm, "resource_requests", side_effect=qualify.QualificationError("invalid resource ID")),
              mock.patch.object(qualify.subprocess, "Popen") as spawn):
            with self.assertRaisesRegex(qualify.QualificationError, "resource ID"):
                vm.start()
            spawn.assert_not_called()

    def test_guest_tool_layout_requires_canonical_sbin_blkid(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            mount = Path(root)
            required = (Path("/usr/lib/systemd/systemd"), Path("/usr/sbin/blkid"),
                        *(Path("/usr/bin") / command for command in
                          ("mount", "findmnt", "mountpoint", "readlink", "systemctl", "ip")))
            for destination in required:
                target = qualify.guest_path(mount, destination)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(b"tool")
            qualify.check_guest_tools(mount)
            self.assertIn("$(/usr/sbin/blkid -s UUID", qualify.volume_setup_script("a"))
            qualify.guest_path(mount, Path("/usr/sbin/blkid")).unlink()
            qualify.guest_path(mount, Path("/usr/bin/blkid")).write_bytes(b"wrong location")
            with self.assertRaisesRegex(qualify.QualificationError, "/usr/sbin/blkid"):
                qualify.check_guest_tools(mount)

    def test_signed_members_derive_distinct_runtime_directories(self) -> None:
        shared = {"cluster_id": "aa" * 16,
                  "tenant_id": "018f0000-0000-7000-8000-000000000001",
                  "database_id": "018f0000-0000-7000-8000-000000000001",
                  "shard_id": 1}
        for member in ("a", "b"):
            scope = {**shared, "member_id": qualify.MEMBER_IDS[member],
                     "incarnation": ("bb" if member == "a" else "cc") * 16}
            with self.subTest(member=member):
                self.assertEqual(qualify.member_directory(scope, 1), qualify.MEMBER_DIRS[member])
        self.assertNotEqual(qualify.MEMBER_DIRS["a"], qualify.MEMBER_DIRS["b"])

    def test_rejects_symlink_and_changed_input(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root)
            source = directory / "input"
            source.write_bytes(b"pinned bytes")
            digest = qualify.sha256_file(source)
            record = {"path": str(source), "sha256": digest}
            self.assertEqual(qualify.exact_input("test", record)["sha256"], digest)
            alias = directory / "alias"
            alias.symlink_to(source)
            with self.assertRaisesRegex(qualify.QualificationError, "regular, direct file"):
                qualify.exact_input("test", {"path": str(alias), "sha256": digest})
            source.write_bytes(b"changed")
            with self.assertRaisesRegex(qualify.QualificationError, "SHA-256 mismatch"):
                qualify.exact_input("test", record)

    def test_rejects_incomplete_profile_before_touching_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            manifest = Path(root) / "manifest.json"
            manifest.write_text(json.dumps({"profile": qualify.PROFILE,
                                            "source_commits": {"orchestrator": "a" * 40, "terrabase": "b" * 40},
                                            "inputs": {}, "members": {"a": {}, "b": {}}}))
            with self.assertRaisesRegex(qualify.QualificationError, "missing or extra"):
                qualify.load_manifest(manifest)

    def test_rejects_subnet_collision_without_creating_links(self) -> None:
        route = subprocess.CompletedProcess(["ip"], 0, stdout='[{"dst":"10.77.39.0/24"}]', stderr="")
        with mock.patch.object(qualify.subprocess, "run", return_value=route) as run:
            with self.assertRaisesRegex(qualify.QualificationError, "collides"):
                qualify.check_subnet_collision()
            self.assertEqual(run.call_count, 1)

    def test_rejects_malformed_scope_before_vm_effects(self) -> None:
        member = "a"
        scope = {"cluster_id": "11" * 16, "tenant_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                 "database_id": "22222222-2222-2222-2222-222222222222", "shard_id": 7,
                 "member_id": qualify.MEMBER_IDS[member], "incarnation": "bb" * 16}
        inputs = {name: {"sha256": "a" * 64} for name in qualify.MEMBER_INPUTS}
        runtime = {
            "device_path": "/dev/oracleoci/oraclevdb",
            "mount_path": str(qualify.member_directory(scope, 1) / "volume"),
            "filesystem_uuid": qualify.VOLUME_UUIDS[member], "filesystem_type": "ext4",
            "trusted_key_sha256": inputs["trusted_public_key"]["sha256"],
            "server_certificate_sha256": inputs["server_crt"]["sha256"],
            "server_private_key_sha256": inputs["server_key"]["sha256"],
            "client_ca_roots_sha256": inputs["client_ca_pem"]["sha256"],
            "client_managed_material_manifest_sha256": inputs["client_managed_manifest"]["sha256"],
            "replication_listen_address": "10.77.39.11:7000",
            "replication_peer_member_id": qualify.MEMBER_IDS["b"],
            "replication_peer_address": "10.77.39.12:7000",
            "replication_server_ca_sha256": inputs["server_ca_pem"]["sha256"],
        }
        config = {"version": 1, "node": "node-a", "failure_domain": "FAULT-DOMAIN-1",
                  "member": {"scope": scope, "host_attempt": 1},
                  "authority": {"epoch": 1, "configuration_id": "a" * 64,
                                "certificate_sha256": inputs["authority_tbca"]["sha256"],
                                "tls_leaf_sha256": "a" * 64},
                  "runtime": runtime, "volume_id": "ocid1.volume.fixture-a",
                  "attachment_id": "ocid1.volumeattachment.fixture-a",
                  "attachment_etag": "fixture-attachment-a", "source_digest": "a" * 64,
                  "collection_id": "21212121-2121-2121-2121-212121212121",
                  "schema_generation": 1, "schema_digest": "a" * 64,
                  "document_id": "018f0000-0000-7000-8000-000000000021"}
        with mock.patch.dict(qualify.MEMBER_DIRS, {member: qualify.member_directory(scope, 1)}):
            qualify._valid_config(member, config, inputs)
            for bad_shard in (0, True, -1, 1 << 64):
                with self.subTest(shard_id=bad_shard):
                    changed = {**config, "member": {"scope": {**scope, "shard_id": bad_shard}, "host_attempt": 1}}
                    with self.assertRaisesRegex(qualify.QualificationError, "scope"):
                        qualify._valid_config(member, changed, inputs)
            changed = {**config, "member": {"scope": {**scope, "tenant_id": scope["tenant_id"].upper()},
                                             "host_attempt": 1}}
            with self.assertRaisesRegex(qualify.QualificationError, "scope"):
                qualify._valid_config(member, changed, inputs)
        with self.assertRaisesRegex(qualify.QualificationError, "runtime directory"):
            qualify._valid_config(member, config, inputs)

    def test_rejects_complete_manifest_with_wrong_peer_before_effects(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root)

            def record(name: str) -> dict[str, str]:
                path = directory / name
                path.write_bytes(name.encode())
                if name in {"firecracker", "go_host_test", "tb_server"}:
                    path.chmod(0o700)
                return {"path": str(path), "sha256": qualify.sha256_file(path)}

            common = {name: record(name) for name in qualify.COMMON_INPUTS}
            members = {}
            expected_dirs = {}
            authority = record("authority.tbca")
            for member in ("a", "b"):
                inputs = {name: record(f"{member}-{name}") for name in qualify.MEMBER_INPUTS}
                inputs["authority_tbca"] = authority
                scope = {"cluster_id": "11" * 16, "tenant_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                         "database_id": "22222222-2222-2222-2222-222222222222", "shard_id": 7,
                         "member_id": qualify.MEMBER_IDS[member],
                         "incarnation": ("bb" if member == "a" else "cc") * 16}
                expected_dirs[member] = qualify.member_directory(scope, 1)
                peer = "b" if member == "a" else "a"
                runtime = {"device_path": "/dev/oracleoci/oraclevdb",
                           "mount_path": str(expected_dirs[member] / "volume"),
                           "filesystem_uuid": qualify.VOLUME_UUIDS[member], "filesystem_type": "ext4",
                           "trusted_key_sha256": inputs["trusted_public_key"]["sha256"],
                           "server_certificate_sha256": inputs["server_crt"]["sha256"],
                           "server_private_key_sha256": inputs["server_key"]["sha256"],
                           "client_ca_roots_sha256": inputs["client_ca_pem"]["sha256"],
                           "client_managed_material_manifest_sha256": inputs["client_managed_manifest"]["sha256"],
                           "replication_listen_address": f"{qualify.GUEST_IPS[member]}:7000",
                           "replication_peer_member_id": qualify.MEMBER_IDS[peer],
                           "replication_peer_address": f"{qualify.GUEST_IPS[peer]}:7000",
                           "replication_server_ca_sha256": inputs["server_ca_pem"]["sha256"]}
                config = {"version": 1, "node": "node-" + member,
                          "failure_domain": "FAULT-DOMAIN-1" if member == "a" else "FAULT-DOMAIN-2",
                          "member": {"scope": scope, "host_attempt": 1},
                          "authority": {"epoch": 1, "configuration_id": "a" * 64,
                                        "certificate_sha256": inputs["authority_tbca"]["sha256"],
                                        "tls_leaf_sha256": "a" * 64},
                          "runtime": runtime, "volume_id": f"ocid1.volume.fixture-{member}",
                          "attachment_id": f"ocid1.volumeattachment.fixture-{member}",
                          "attachment_etag": f"fixture-attachment-{member}", "source_digest": "a" * 64,
                          "collection_id": "21212121-2121-2121-2121-212121212121",
                          "schema_generation": 1, "schema_digest": "a" * 64,
                          "document_id": "018f0000-0000-7000-8000-000000000021"}
                members[member] = {"inputs": inputs, "guest_config": config}
            manifest = {"profile": qualify.PROFILE,
                        "source_commits": {"orchestrator": "a" * 40, "terrabase": "b" * 40},
                        "inputs": common, "members": members}
            path = directory / "manifest.json"
            # Keep only the synthetic volume size small; all file/hash checks remain real.
            with (mock.patch.object(qualify, "VOLUME_BYTES", len(b"a-volume_ext4")),
                  mock.patch.dict(qualify.MEMBER_DIRS, expected_dirs)):
                path.write_text(json.dumps(manifest))
                qualify.load_manifest(path)
                members["b"]["guest_config"]["runtime"]["replication_peer_member_id"] = qualify.MEMBER_IDS["b"]
                path.write_text(json.dumps(manifest))
                with mock.patch.object(qualify.subprocess, "run") as run:
                    with self.assertRaisesRegex(qualify.QualificationError, "runtime pins"):
                        qualify.load_manifest(path)
                    run.assert_not_called()


class ResultContractTests(unittest.TestCase):
    def test_requires_exact_non_skipped_go_pass_and_runner_marker(self) -> None:
        output = ("=== RUN   TestManagedMemberFirecrackerSignedServing\n"
                  "TS_MANAGED_MEMBER_PHASE=PASS node=node-a\n"
                  "--- PASS: TestManagedMemberFirecrackerSignedServing (0.01s)\nPASS\n")
        marker = "[  42.1] ts-managed-member-test[100]: TS_MANAGED_MEMBER_QUALIFICATION_RESULT=PASS node=node-a\n"
        qualify.Lab.parse_test_result("a", output, marker)
        for bad_output in (output.replace("--- PASS:", "--- SKIP:"),
                           output.replace("node=node-a", "node=node-b"),
                           output + "--- PASS: TestManagedMemberFirecrackerSignedServing (0.01s)\n"):
            with self.subTest(bad_output=bad_output):
                with self.assertRaises(qualify.QualificationError):
                    qualify.Lab.parse_test_result("a", bad_output, marker)
        with self.assertRaisesRegex(qualify.QualificationError, "terminal"):
            qualify.Lab.parse_test_result("a", output, marker + marker)

    def test_rejects_configured_values_without_native_evidence(self) -> None:
        lab = qualify.Lab.__new__(qualify.Lab)
        evidence = {name: None for name in ("version", "node", "member_id", "process_pid", "process_uid",
                                            "process_gid", "process_cgroup", "memory_max_bytes", "filesystem_uuid",
                                            "mount_id", "claim_sha256", "storage_recovered", "listener_ready", "metrics")}
        with self.assertRaises(qualify.QualificationError):
            lab.validate_evidence("a", evidence)


if __name__ == "__main__":
    unittest.main()
