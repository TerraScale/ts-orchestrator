"""Fail-closed checks for the two-member Firecracker driver contract."""

from __future__ import annotations

import importlib.util
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
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
    def test_managed_host_and_guest_supervisors_keep_tenant_volume_read_boundary(self) -> None:
        setup = qualify.volume_setup_script("a")
        self.assertIn('mkdir -m 0700 "$MOUNT/data" "$MOUNT/replication"', setup)
        self.assertIn('chown 65534:65534 "$MOUNT/data" "$MOUNT/replication"', setup)
        host_unit = (Path(__file__).resolve().parents[3] / "deploy/systemd" /
                     "terrascale-orchestrator-host.service").read_text()
        required = {"CAP_CHOWN", "CAP_KILL", "CAP_SETGID", "CAP_SETUID", "CAP_SETPCAP",
                    "CAP_DAC_READ_SEARCH"}
        for unit in (host_unit, qualify.test_unit()):
            with self.subTest(unit=unit.splitlines()[1]):
                directives = dict(line.split("=", 1) for line in unit.splitlines()
                                  if "=" in line and not line.startswith("#"))
                self.assertEqual(directives["User"], "root")
                self.assertEqual(directives["Group"], "root")
                self.assertEqual(directives["NoNewPrivileges"], "yes")
                self.assertEqual(directives["AmbientCapabilities"], "")
                self.assertEqual(set(directives["CapabilityBoundingSet"].split()), required)

    def test_root_supervisor_needs_read_search_for_tenant_replication_directory(self) -> None:
        if os.geteuid() == 0 or any(shutil.which(command) is None for command in ("sudo", "setpriv")):
            self.skipTest("requires a nonroot host user, passwordless sudo and setpriv")
        try:
            sudo = subprocess.run(["sudo", "-n", "true"], capture_output=True, timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            self.skipTest("passwordless sudo is unavailable")
        if sudo.returncode != 0:
            self.skipTest("passwordless sudo is unavailable")

        with tempfile.TemporaryDirectory() as root:
            base = Path(root)
            base.chmod(0o755)
            replication = base / "replication"
            subprocess.run(["sudo", "-n", "install", "-d", "-o", "65534", "-g", "65534",
                            "-m", "0700", str(replication)], check=True, timeout=10)
            try:
                for bounds, expected_error in (("-dac_override,-dac_read_search", "Permission denied"),
                                               ("-dac_override", "No such file or directory")):
                    with self.subTest(bounds=bounds):
                        result = subprocess.run(
                            ["sudo", "-n", "setpriv", "--nnp", "--bounding-set=" + bounds,
                             "stat", "--", str(replication / "shard")],
                            capture_output=True, text=True, timeout=10,
                            env={**os.environ, "LC_ALL": "C"})
                        self.assertEqual(result.returncode, 1)
                        self.assertIn(expected_error, result.stderr)
            finally:
                subprocess.run(["sudo", "-n", "rm", "-rf", "--", str(replication)],
                               check=True, timeout=10)

    def test_real_managed_material_staging_under_protected_parent(self) -> None:
        if os.geteuid() == 0 or shutil.which("sudo") is None:
            self.skipTest("requires a nonroot host user and passwordless sudo")
        try:
            sudo = subprocess.run(["sudo", "-n", "true"], capture_output=True, timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            self.skipTest("passwordless sudo is unavailable")
        if sudo.returncode != 0:
            self.skipTest("passwordless sudo is unavailable")

        with tempfile.TemporaryDirectory() as root:
            base = Path(root)
            mount = base / "guest-root"
            mount.mkdir()
            logs = base / "logs"
            logs.mkdir()
            inputs = {}
            for key in qualify.MATERIAL:
                source = base / key
                payload = f"pinned-{key}".encode()
                source.write_bytes(payload)
                inputs[key] = {"path": source, "sha256": hashlib.sha256(payload).hexdigest()}
            events = []
            lab = qualify.Lab.__new__(qualify.Lab)
            lab.command_log = qualify.CommandLog(logs)
            lab.note = lambda kind, **fields: events.append((kind, fields))
            try:
                lab.stage_managed_material(mount, "a", inputs)
                commands = [fields for kind, fields in events if kind == "command"]
                self.assertEqual([entry["label"] for entry in commands[:5]],
                                 ["install-dir-ts-managed", "install-dir-" + qualify.MEMBER_DIRS["a"].name,
                                  "install-dir-material", "install-dir-control", "install-dir-volume"])
                material_commands = commands[5:5 + 2 * len(qualify.MATERIAL)]
                for index, filename in enumerate(qualify.MATERIAL.values()):
                    self.assertEqual([entry["label"] for entry in material_commands[2 * index:2 * index + 2]],
                                     ["install-" + filename, "hash-" + filename])
                self.assertEqual([entry["label"] for entry in commands[-6:]],
                                 ["install-dir-volume", "install-dir-control", "install-dir-material",
                                  "install-dir-" + qualify.MEMBER_DIRS["a"].name,
                                  "install-dir-ts-managed", "verify-a-managed-layout"])

                protected = mount / "srv/ts-managed"
                self.assertEqual(protected.stat().st_mode & 0o777, 0o750)
                with self.assertRaises(PermissionError):
                    os.stat(mount / qualify.MEMBER_DIRS["a"].relative_to("/") / "material" /
                            next(iter(qualify.MATERIAL.values())))
                directories = qualify.managed_directories("a")
                material = [qualify.MEMBER_DIRS["a"] / "material" / filename
                            for filename in qualify.MATERIAL.values()]
                output = subprocess.run(
                    ["sudo", "-n", "stat", "-c", "%u:%g:%f", "--",
                     *(str(mount / destination.relative_to("/")) for destination, _ in directories),
                     *(str(mount / destination.relative_to("/")) for destination in material)],
                    capture_output=True, text=True, check=True, timeout=10)
                self.assertEqual(output.stdout.splitlines(),
                                 [f"0:65534:{stat.S_IFDIR | mode:x}" for _, mode in directories] +
                                 [f"0:65534:{stat.S_IFREG | 0o440:x}"] * len(material))
            finally:
                subprocess.run(["sudo", "-n", "rm", "-rf", "--", str(mount)], check=True, timeout=10)

    def test_managed_material_stages_before_protected_parent_lock(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            mount = Path(root)
            member = "a"
            directories = qualify.managed_directories(member)
            for destination, _ in directories:
                (mount / destination.relative_to("/")).mkdir(parents=True, exist_ok=True)
            protected = mount / "srv/ts-managed"
            inputs = {key: {"path": mount / key, "sha256": "a" * 64} for key in qualify.MATERIAL}
            events = []
            bad_stat = False
            lab = qualify.Lab.__new__(qualify.Lab)

            def install_dir(_mount: Path, destination: Path, mode: str, group: str = "root") -> None:
                self.assertEqual(group, "65534")
                events.append(("directory", destination, mode))
                if destination == Path("/srv/ts-managed") and mode == "0750":
                    protected.chmod(0o000)

            def install(_mount: Path, _source: Path, destination: Path, mode: str,
                        group: str = "root") -> None:
                self.assertEqual((mode, group), ("0440", "65534"))
                target = qualify.guest_path(mount, destination)
                target.write_bytes(b"pinned")
                events.append(("material", destination))

            def staged_sha256(_mount: Path, destination: Path) -> str:
                events.append(("hash", destination))
                return "a" * 64

            def run_cmd(label: str, argv: list[str], **kwargs: object) -> str:
                self.assertEqual(label, "verify-a-managed-layout")
                self.assertTrue(kwargs["sudo"])
                self.assertEqual(argv[:4], ["stat", "-c", "%u:%g:%f", "--"])
                self.assertEqual(protected.stat().st_mode & 0o777, 0)
                events.append(("verify",))
                records = []
                for index, _path in enumerate(argv[4:]):
                    directory = index < len(directories)
                    mode = directories[index][1] if directory else 0o440
                    gid = "0" if bad_stat and index == len(directories) else "65534"
                    bits = (stat.S_IFDIR if directory else stat.S_IFREG) | mode
                    records.append(f"0:{gid}:{bits:x}")
                return "\n".join(records) + "\n"

            lab.install_dir = install_dir
            lab.install = install
            lab.staged_sha256 = staged_sha256
            lab.run_cmd = run_cmd
            try:
                lab.stage_managed_material(mount, member, inputs)
                self.assertEqual(events[:len(directories)],
                                 [("directory", destination, "0755") for destination, _ in directories])
                first_lock = next(index for index, event in enumerate(events)
                                  if event[0] == "directory" and event[2] != "0755")
                self.assertEqual(sum(event[0] == "hash" for event in events[:first_lock]), len(qualify.MATERIAL))
                self.assertEqual(events[first_lock:-1],
                                 [("directory", destination, f"{mode:04o}")
                                  for destination, mode in reversed(directories)])
                self.assertEqual(events[-1], ("verify",))
                protected.chmod(0o755)
                bad_stat = True
                with self.assertRaisesRegex(qualify.QualificationError, "unsafe final managed layout"):
                    lab.lock_managed_layout(mount, member, directories)
            finally:
                protected.chmod(0o755)

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
