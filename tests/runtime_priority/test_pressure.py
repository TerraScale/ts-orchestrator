from __future__ import annotations

import contextlib
import copy
import datetime as dt
import hashlib
import io
import json
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

import alpha_adapter
import alpha_runner
import pressure
import qualify


ROOT = Path(__file__).resolve().parent
EXAMPLE = ROOT / "example-dry-run.json"
ZERO_SHA256 = "0" * 64


def timestamp(value: dt.datetime | None = None) -> str:
    value = value or dt.datetime.now(dt.timezone.utc)
    return value.astimezone(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def raw_stat(pid: int, start_time: int) -> str:
    fields = ["S", *(["0"] * 18), str(start_time)]
    return f"{pid} (d15 worker) " + " ".join(fields)


def sealed_json(value: object) -> tuple[str, str]:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"))
    return raw, hashlib.sha256(raw.encode()).hexdigest()


class RuntimePriorityManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest, self.manifest_wire = pressure.load_json(EXAMPLE)
        self.manifest_hash = hashlib.sha256(self.manifest_wire).hexdigest()

    def test_example_is_a_structural_v4_dry_run_and_starts_no_command(self) -> None:
        reasons = pressure.validate_manifest(self.manifest, dry_run=True)
        self.assertIn("OCI owner has not explicitly authorized live pressure", reasons)
        self.assertIn("host_service memory floors are allocations, not measured floors", reasons)
        self.assertTrue(any("operator executable pin" in reason for reason in reasons))

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = pressure.dry_run(self.manifest, self.manifest_hash)
        plan = json.loads(output.getvalue())
        self.assertEqual(status, 0)
        self.assertEqual(plan["schema"], pressure.SCHEMA)
        self.assertEqual(plan["qualification_status"], "UNQUALIFIED")
        self.assertFalse(plan["commands_executed"])
        self.assertFalse(plan["pressure_started"])

    def test_unqualified_run_writes_evidence_without_spawning_adapters(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            evidence_dir = Path(temporary) / "evidence"
            with mock.patch.object(
                pressure.subprocess, "Popen",
                side_effect=AssertionError("unqualified run started an adapter"),
            ):
                with contextlib.redirect_stdout(io.StringIO()):
                    status = pressure.run_qualification(
                        self.manifest, self.manifest_wire, self.manifest_hash, evidence_dir,
                    )
            summary = json.loads((evidence_dir / "summary.json").read_text())
            self.assertEqual(status, 1)
            self.assertEqual(summary["qualification_status"], "UNQUALIFIED")
            self.assertFalse(summary["commands_executed"])
            self.assertFalse(summary["pressure_started"])
            self.assertEqual((evidence_dir / "manifest.json").read_bytes(), self.manifest_wire)
            self.assertTrue((evidence_dir / "checksums.sha256").is_file())

    def test_pressure_resource_and_cpu_quota_bounds_fail_before_transport(self) -> None:
        manifest = copy.deepcopy(self.manifest)
        manifest["pressure"]["memory_bytes"] = 500 * 1024 * 1024
        with self.assertRaisesRegex(pressure.HarnessError, "exceeds the pressure cgroup memory.max"):
            pressure.validate_manifest(manifest, dry_run=True)

        manifest = copy.deepcopy(self.manifest)
        manifest["pressure"]["workload_cgroup"]["cpu_max"] = "75000 100001"
        with self.assertRaisesRegex(pressure.HarnessError, "<quota> 100000"):
            pressure.validate_manifest(manifest, dry_run=True)

    def test_oom_plan_requires_one_page_aligned_native_role_cap_below_signed_cap(self) -> None:
        manifest = copy.deepcopy(self.manifest)
        manifest["pressure"].update({
            "scenario": "terrabase_oom",
            "scenario_event_after_seconds": 30,
            "oom_fault": {"target_memory_max_bytes": 512 * 1024 * 1024,
                           "deadline_seconds": 10},
        })
        manifest["adapter"]["deadlines_seconds"]["kernel_oom_evidence"] = 20
        reasons = pressure.validate_manifest(manifest, dry_run=True)
        self.assertFalse(any("required adapter 'kernel_oom_evidence'" in reason for reason in reasons))

        del manifest["adapter"]["deadlines_seconds"]["kernel_oom_evidence"]
        reasons = pressure.validate_manifest(manifest, dry_run=True)
        self.assertTrue(any("required adapter 'kernel_oom_evidence'" in reason for reason in reasons))
        manifest["adapter"]["deadlines_seconds"]["kernel_oom_evidence"] = 20

        manifest["pressure"]["oom_fault"]["target_memory_max_bytes"] = 1024 * 1024 * 1024
        with self.assertRaisesRegex(pressure.HarnessError, "below the signed TerraBase role cap"):
            pressure.validate_manifest(manifest, dry_run=True)

    @staticmethod
    def write_pinned_file(path: Path, content: bytes, mode: int = 0o600) -> tuple[str, str]:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        path.chmod(mode)
        return str(path), hashlib.sha256(content).hexdigest()

    def fully_pinned_allocation_manifest(self, root: Path) -> dict[str, object]:
        manifest = copy.deepcopy(self.manifest)
        auth = manifest["authorization"]
        auth["live_stress_authorized"] = True
        auth["owner_handoff_path"], auth["owner_handoff_sha256"] = self.write_pinned_file(
            root / "owner-handoff.json", b"owner-authorized qualification handoff\n",
        )
        adapter_path = str(ROOT / "alpha_adapter.py")
        adapter_hash = hashlib.sha256(Path(adapter_path).read_bytes()).hexdigest()
        contract = manifest["adapter_contract"]
        contract.update({"id": "frozen-alpha-d15-test", "frozen": True,
                         "source_path": adapter_path, "source_sha256": adapter_hash})
        adapter = manifest["adapter"]
        adapter.update({"python_path": sys.executable,
                        "python_sha256": hashlib.sha256(Path(sys.executable).read_bytes()).hexdigest(),
                        "source_path": adapter_path, "source_sha256": adapter_hash})
        for scope in pressure.FLOOR_SCOPES:
            evidence = manifest["memory_floor_evidence"][scope]
            evidence["source_path"], evidence["source_sha256"] = self.write_pinned_file(
                root / f"{scope}-allocation.json", json.dumps({"scope": scope, "basis": "allocation"}).encode(),
            )
        for scope, evidence in manifest["controller_memory_floor_evidence"].items():
            evidence["source_path"], evidence["source_sha256"] = self.write_pinned_file(
                root / f"controller-{scope}-allocation.json",
                json.dumps({"guest": "controller", "scope": scope, "basis": "allocation"}).encode(),
            )

        transport = manifest["transport"]
        operator = transport["operator"]
        operator["executable_path"], operator["executable_sha256"] = self.write_pinned_file(
            root / "operator", b"fixture operator\n", 0o700,
        )
        operator["config_path"], operator["config_sha256"] = self.write_pinned_file(
            root / "operator.toml", b"[fixture]\n", 0o600,
        )
        ssh = transport["ssh"]
        ssh["executable_path"], ssh["executable_sha256"] = self.write_pinned_file(
            root / "ssh", b"fixture ssh\n", 0o700,
        )
        for label, target in ssh["targets"].items():
            target["known_hosts_path"], target["known_hosts_sha256"] = self.write_pinned_file(
                root / f"{label}-known-hosts", b"fixture host key\n",
            )
            target["identity_file_path"], _ = self.write_pinned_file(
                root / f"{label}-key", b"fixture private key\n",
            )
        https = transport["https"]
        https["ca_bundle_path"], https["ca_bundle_sha256"] = self.write_pinned_file(
            root / "client-ca.pem", b"fixture CA bundle\n",
        )
        for label in ("source", "peer"):
            https[f"{label}_credential_file"], _ = self.write_pinned_file(
                root / f"{label}-token", b"fixture-token\n",
            )
        runtime = transport["runtime"]
        runtime["stress_launcher_sha256"] = hashlib.sha256((ROOT / "pressure.py").read_bytes()).hexdigest()
        manifest["pressure"]["workload_cgroup"]["io_device"] = "8:1"
        return manifest

    def test_allocated_preview_profile_can_pass_all_non_floor_live_preflights(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest = self.fully_pinned_allocation_manifest(Path(temporary))
            dry_reasons = pressure.validate_manifest(manifest, dry_run=True)
            self.assertEqual(len([reason for reason in dry_reasons if "allocations, not measured" in reason]),
                             len(pressure.FLOOR_SCOPES) + 2)
            runnable_reasons = pressure.validate_manifest(
                manifest, dry_run=True, allow_allocations=True,
            )
            self.assertEqual(runnable_reasons, [])
            pressure.validate_manifest(manifest, dry_run=False, allow_allocations=True)

    def test_allocated_preview_profile_reaches_adapter_preflight_but_never_silently_passes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            manifest = self.fully_pinned_allocation_manifest(Path(temporary))
            manifest_wire = json.dumps(manifest, sort_keys=True).encode()
            manifest_hash = hashlib.sha256(manifest_wire).hexdigest()
            evidence_dir = Path(temporary) / "evidence"
            roles: list[str] = []

            class StopAtFirstAdapter:
                def __init__(self, *_args: object) -> None:
                    self.harness_sha256 = "a" * 64
                    self.run_id = "allocation-preflight-test"
                    self.results = []
                    self.memory_usage_samples = []
                    self.pressure_completed = False
                    self.failure_observed = False
                    self.recovery_observed = False
                    self.oom_observed = False
                    self.oom_restore_intent = None
                    self.oom_restore_cleanup_verified = False
                    self.oom_restore_unresolved_reason = None

                def call(self, role: str, *_args: object, **_kwargs: object) -> None:
                    roles.append(role)
                    raise pressure.HarnessError("test stop after run preflight")

            with (mock.patch.object(alpha_runner, "AdapterRunner", StopAtFirstAdapter),
                  contextlib.redirect_stdout(io.StringIO())):
                status = alpha_runner.run_qualification(manifest, manifest_wire, manifest_hash, evidence_dir)
            summary = json.loads((evidence_dir / "summary.json").read_text())
            self.assertEqual(roles, ["target_identity"])
            self.assertEqual(status, 1)
            self.assertEqual(summary["qualification_status"], "FAIL")
            self.assertFalse(summary["pressure_started"])
            self.assertEqual(summary["memory_usage_sampling"]["floor_basis_by_scope"], {
                scope: "allocation" for scope in pressure.FLOOR_SCOPES
            })

    def test_allocation_origin_only_passes_after_pressure_recovery_and_samples(self) -> None:
        complete_phases = {f"{role}:{phase}" for role in ("host", "controller")
                           for phase in ("before", "during", "after")}
        status, reasons = alpha_runner.evaluate_run_status(
            [], pressure_started=True, pressure_completed=True,
            scenario="terrabase_oom", recovery_observed=True,
            memory_sample_phases=complete_phases,
        )
        self.assertEqual((status, reasons), ("PASS", []))

        incomplete, reasons = alpha_runner.evaluate_run_status(
            [], pressure_started=True, pressure_completed=False,
            scenario="terrabase_oom", recovery_observed=True,
            memory_sample_phases=complete_phases,
        )
        self.assertEqual(incomplete, "FAIL")
        self.assertIn("full configured duration", reasons[0])

        incomplete, reasons = alpha_runner.evaluate_run_status(
            [], pressure_started=True, pressure_completed=True,
            scenario="terrabase_oom", recovery_observed=False,
            memory_sample_phases=complete_phases,
        )
        self.assertEqual(incomplete, "FAIL")
        self.assertIn("recovery evidence", reasons[0])

        incomplete, reasons = alpha_runner.evaluate_run_status(
            [], pressure_started=True, pressure_completed=True,
            scenario="management_stability", recovery_observed=False,
            memory_sample_phases=complete_phases - {"controller:before"},
        )
        self.assertEqual(incomplete, "UNQUALIFIED")
        self.assertIn("before", reasons[0])


class MemoryUsageSampleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest, _ = pressure.load_json(EXAMPLE)
        self.identity = self.manifest["identity"]
        self.boot_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        self.started = dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=2)
        self.finished = dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=1)
        self.host_cgroup = "/sys/fs/cgroup/system.slice/terrascale-orchestrator-host.service"
        self.controller_cgroup = "/sys/fs/cgroup/system.slice/terrascale-orchestrator-controller.service"

    @staticmethod
    def seal(sample: dict[str, object]) -> dict[str, object]:
        sample.pop("sample_sha256", None)
        sample["sample_sha256"] = hashlib.sha256(pressure.canonical_json_bytes(sample)).hexdigest()
        return sample

    def sample(self) -> dict[str, object]:
        scopes = {}
        paths = {
            "host_service": (self.host_cgroup, 101),
            "system_slice": ("/sys/fs/cgroup/system.slice", 100),
        }
        for name, (path, inode) in paths.items():
            stat_raw = "anon 10\nfile 20\n"
            scopes[name] = {
                "cgroup_path": path, "cgroup_inode": inode,
                "memory_current_raw": "30\n", "memory_current_bytes": 30,
                "memory_peak_raw": "40\n", "memory_peak_bytes": 40,
                "memory_stat_raw": stat_raw,
                "memory_stat_sha256": hashlib.sha256(stat_raw.encode()).hexdigest(),
            }
        sample: dict[str, object] = {
            "schema": pressure.MEMORY_USAGE_SAMPLE_SCHEMA,
            "guest_role": "host",
            "oci_instance_id": self.identity["oci_instance_id"],
            **{key: self.identity[key] for key in ("image_id", "artifact_id", "config_id", "profile_id")},
            "host_boot_id": self.boot_id, "kernel_release": "6.8.0-test",
            "systemd_version": "systemd 255 (test)",
            "started_at_utc": timestamp(self.started), "finished_at_utc": timestamp(self.finished),
            "scopes": scopes,
            "system_slice_direct_child_cgroups": [
                "terrascale-orchestrator-controller.service",
                "terrascale-orchestrator-host.service",
            ],
        }
        return self.seal(sample)

    def validate(self, sample: object) -> dict[str, object]:
        return pressure.validate_memory_usage_sample(
            sample, identity=self.identity, guest_role="host",
            expected_service_cgroup=self.host_cgroup, expected_boot_id=self.boot_id,
            expected_systemd_version="systemd 255 (test)",
            not_before=self.started - dt.timedelta(seconds=1),
            not_after=self.finished + dt.timedelta(seconds=1),
        )

    def test_schema_hash_scopes_and_identity_are_validated(self) -> None:
        sample = self.sample()
        self.assertEqual(self.validate(sample)["sample_sha256"], sample["sample_sha256"])

        for key, value in (("oci_instance_id", "ocid1.instance.oc1.test-other-instance"),
                           ("image_id", "ocid1.image.oc1.test-other-image"),
                           ("artifact_id", "other-artifact"),
                           ("config_id", "other-config"),
                           ("profile_id", "preview-other-profile"),
                           ("host_boot_id", "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")):
            changed = copy.deepcopy(sample)
            changed[key] = value
            self.seal(changed)
            with self.subTest(identity_key=key), self.assertRaises(pressure.HarnessError):
                self.validate(changed)

        changed = copy.deepcopy(sample)
        changed["scopes"]["host_service"]["cgroup_path"] = "/sys/fs/cgroup/user.slice/host.service"
        self.seal(changed)
        with self.assertRaisesRegex(pressure.HarnessError, "exact unit scope"):
            self.validate(changed)

    def test_controller_usage_sample_requires_its_own_identity_and_scope(self) -> None:
        sample = self.sample()
        controller_identity = self.manifest["controller_identity"]
        sample.update({key: controller_identity[key] for key in (
            "oci_instance_id", "image_id", "artifact_id", "config_id", "profile_id",
        )})
        sample["guest_role"] = "controller"
        sample["scopes"]["controller_service"] = sample["scopes"].pop("host_service")
        sample["scopes"]["controller_service"]["cgroup_path"] = self.controller_cgroup
        self.seal(sample)
        kwargs = dict(identity=controller_identity, guest_role="controller",
                      expected_service_cgroup=self.controller_cgroup,
                      expected_boot_id=self.boot_id,
                      expected_systemd_version="systemd 255 (test)",
                      not_before=self.started - dt.timedelta(seconds=1),
                      not_after=self.finished + dt.timedelta(seconds=1))
        self.assertEqual(pressure.validate_memory_usage_sample(sample, **kwargs), sample)
        sample["oci_instance_id"] = self.identity["oci_instance_id"]
        self.seal(sample)
        with self.assertRaisesRegex(pressure.HarnessError, "oci_instance_id"):
            pressure.validate_memory_usage_sample(sample, **kwargs)

    def test_stale_or_malformed_raw_usage_is_rejected_even_with_resealed_hashes(self) -> None:
        changed = copy.deepcopy(self.sample())
        old = dt.datetime(2020, 1, 1, tzinfo=dt.timezone.utc)
        changed["started_at_utc"] = timestamp(old)
        changed["finished_at_utc"] = timestamp(old + dt.timedelta(seconds=1))
        self.seal(changed)
        with self.assertRaisesRegex(pressure.HarnessError, "stale"):
            self.validate(changed)

        changed = copy.deepcopy(self.sample())
        scope = changed["scopes"]["host_service"]
        scope["memory_stat_raw"] = "anon 10\nanon 20\n"
        scope["memory_stat_sha256"] = hashlib.sha256(scope["memory_stat_raw"].encode()).hexdigest()
        self.seal(changed)
        with self.assertRaisesRegex(pressure.HarnessError, "repeats key"):
            self.validate(changed)

        changed = copy.deepcopy(self.sample())
        scope = changed["scopes"]["host_service"]
        scope["memory_stat_raw"] = "anon 1\n" * (
            pressure.MAX_MEMORY_STAT_BYTES // len("anon 1\n") + 1
        )
        scope["memory_stat_sha256"] = hashlib.sha256(scope["memory_stat_raw"].encode()).hexdigest()
        self.seal(changed)
        with self.assertRaisesRegex(pressure.HarnessError, "fixed evidence bound"):
            self.validate(changed)

        changed = copy.deepcopy(self.sample())
        scope = changed["scopes"]["host_service"]
        oversized_counter = "9" * pressure.MAX_MEMORY_COUNTER_BYTES + "\n"
        counter_value = int(oversized_counter.strip())
        scope["memory_current_raw"] = oversized_counter
        scope["memory_current_bytes"] = counter_value
        scope["memory_peak_raw"] = oversized_counter
        scope["memory_peak_bytes"] = counter_value
        self.seal(changed)
        with self.assertRaisesRegex(pressure.HarnessError, "fixed evidence bound"):
            self.validate(changed)

        changed = copy.deepcopy(self.sample())
        changed["system_slice_direct_child_cgroups"] = [f"child-{index:03d}" for index in range(257)]
        self.seal(changed)
        with self.assertRaisesRegex(pressure.HarnessError, "fixed evidence bound"):
            self.validate(changed)

        changed = copy.deepcopy(self.sample())
        changed["system_slice_direct_child_cgroups"] = ["x" * 16385]
        self.seal(changed)
        with self.assertRaisesRegex(pressure.HarnessError, "fixed evidence bound"):
            self.validate(changed)

        changed = copy.deepcopy(self.sample())
        changed["sample_sha256"] = "0" * 64
        with self.assertRaisesRegex(pressure.HarnessError, "sample hash"):
            self.validate(changed)

    def test_alpha_runner_retains_only_usage_samples_bound_to_current_source_identity(self) -> None:
        manifest, _ = pressure.load_json(EXAMPLE)
        runner = alpha_runner.AdapterRunner(manifest, "a" * 64, Path("/unused/evidence"))
        role_path = "/system.slice/terrascale-orchestrator-host.service/supervisor/runner/terrabase"
        runner.host_snapshot = {"members": {"source": {
            "host_boot_id": self.boot_id,
            "managed_identity": {"pid": 77, "cgroup": role_path},
        }}}
        runner.service_snapshot = {alpha_runner.SOURCE_UNIT: {
            "main_pid": 70, "process_start": "700",
            "control_group": "/system.slice/terrascale-orchestrator-host.service",
            "host_boot_id": self.boot_id,
        }}
        sample = self.sample()
        summary = {
            "status": "PASS", "guest_role": "host", "qualifier_sha256": "1" * 64,
            "oci_instance_id": self.identity["oci_instance_id"],
            "image_id": self.identity["image_id"],
            "unit_sha256": {
                alpha_runner.SOURCE_UNIT: "2" * 64,
            },
            "systemd_version": "systemd 255 (test)",
            "artifact_id": self.identity["artifact_id"], "config_id": self.identity["config_id"],
            "profile_id": self.identity["profile_id"],
            "memory_profile": {
                "host_memory_min_bytes": manifest["qualification"]["expected_memory_min_bytes"],
                "host_memory_low_bytes": manifest["qualification"]["expected_memory_low_bytes"],
                "system_slice_memory_min_bytes": manifest["qualification"]["expected_system_slice_memory_min_bytes"],
                "system_slice_memory_low_bytes": manifest["qualification"]["expected_system_slice_memory_low_bytes"],
                "system_reserve_bytes": manifest["qualification"]["system_reserve_bytes"],
                "allocatable_memory_bytes": manifest["qualification"]["allocatable_memory_bytes"],
            },
            "processes": {"host_supervisor": {"pid": 70, "process_start_time": "700"},
                          "terrabase": {"pid": 77, "cgroup": role_path}},
            "cgroups": {
                "host_service": self.host_cgroup,
                "native_runner": "/sys/fs/cgroup/system.slice/terrascale-orchestrator-host.service/supervisor/runner",
                "roles": {"terrabase": {"memory": {
                    "memory_max": str(manifest["qualification"]["database_memory_max_bytes"]),
                }}},
            },
            "memory_usage_sample": sample,
            "started_at_utc": timestamp(self.started - dt.timedelta(milliseconds=100)),
            "finished_at_utc": timestamp(self.finished + dt.timedelta(milliseconds=100)),
        }
        summary_wire = json.dumps(summary, sort_keys=True, indent=2) + "\n"
        commands = "$ systemctl show\n"
        request = {
            "request_id": "memory-sample-request", "guest_role": "host",
            "sent_at_utc": timestamp(self.started - dt.timedelta(seconds=1)),
        }
        evidence = {
            "summary": summary,
            "probe_evidence": {
                "fresh_for_request_id": request["request_id"],
                "summary_sha256": hashlib.sha256(summary_wire.encode()).hexdigest(),
                "commands_log": commands,
                "commands_sha256": hashlib.sha256(commands.encode()).hexdigest(),
            },
        }
        runner._validate_qualifier(evidence, request, timestamp(), "before")
        self.assertEqual(runner.memory_usage_samples, [{
            "phase": "before", "guest_role": "host", "request_id": "memory-sample-request",
            "sample_sha256": sample["sample_sha256"],
        }])

        wrong = copy.deepcopy(evidence)
        wrong["summary"]["memory_usage_sample"]["profile_id"] = "wrong-profile"
        wrong["summary"]["memory_usage_sample"]["sample_sha256"] = hashlib.sha256(
            pressure.canonical_json_bytes({
                key: value for key, value in wrong["summary"]["memory_usage_sample"].items()
                if key != "sample_sha256"
            })
        ).hexdigest()
        wrong["probe_evidence"]["summary_sha256"] = hashlib.sha256(
            (json.dumps(wrong["summary"], sort_keys=True, indent=2) + "\n").encode()
        ).hexdigest()
        with self.assertRaisesRegex(pressure.HarnessError, "profile_id differs"):
            runner._validate_qualifier(wrong, request, timestamp(), "during")
        self.assertEqual(len(runner.memory_usage_samples), 1)

    def test_packaged_qualifier_emits_raw_identity_bound_cgroup_samples(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "cgroup"
            system_slice = root / "system.slice"
            host = system_slice / "terrascale-orchestrator-host.service"
            controller = system_slice / "terrascale-orchestrator-controller.service"
            for path in (host, controller):
                path.mkdir(parents=True)
                (path / "memory.current").write_text("123\n")
                (path / "memory.peak").write_text("456\n")
                (path / "memory.stat").write_text("anon 12\nfile 34\n")
            (system_slice / "memory.current").write_text("789\n")
            (system_slice / "memory.peak").write_text("900\n")
            (system_slice / "memory.stat").write_text("anon 56\nfile 78\n")
            proc = Path(temporary) / "proc"
            (proc / "sys/kernel/random").mkdir(parents=True)
            (proc / "sys/kernel/random/boot_id").write_text(self.boot_id + "\n")
            args = mock.Mock(
                oci_instance_id=self.identity["oci_instance_id"],
                image_id=self.identity["image_id"], artifact_id=self.identity["artifact_id"],
                config_id=self.identity["config_id"], profile_id=self.identity["profile_id"],
                role="host",
            )
            probe = qualify.Probe(args)
            with (mock.patch.object(qualify, "CGROUP_ROOT", root),
                  mock.patch.object(qualify, "PROC_ROOT", proc),
                  mock.patch.object(pressure, "CGROUP_ROOT", root)):
                sample = probe.memory_usage_sample({
                    "host_service": host, "system_slice": system_slice,
                }, "systemd 255 (test)")
                validated = pressure.validate_memory_usage_sample(
                    sample, identity=self.identity, guest_role="host",
                    expected_service_cgroup=str(host), expected_boot_id=self.boot_id,
                    expected_systemd_version="systemd 255 (test)",
                    not_before=pressure.parse_timestamp(sample["started_at_utc"], "sample started_at"),
                    not_after=pressure.parse_timestamp(sample["finished_at_utc"], "sample finished_at"),
                )
            self.assertEqual(validated["scopes"]["host_service"]["memory_current_raw"], "123\n")
            self.assertEqual(validated["scopes"]["system_slice"]["memory_peak_bytes"], 900)
            self.assertIn(host.name, validated["system_slice_direct_child_cgroups"])

    def test_packaged_qualifier_stops_at_the_child_cgroup_evidence_bound(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "cgroup"
            system_slice = root / "system.slice"
            host = system_slice / "terrascale-orchestrator-host.service"
            controller = system_slice / "terrascale-orchestrator-controller.service"
            for path in (host, controller):
                path.mkdir(parents=True)
                (path / "memory.current").write_text("123\n")
                (path / "memory.peak").write_text("456\n")
                (path / "memory.stat").write_text("anon 12\nfile 34\n")
            for index in range(300):
                (system_slice / f"child-{index:03d}.scope").mkdir()
            (system_slice / "memory.current").write_text("789\n")
            (system_slice / "memory.peak").write_text("900\n")
            (system_slice / "memory.stat").write_text("anon 56\nfile 78\n")
            proc = Path(temporary) / "proc"
            (proc / "sys/kernel/random").mkdir(parents=True)
            (proc / "sys/kernel/random/boot_id").write_text(self.boot_id + "\n")
            args = mock.Mock(
                oci_instance_id=self.identity["oci_instance_id"],
                image_id=self.identity["image_id"], artifact_id=self.identity["artifact_id"],
                config_id=self.identity["config_id"], profile_id=self.identity["profile_id"],
                role="host",
            )
            probe = qualify.Probe(args)
            original_iterdir = Path.iterdir
            visited: list[Path] = []

            def tracked_iterdir(path: Path):
                if path == system_slice:
                    for child in original_iterdir(path):
                        visited.append(child)
                        yield child
                else:
                    yield from original_iterdir(path)

            with (mock.patch.object(qualify, "CGROUP_ROOT", root),
                  mock.patch.object(qualify, "PROC_ROOT", proc),
                  mock.patch.object(Path, "iterdir", tracked_iterdir)):
                with self.assertRaisesRegex(qualify.QualificationError, "evidence bound"):
                    probe.memory_usage_sample({
                        "host_service": host, "system_slice": system_slice,
                    }, "systemd 255 (test)")
            self.assertLess(len(visited), 303)

    def test_packaged_qualifier_rejects_cgroup_replacement_during_capture(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "cgroup"
            system_slice = root / "system.slice"
            host = system_slice / "terrascale-orchestrator-host.service"
            controller = system_slice / "terrascale-orchestrator-controller.service"
            for path in (host, controller):
                path.mkdir(parents=True)
                (path / "memory.current").write_text("123\n")
                (path / "memory.peak").write_text("456\n")
                (path / "memory.stat").write_text("anon 12\nfile 34\n")
            proc = Path(temporary) / "proc"
            (proc / "sys/kernel/random").mkdir(parents=True)
            (proc / "sys/kernel/random/boot_id").write_text(self.boot_id + "\n")
            args = mock.Mock(
                oci_instance_id=self.identity["oci_instance_id"],
                image_id=self.identity["image_id"], artifact_id=self.identity["artifact_id"],
                config_id=self.identity["config_id"], profile_id=self.identity["profile_id"],
                role="host",
            )
            probe = qualify.Probe(args)
            original_open = os.open
            replaced = False

            def replace_after_open(path: object, flags: int, *args: object, **kwargs: object) -> int:
                nonlocal replaced
                fd = original_open(path, flags, *args, **kwargs)
                if (not replaced and isinstance(path, Path) and path == host and
                        flags & os.O_DIRECTORY):
                    host.rename(system_slice / "replaced-host.service")
                    host.mkdir()
                    replaced = True
                return fd

            with (mock.patch.object(qualify, "CGROUP_ROOT", root),
                  mock.patch.object(qualify, "PROC_ROOT", proc),
                  mock.patch.object(qualify.os, "open", replace_after_open)):
                with self.assertRaisesRegex(qualify.QualificationError, "changed before capture"):
                    probe.memory_usage_sample({
                        "host_service": host, "system_slice": system_slice,
                    }, "systemd 255 (test)")
            self.assertTrue(replaced)


class AlphaTransportPinTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest, _ = pressure.load_json(EXAMPLE)

    @staticmethod
    def write_file(path: Path, content: bytes, mode: int = 0o600) -> tuple[str, str]:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        path.chmod(mode)
        return str(path), hashlib.sha256(content).hexdigest()

    def test_transport_pins_pass_only_for_the_actual_files_and_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            transport = self.manifest["transport"]
            transport["operator"]["executable_path"], transport["operator"]["executable_sha256"] = self.write_file(
                root / "terrascale", b"operator fixture", 0o700,
            )
            transport["operator"]["config_path"], transport["operator"]["config_sha256"] = self.write_file(
                root / "operator.toml", b"[fixture]\n", 0o600,
            )
            transport["ssh"]["executable_path"], transport["ssh"]["executable_sha256"] = self.write_file(
                root / "ssh", b"ssh fixture", 0o700,
            )
            for label, target in transport["ssh"]["targets"].items():
                target["known_hosts_path"], target["known_hosts_sha256"] = self.write_file(
                    root / f"{label}-known-hosts", b"fixture host key\n",
                )
                target["identity_file_path"], _ = self.write_file(
                    root / f"{label}-key", b"fixture private key", 0o600,
                )
            https = transport["https"]
            https["ca_bundle_path"], https["ca_bundle_sha256"] = self.write_file(
                root / "ca.pem", b"fixture CA bundle",
            )
            for label in ("source", "peer"):
                https[f"{label}_credential_file"], _ = self.write_file(
                    root / f"{label}-token", b"fixture-token", 0o600,
                )

            request = {
                "transport": transport,
                "adapter_source_path": str(ROOT / "alpha_adapter.py"),
                "adapter_source_sha256": hashlib.sha256((ROOT / "alpha_adapter.py").read_bytes()).hexdigest(),
            }
            alpha_adapter._verify_transport(request)

            https["ca_bundle_path"] = str(root / "missing-ca.pem")
            with self.assertRaisesRegex(pressure.HarnessError, "TLS CA bundle pinned source file is unavailable"):
                alpha_adapter._verify_transport(request)

    def test_embedded_remote_dispatcher_compiles_offline(self) -> None:
        compile(alpha_adapter.REMOTE_ACTIONS, "<alpha remote action>", "exec")

    def test_https_leaf_pin_is_checked_before_credentials_or_request_body(self) -> None:
        class FakeTLSocket:
            def getpeercert(self, *, binary_form: bool) -> bytes:
                self.assert_binary_form = binary_form
                return b"CA-valid but not the pinned leaf"

        class FakeHTTPSConnection:
            def __init__(self, *_args: object, **_kwargs: object) -> None:
                self.sock: FakeTLSocket | None = None
                self.request_calls: list[tuple[object, ...]] = []
                self.events: list[str] = []

            def connect(self) -> None:
                self.events.append("connect")
                self.sock = FakeTLSocket()

            def request(self, *args: object, **kwargs: object) -> None:
                self.events.append("request")
                self.request_calls.append((args, kwargs))

            def close(self) -> None:
                self.events.append("close")

        connection = FakeHTTPSConnection()
        request = {
            "transport": {"https": {
                "source_base_url": "https://source.example.test",
                "ca_bundle_path": "/pinned/ca.pem",
                "source_credential_file": "/private/source-token",
            }},
            "deadline_seconds": 10,
            "managed_member": {"source": {"authority": {"tls_leaf_sha256": "0" * 64}}},
        }
        with (mock.patch.object(alpha_adapter.http.client, "HTTPSConnection", return_value=connection),
              mock.patch.object(alpha_adapter, "_credential_token") as credential,
              mock.patch.object(alpha_adapter.ssl, "create_default_context") as create_context):
            create_context.return_value = mock.Mock()
            with self.assertRaisesRegex(pressure.HarnessError, "peer certificate differs"):
                alpha_adapter._https_request(
                    request, "source", "POST", "/transactions", b"sensitive transaction body",
                )

        self.assertEqual(connection.events, ["connect", "close"])
        self.assertEqual(connection.request_calls, [])
        credential.assert_not_called()
        self.assertTrue(connection.sock.assert_binary_form)

    def test_remote_terrabase_sigkill_rejects_changed_role_before_os_kill(self) -> None:
        native = "/sys/fs/cgroup/system.slice/terrascale-host.service/supervisor/runner"
        database = native + "/terrabase"
        changed_cgroup = native + "/another-role"
        pid = 77
        target = {
            "kind": "terrabase", "pid": pid, "process_start": "9001",
            "process_nonce": "b" * 32, "cgroup": changed_cgroup,
            "host_boot_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        }
        witness = {
            "stat_raw": raw_stat(pid, 9001),
            "cgroup_raw": f"0::{changed_cgroup}\n",
            "host_boot_id": target["host_boot_id"],
        }
        request = {
            "transport": {"runtime": {}},
            "target_process": target,
            "native_runner_cgroup_path": native,
            "protected_database_cgroup_path": database,
            "remote_payload": {"witness": witness},
        }
        stubs = '''\ndef safe_cgroup(report_path):\n    return Path("/sys/fs/cgroup") / report_path.lstrip("/")\ndef safe_cgroup_absolute(path):\n    return Path(path)\ndef process_witness(pid):\n    return payload["witness"]\n'''
        script = alpha_adapter.REMOTE_ACTIONS.replace(
            "\ntry:\n    main()\n",
            stubs + "\ntry:\n    main()\n",
            1,
        )
        self.assertNotEqual(script, alpha_adapter.REMOTE_ACTIONS)
        stderr = io.StringIO()
        with (mock.patch.object(alpha_adapter.sys, "stdin", io.StringIO(json.dumps(request))),
              mock.patch.object(alpha_adapter.sys, "argv", ["remote", "failure_inject"]),
              mock.patch.object(alpha_adapter.os, "kill") as kill,
              contextlib.redirect_stderr(stderr)):
            with self.assertRaises(SystemExit) as exit_result:
                exec(script, {"__name__": "__main__"})
        self.assertEqual(exit_result.exception.code, 2)
        self.assertIn("RuntimeError", stderr.getvalue())
        kill.assert_not_called()

    def test_cleanup_verifies_pending_oom_intent_without_receipt_and_rejects_unknown_cap(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "cgroup-root"
            native = root / "system.slice" / "terrascale-host.service" / "supervisor" / "runner"
            database = native / "terrabase"
            database.mkdir(parents=True)
            memory_max = database / "memory.max"
            memory_max.write_text("700\n")
            native_path = "/sys/fs/cgroup/system.slice/terrascale-host.service/supervisor/runner"
            database_path = native_path + "/terrabase"
            report_path = "/system.slice/terrascale-host.service/supervisor/runner/terrabase"
            target = {
                "kind": "terrabase", "pid": 77, "process_start": "9001",
                "process_nonce": "b" * 32, "cgroup": report_path,
                "host_boot_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            }
            cap = 1000
            temporary_cap = 500
            intent = {
                "target": target,
                "native_runner_cgroup_path": native_path,
                "database_cgroup_path": database_path,
                "cgroup_inode": database.stat().st_ino,
                "prior_memory_max_bytes": cap,
                "temporary_memory_max_bytes": temporary_cap,
            }
            request = {
                "transport": {"runtime": {}}, "run_id": "cleanup-test",
                "pressure": {"io_directory": str(Path(temporary) / "io")},
                "qualification": {"database_memory_max_bytes": cap},
                "oom_restore_intent": intent,
                "native_runner_cgroup_path": native_path,
                "protected_database_cgroup_path": database_path,
                "remote_payload": {"fake_cgroup_root": str(root),
                                   "pressure_path": str(Path(temporary) / "pressure.scope")},
            }
            stubs = '''\ndef expected_scope_path():\n    return Path(payload["pressure_path"])\ndef native_role_cgroups(target,native_path,database_path):\n    root=Path(payload["fake_cgroup_root"])\n    native=root/native_path.removeprefix("/sys/fs/cgroup/")\n    database=root/database_path.removeprefix("/sys/fs/cgroup/")\n    reported=root/target["cgroup"].lstrip("/")\n    if reported!=database or native not in reported.parents or len(reported.relative_to(native).parts)!=1:\n        raise RuntimeError("wrong native role")\n    return reported,native,database\ndef process_witness(pid):\n    raise FileNotFoundError(pid)\n'''
            script = alpha_adapter.REMOTE_ACTIONS.replace(
                "\ntry:\n    main()\n", stubs + "\ntry:\n    main()\n", 1,
            )
            output = io.StringIO()
            with (mock.patch.object(alpha_adapter.sys, "stdin", io.StringIO(json.dumps(request))),
                  mock.patch.object(alpha_adapter.sys, "stdout", output),
                  mock.patch.object(alpha_adapter.sys, "argv", ["remote", "cleanup_verify"])):
                exec(script, {"__name__": "__main__"})

            remote = json.loads(output.getvalue())
            cleanup = remote["cleanup"]
            self.assertFalse(cleanup["oom_restore_verified"])
            self.assertIn("unknown cap", cleanup["oom_restore_unresolved_reason"])
            self.assertEqual(memory_max.read_text(), "700\n")

            runner = alpha_runner.AdapterRunner(self.manifest, "a" * 64, Path("/unused/evidence"))
            runner.qualification["database_memory_max_bytes"] = cap
            runner.oom_restore_intent = intent
            response = {"observed_at_utc": timestamp(), "evidence": remote}
            with self.assertRaisesRegex(pressure.HarnessError, "restore obligation unresolved"):
                runner._validate_role("cleanup_verify", "cleanup", {}, response)
            self.assertFalse(runner.oom_restore_cleanup_verified)
            self.assertIsNotNone(runner.oom_restore_unresolved_reason)

            memory_max.write_text(f"{temporary_cap}\n")
            output = io.StringIO()
            with (mock.patch.object(alpha_adapter.sys, "stdin", io.StringIO(json.dumps(request))),
                  mock.patch.object(alpha_adapter.sys, "stdout", output),
                  mock.patch.object(alpha_adapter.sys, "argv", ["remote", "cleanup_verify"])):
                exec(script, {"__name__": "__main__"})
            restored = json.loads(output.getvalue())["cleanup"]
            self.assertTrue(restored["oom_restore_verified"])
            self.assertEqual(memory_max.read_text().strip(), str(cap))
            runner._validate_role(
                "cleanup_verify", "cleanup", {},
                {"observed_at_utc": timestamp(), "evidence": {"cleanup": restored}},
            )
            self.assertTrue(runner.oom_restore_cleanup_verified)

            original = database.with_name("terrabase-original")
            database.rename(original)
            database.mkdir()
            replaced_memory_max = database / "memory.max"
            replaced_memory_max.write_text(f"{temporary_cap}\n")
            self.assertNotEqual(database.stat().st_ino, intent["cgroup_inode"])
            runner.oom_restore_cleanup_verified = False
            runner.oom_restore_unresolved_reason = None
            output = io.StringIO()
            with (mock.patch.object(alpha_adapter.sys, "stdin", io.StringIO(json.dumps(request))),
                  mock.patch.object(alpha_adapter.sys, "stdout", output),
                  mock.patch.object(alpha_adapter.sys, "argv", ["remote", "cleanup_verify"])):
                exec(script, {"__name__": "__main__"})
            replaced = json.loads(output.getvalue())["cleanup"]
            self.assertFalse(replaced["oom_restore_verified"])
            self.assertIn("cgroup identity changed", replaced["oom_restore_unresolved_reason"])
            self.assertEqual(replaced_memory_max.read_text(), f"{temporary_cap}\n")
            with self.assertRaisesRegex(pressure.HarnessError, "restore obligation unresolved"):
                runner._validate_role(
                    "cleanup_verify", "cleanup", {},
                    {"observed_at_utc": timestamp(), "evidence": {"cleanup": replaced}},
                )
            self.assertFalse(runner.oom_restore_cleanup_verified)

            race_root = Path(temporary) / "race-cgroup-root"
            race_native = race_root / "system.slice" / "terrascale-host.service" / "supervisor" / "runner"
            race_database = race_native / "terrabase"
            race_database.mkdir(parents=True)
            (race_database / "memory.max").write_text(f"{temporary_cap}\n")
            race_intent = dict(intent, cgroup_inode=race_database.stat().st_ino)
            race_request = copy.deepcopy(request)
            race_request["oom_restore_intent"] = race_intent
            race_request["remote_payload"].update({
                "fake_cgroup_root": str(race_root), "fake_database_path": str(race_database),
                "temporary_cap": temporary_cap,
            })
            race_stubs = '''\ndef expected_scope_path():\n    return Path(payload["pressure_path"])\ndef native_role_cgroups(target,native_path,database_path):\n    root=Path(payload["fake_cgroup_root"])\n    native=root/native_path.removeprefix("/sys/fs/cgroup/")\n    database=root/database_path.removeprefix("/sys/fs/cgroup/")\n    reported=root/target["cgroup"].lstrip("/")\n    if reported!=database or native not in reported.parents or len(reported.relative_to(native).parts)!=1:\n        raise RuntimeError("wrong native role")\n    return reported,native,database\ndef process_witness(pid):\n    raise FileNotFoundError(pid)\n_real_open=os.open\ndef _open_with_replacement_race(path,flags,mode=0o777,*,dir_fd=None):\n    if path=="memory.max" and flags & os.O_WRONLY and dir_fd is not None:\n        original=Path(payload["fake_database_path"])\n        displaced=original.with_name("terrabase-original")\n        original.rename(displaced)\n        original.mkdir()\n        (original/"memory.max").write_text(str(payload["temporary_cap"]))\n    return _real_open(path,flags,mode,dir_fd=dir_fd)\nos.open=_open_with_replacement_race\n'''
            race_script = alpha_adapter.REMOTE_ACTIONS.replace(
                "\ntry:\n    main()\n", race_stubs + "\ntry:\n    main()\n", 1,
            )
            output = io.StringIO()
            original_open = alpha_adapter.os.open
            try:
                with (mock.patch.object(alpha_adapter.sys, "stdin", io.StringIO(json.dumps(race_request))),
                      mock.patch.object(alpha_adapter.sys, "stdout", output),
                      mock.patch.object(alpha_adapter.sys, "argv", ["remote", "cleanup_verify"])):
                    exec(race_script, {"__name__": "__main__"})
            finally:
                alpha_adapter.os.open = original_open
            raced = json.loads(output.getvalue())["cleanup"]
            self.assertFalse(raced["oom_restore_verified"])
            self.assertIn("exact TerraBase role memory.max restore could not be verified", raced["oom_restore_unresolved_reason"])
            self.assertEqual((race_database / "memory.max").read_text().strip(), str(temporary_cap))
            self.assertEqual((race_database.with_name("terrabase-original") / "memory.max").read_text().strip(), str(cap))

    def test_oom_fault_does_not_lower_a_replacement_cgroup_after_preflight(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "cgroup-root"
            native = root / "system.slice" / "terrascale-host.service" / "supervisor" / "runner"
            database = native / "terrabase"
            database.mkdir(parents=True)
            (database / "memory.max").write_text("1000\n")
            (database / "memory.current").write_text("800\n")
            (database / "cgroup.procs").write_text("77\n")
            native_path = "/sys/fs/cgroup/system.slice/terrascale-host.service/supervisor/runner"
            database_path = native_path + "/terrabase"
            report_path = "/system.slice/terrascale-host.service/supervisor/runner/terrabase"
            target = {
                "kind": "terrabase", "pid": 77, "process_start": "9001",
                "process_nonce": "b" * 32, "cgroup": report_path,
                "host_boot_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            }
            intent = {
                "target": target,
                "native_runner_cgroup_path": native_path,
                "database_cgroup_path": database_path,
                "cgroup_inode": database.stat().st_ino,
                "prior_memory_max_bytes": 1000,
                "temporary_memory_max_bytes": 500,
            }
            request = {
                "transport": {"runtime": {}}, "oom_target": target,
                "native_runner_cgroup_path": native_path,
                "protected_database_cgroup_path": database_path,
                "oom_restore_intent": intent,
                "qualification": {"database_memory_max_bytes": 1000},
                "pressure": {"oom_fault": {"target_memory_max_bytes": 500, "deadline_seconds": 1}},
                "journal_watermark": {"cursor": "before"},
                "remote_payload": {
                    "fake_cgroup_root": str(root), "fake_database_path": str(database),
                    "witness": {
                        "stat_raw": raw_stat(77, 9001),
                        "cgroup_raw": f"0::{report_path}\n",
                        "host_boot_id": target["host_boot_id"],
                    },
                },
            }
            race_stubs = '''\ndef native_role_cgroups(target,native_path,database_path):\n    root=Path(payload["fake_cgroup_root"])\n    native=root/native_path.removeprefix("/sys/fs/cgroup/")\n    database=root/database_path.removeprefix("/sys/fs/cgroup/")\n    reported=root/target["cgroup"].lstrip("/")\n    if reported!=database or native not in reported.parents or len(reported.relative_to(native).parts)!=1:\n        raise RuntimeError("wrong native role")\n    return reported,native,database\ndef process_witness(pid):\n    return payload["witness"]\ndef pressure_module():\n    return None,None\n_real_open=os.open\n_real_write=os.write\ndef _open_with_replacement_race(path,flags,mode=0o777,*,dir_fd=None):\n    if path=="memory.max" and flags & os.O_WRONLY and dir_fd is not None:\n        original=Path(payload["fake_database_path"])\n        displaced=original.with_name("terrabase-original")\n        original.rename(displaced)\n        original.mkdir()\n        (original/"memory.max").write_text("700\\n")\n        (original/"memory.current").write_text("800\\n")\n        (original/"cgroup.procs").write_text("77\\n")\n    return _real_open(path,flags,mode,dir_fd=dir_fd)\nos.open=_open_with_replacement_race\n'''
            script = alpha_adapter.REMOTE_ACTIONS.replace(
                "\ntry:\n    main()\n", race_stubs + "\ntry:\n    main()\n", 1,
            )
            output = io.StringIO()
            stderr = io.StringIO()
            original_open = alpha_adapter.os.open
            try:
                with (mock.patch.object(alpha_adapter.sys, "stdin", io.StringIO(json.dumps(request))),
                      mock.patch.object(alpha_adapter.sys, "stdout", output),
                      mock.patch.object(alpha_adapter.sys, "stderr", stderr),
                      mock.patch.object(alpha_adapter.sys, "argv", ["remote", "oom_fault"])):
                    with self.assertRaises(SystemExit) as exit_result:
                        exec(script, {"__name__": "__main__"})
            finally:
                alpha_adapter.os.open = original_open
            self.assertEqual(exit_result.exception.code, 2)
            self.assertIn("RuntimeError", stderr.getvalue())
            self.assertEqual((database / "memory.max").read_text(), "700\n")
            self.assertEqual((database.with_name("terrabase-original") / "memory.max").read_text(), "1000\n")


class AlphaQualifiedCgroupTests(unittest.TestCase):
    def test_oom_cgroups_must_be_rooted_and_the_database_role_must_be_direct_child(self) -> None:
        root = alpha_runner.CGROUP_ROOT
        native = root / "system.slice" / "terrascale-host.service" / "supervisor" / "terrascale-host-1"
        role, database, role_name = alpha_runner._qualified_role_cgroups(
            str(native), "/system.slice/terrascale-host.service/supervisor/terrascale-host-1/terrabase",
        )
        self.assertEqual(role, native)
        self.assertEqual(database, native / "terrabase")
        self.assertEqual(role_name, "terrabase")

        with self.assertRaisesRegex(pressure.HarnessError, "safely below the cgroup root"):
            alpha_runner._qualified_role_cgroups("/tmp/runner", "/system.slice/terrabase")
        with self.assertRaisesRegex(pressure.HarnessError, "direct native role child"):
            alpha_runner._qualified_role_cgroups(
                str(native), "/system.slice/terrascale-host.service/supervisor/terrascale-host-1/terrabase/nested",
            )
        with self.assertRaisesRegex(pressure.HarnessError, "safe cgroup-root-relative"):
            alpha_runner._qualified_role_cgroups(str(native), "/system.slice/../terrabase")


class AlphaHostAndDatabaseEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest, _ = pressure.load_json(EXAMPLE)

    def report(self, label: str, pid: int, start: int, observed: str) -> tuple[dict[str, object], dict[str, object]]:
        member = self.manifest["managed_member"][label]
        scope = member["scope"]
        authority = member["authority"]
        process_cgroup = f"/terrascale-workload.slice/{label}-runner/terrabase"
        identity = {"pid": pid, "start_nonce": "d" * 32}
        proof = {
            "schema_version": 1,
            "nonce": "e" * 32,
            "process": identity,
            "scope": scope,
            "authority": authority,
            "serving": True,
            "listeners": {"client": True, "replication": True},
            "object": {
                "root_sha256": "1" * 64,
                "target_sha256": "2" * 64,
                "native_commit_seq_at_recovery": 3,
                "inbox_archive_sha256_at_recovery": "3" * 64,
                "local_source_sequence": 4,
                "remote_inbox_durable_sequence": 4,
                "remote_applied_sequence": 4,
            },
            "replication": {
                "local_source_sequence": 4,
                "peer_member_id": self.manifest["managed_member"]["peer"]["scope"]["member_id"],
                "peer_incarnation": self.manifest["managed_member"]["peer"]["scope"]["incarnation"],
                "current_authenticated": True,
                "peer_durable_sequence": 4,
                "peer_applied_sequence": 4,
                "local_inbox_durable_sequence": 4,
                "local_inbox_applied_sequence": 4,
            },
        }
        report = {
            "cell": member["cell"], "node": member["node"],
            "environment": member["environment"], "role": member["role"],
            "observed_at": observed, "generation": 1, "digest": "4" * 64,
            "session_id": "session-" + label, "epoch": 1, "state": "running",
            "managed": {
                "member": {"scope": scope, "host_attempt": 1},
                "authority": authority, "process_pid": pid, "process_start": str(start),
                "process_cgroup": process_cgroup, "process_boot_id": "d" * 32,
                "storage_recovered": True, "listener_ready": True,
                "serving_proof": proof,
            },
        }
        host = {
            "registration": {
                "cell": member["cell"], "node": member["node"],
                "environment": member["environment"], "generation": 1,
                "managed_member": {"scope": scope, "host_attempt": 1},
                "managed_oci": {"instance_id": self.manifest["identity"]["oci_instance_id"]
                                if label == "source" else self.manifest["transport"]["ssh"]["targets"]["peer"]["oci_instance_id"]},
            },
            "session_expires_at": timestamp(dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=2)),
            "reports": [report], "verified": False,
        }
        witness = {
            "pid": pid, "stat_raw": raw_stat(pid, start),
            "cgroup_raw": f"0::{process_cgroup}\n",
            "host_boot_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        }
        return host, witness

    def test_host_status_uses_controller_admitted_read_only_reports_and_raw_process_witnesses(self) -> None:
        observed = timestamp()
        hosts = []
        witnesses = {}
        for offset, label in enumerate(("source", "peer")):
            host, witness = self.report(label, 42 + offset, 1000 + offset, observed)
            hosts.append(host)
            witnesses[label] = witness
        raw, digest = sealed_json(hosts)
        evidence = {"operator_hosts_json": raw, "operator_hosts_sha256": digest,
                    "process_witnesses": witnesses}
        snapshot = alpha_runner.validate_report_evidence(
            evidence, {"pressure": {"scenario": "management_stability"}}, observed,
            self.manifest["managed_member"], {},
        )
        self.assertEqual(snapshot["members"]["source"]["managed_identity"]["pid"], 42)

        hosts[0]["verified"] = True
        raw, digest = sealed_json(hosts)
        evidence.update(operator_hosts_json=raw, operator_hosts_sha256=digest)
        with self.assertRaisesRegex(pressure.HarnessError, "verified must remain false"):
            alpha_runner.validate_report_evidence(
                evidence, {"pressure": {"scenario": "management_stability"}}, observed,
                self.manifest["managed_member"], {},
            )

    def test_host_manager_recovery_allows_only_source_session_advance_with_restart_witness(self) -> None:
        initial_observed = timestamp()
        hosts = []
        witnesses = {}
        for offset, label in enumerate(("source", "peer")):
            host, witness = self.report(label, 52 + offset, 2000 + offset, initial_observed)
            hosts.append(host)
            witnesses[label] = witness
        raw, digest = sealed_json(hosts)
        evidence = {"operator_hosts_json": raw, "operator_hosts_sha256": digest,
                    "process_witnesses": witnesses}
        request = {"pressure": {"scenario": "host_manager_sigkill"}, "phase": "before"}
        baseline = alpha_runner.validate_report_evidence(
            evidence, request, initial_observed, self.manifest["managed_member"], {},
        )

        later = dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=1)
        recovered_observed = timestamp(later)
        recovered_hosts = copy.deepcopy(hosts)
        for host in recovered_hosts:
            host["reports"][0]["observed_at"] = recovered_observed
        recovered_hosts[0]["reports"][0]["session_id"] = "session-source-after-restart"
        recovered_hosts[0]["reports"][0]["epoch"] = 2
        recovered_raw, recovered_digest = sealed_json(recovered_hosts)
        recovered_evidence = {"operator_hosts_json": recovered_raw,
                              "operator_hosts_sha256": recovered_digest,
                              "process_witnesses": witnesses}
        post_recovery = {"pressure": {"scenario": "host_manager_sigkill"},
                         "phase": "post_recovery"}
        accepted = alpha_runner.validate_report_evidence(
            recovered_evidence, post_recovery, recovered_observed,
            self.manifest["managed_member"], baseline["members"],
        )

        runner = alpha_runner.AdapterRunner(self.manifest, "a" * 64, Path("/unused/evidence"))
        runner.pressure["scenario"] = "host_manager_sigkill"
        runner.failure_observed = True
        runner.baseline_services = {
            alpha_runner.SOURCE_UNIT: {"control_group": "/source", "main_pid": 10,
                                       "process_start": "100", "n_restarts": 0},
            alpha_runner.CONTROLLER_UNIT: {"control_group": "/controller", "main_pid": 20,
                                           "process_start": "200", "n_restarts": 0},
        }
        current_services = copy.deepcopy(runner.baseline_services)
        current_services[alpha_runner.SOURCE_UNIT].update(
            main_pid=11, process_start="101", n_restarts=1,
        )
        runner.previous_services = copy.deepcopy(runner.baseline_services)
        runner._compare_services(current_services, "post_recovery")
        changed_controller = copy.deepcopy(current_services)
        changed_controller[alpha_runner.CONTROLLER_UNIT]["main_pid"] += 1
        with self.assertRaisesRegex(pressure.HarnessError, "process identity/restart counter changed"):
            runner._compare_services({alpha_runner.CONTROLLER_UNIT:
                                      changed_controller[alpha_runner.CONTROLLER_UNIT]}, "post_recovery")
        self.assertEqual(accepted["members"]["source"]["epoch"], 2)

        for field, changed in (("session_id", "unexpected-peer-session"), ("epoch", 2)):
            with self.subTest(peer_field=field):
                peer_changed = copy.deepcopy(recovered_hosts)
                peer_changed[1]["reports"][0][field] = changed
                peer_raw, peer_digest = sealed_json(peer_changed)
                peer_evidence = {"operator_hosts_json": peer_raw, "operator_hosts_sha256": peer_digest,
                                 "process_witnesses": witnesses}
                with self.assertRaisesRegex(pressure.HarnessError, "host session identity changed"):
                    alpha_runner.validate_report_evidence(
                        peer_evidence, post_recovery, recovered_observed,
                        self.manifest["managed_member"], baseline["members"],
                    )

    def test_terrabase_sigkill_rejects_report_cgroup_outside_qualified_role(self) -> None:
        self.manifest["pressure"]["scenario"] = "terrabase_process"
        runner = alpha_runner.AdapterRunner(self.manifest, "a" * 64, Path("/unused/evidence"))
        runner.native_runner_path = (
            alpha_runner.CGROUP_ROOT / "system.slice" / "terrascale-host.service" /
            "supervisor" / "terrascale-host-1"
        )
        runner.database_cgroup_path = runner.native_runner_path / "terrabase"
        changed_cgroup = "/" + str((runner.native_runner_path / "another-role").relative_to(
            alpha_runner.CGROUP_ROOT,
        ))
        host_boot_id = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        runner.host_snapshot = {
            "members": {"source": {
                "report_time": dt.datetime.now(dt.timezone.utc),
                "report": {"managed": {
                    "process_pid": 4242, "process_start": "98765",
                    "process_boot_id": "b" * 32, "process_cgroup": changed_cgroup,
                }},
            }},
            "process_witnesses": {"source": {
                "host_boot_id": host_boot_id,
                "stat_raw": raw_stat(4242, 98765),
                "cgroup_raw": f"0::{changed_cgroup}\n",
            }},
        }
        with self.assertRaisesRegex(pressure.HarnessError, "differs from the qualifier-pinned native role cgroup"):
            runner._failure_target()

    def test_live_oci_image_metadata_is_matched_to_controller_host_and_manifest_pins(self) -> None:
        hosts = []
        for label in ("source", "peer"):
            member = self.manifest["managed_member"][label]
            target = self.manifest["transport"]["ssh"]["targets"][label]
            hosts.append({
                "verified": False,
                "registration": {
                    "cell": member["cell"], "node": member["node"],
                    "environment": member["environment"],
                    "managed_member": {"scope": member["scope"], "host_attempt": 1},
                    "managed_oci": {"instance_id": target["oci_instance_id"],
                                    "region": "GRU"},
                },
            })
        raw, digest = sealed_json(hosts)
        runner = alpha_runner.AdapterRunner(self.manifest, "a" * 64, Path("/unused/evidence"))
        request = {"request_id": "fixture-request"}
        response = {
            "observed_at_utc": timestamp(),
            "evidence": {
                "operator_hosts_json": raw,
                "operator_hosts_sha256": digest,
                "architecture_by_member": {"source": "aarch64", "peer": "aarch64", "controller": "aarch64"},
                "controller_oci_metadata": {
                    "instance_id": self.manifest["controller_identity"]["oci_instance_id"],
                    "image_id": self.manifest["controller_identity"]["image_id"],
                    "region": "sa-saopaulo-1", "shape": "VM.Standard.A1.Flex",
                },
                "source_oci_metadata": {
                    "instance_id": self.manifest["identity"]["oci_instance_id"],
                    "image_id": self.manifest["identity"]["image_id"],
                    "region": "sa-saopaulo-1", "shape": "VM.Standard.E5.Flex",
                },
            },
        }
        runner._validate_role("target_identity", "preflight", request, response)

        response["evidence"]["source_oci_metadata"]["image_id"] = "ocid1.image.other-region.not-the-imported-image"
        with self.assertRaisesRegex(pressure.HarnessError, "live OCI metadata"):
            runner._validate_role("target_identity", "preflight", request, response)
        response["evidence"]["source_oci_metadata"]["image_id"] = self.manifest["identity"]["image_id"]
        response["evidence"]["controller_oci_metadata"]["instance_id"] = self.manifest["identity"]["oci_instance_id"]
        with self.assertRaisesRegex(pressure.HarnessError, "pinned controller instance"):
            runner._validate_role("target_identity", "preflight", request, response)

    def test_object_durable_receipt_sequence_is_bound_to_exact_peer_read(self) -> None:
        source_scope = self.manifest["managed_member"]["source"]["scope"]
        document = self.manifest["managed_member"]["document"]
        request = {
            "document_id": "018f0000-0000-7000-8000-000000000006",
            "value": 17,
            "transaction_id": {"expires_at_unix_ms": "1893456000000", "nonce": "f" * 32},
        }
        event = {
            "database": source_scope["database_id"], "shard": str(source_scope["shard_id"]),
            "replica": source_scope["member_id"], "incarnation": source_scope["incarnation"],
            "sequence": "21",
        }
        transaction = {
            "version": 1, "transaction_id": request["transaction_id"],
            "writes": [{
                "collection": document["collection_id"], "document": request["document_id"],
                "schema_generation": str(document["schema_generation"]),
                "schema_digest": document["schema_digest"], "observed": [],
                "value": {"kind": "live", "fields": [{
                    "id": document["field_id"],
                    "value": {"type": "i64", "value": "17"},
                }]},
            }],
        }
        receipt = {"version": 1, "durability": "object_durable",
                   "transaction_id": request["transaction_id"], "event": event,
                   "commit_sequence": "507"}
        point = {"version": 1, "state": "value", "siblings": [{
            "event": event, "kind": "live",
            "schema_generation": str(document["schema_generation"]),
            "schema_digest": document["schema_digest"],
            "fields": [{"id": document["field_id"],
                        "value": {"type": "i64", "value": "17"}}],
        }]}
        transaction_raw, transaction_hash = sealed_json(transaction)
        receipt_raw, receipt_hash = sealed_json(receipt)
        point_raw, point_hash = sealed_json(point)
        evidence = {
            "write_path": (f"/v1/tenants/{source_scope['tenant_id']}/databases/{source_scope['database_id']}"
                           f"/shards/{source_scope['shard_id']}/transactions"),
            "peer_read_path": (f"/v1/tenants/{source_scope['tenant_id']}/databases/{source_scope['database_id']}"
                               f"/shards/{source_scope['shard_id']}/collections/{document['collection_id']}"
                               f"/documents/{request['document_id']}"),
            "document_id": request["document_id"],
            "transaction_request_raw": transaction_raw,
            "transaction_request_sha256": transaction_hash,
            "write_receipt_raw": receipt_raw, "write_receipt_sha256": receipt_hash,
            "peer_read_raw": point_raw, "peer_read_sha256": point_hash,
        }
        accepted = alpha_runner.validate_database_wire(
            evidence, request, self.manifest["managed_member"],
        )
        self.assertEqual(accepted["event_sequence"], 21)
        self.assertEqual(accepted["commit_sequence_opaque"], "507")

        point["siblings"][0]["event"]["sequence"] = "20"
        point_raw, point_hash = sealed_json(point)
        evidence.update(peer_read_raw=point_raw, peer_read_sha256=point_hash)
        with self.assertRaisesRegex(pressure.HarnessError, "does not contain exactly one sibling"):
            alpha_runner.validate_database_wire(evidence, request, self.manifest["managed_member"])


class AlphaPressureAndOomTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest, _ = pressure.load_json(EXAMPLE)
        self.manifest["pressure"]["workload_cgroup"]["io_device"] = "253:0"
        self.runner = alpha_runner.AdapterRunner(self.manifest, "a" * 64, Path("/unused/evidence"))

    def pressure_observation(self) -> tuple[dict[str, object], dict[str, object], str]:
        now = dt.datetime.now(dt.timezone.utc)
        started = now - dt.timedelta(seconds=2)
        unit = f"terrascale-d15-{self.runner.run_id}.scope"
        path = f"/sys/fs/cgroup/terrascale-workload.slice/{unit}"
        group = f"/terrascale-workload.slice/{unit}"
        parent_group = "/terrascale-workload.slice"
        roles = [(41, "pressure_runner", 901), (42, "memory_worker", 902),
                 (43, "cpu_worker", 903), (44, "io_worker", 904)]
        processes = [{
            "pid": pid, "process_start_time": str(start_time), "role": role,
            "process_stat_raw": raw_stat(pid, start_time),
            "process_cgroup_raw": f"0::{group}\n",
        } for pid, role, start_time in roles]
        pids = [row[0] for row in roles]
        worker_pids = [42, 43, 44]
        state = {
            "schema": pressure.PRESSURE_WORKER_STATE_SCHEMA,
            "run_id": self.runner.run_id,
            "status": "RUNNING",
            "started_at_utc": timestamp(started),
            "started_monotonic_ns": 100,
            "observed_at_utc": timestamp(now - dt.timedelta(milliseconds=50)),
            "elapsed_monotonic_ns": 1_000_000_000,
            "worker_pids": worker_pids,
            "worker_roles": [{"pid": pid, "role": role} for pid, role, _ in roles[1:]],
            "active_worker_pids": worker_pids,
            "finished_at_utc": None,
            "finished_monotonic_ns": None,
        }
        state_raw, state_hash = sealed_json(state)
        canonical = json.dumps(processes, sort_keys=True, separators=(",", ":")).encode()
        cgroup = {
            "path": path,
            "parent_path": self.manifest["pressure"]["workload_cgroup"]["parent_path"],
            "cpu_max": "75000 100000",
            "memory_max_bytes": 536870912,
            "memory_min_bytes": 0,
            "memory_low_bytes": 0,
            "io_weight": 1000,
            "io_device": "253:0",
            "io_backing": {"filesystem_device": "253:0"},
            "systemd_scope": {
                "unit": unit, "slice": "terrascale-workload.slice",
                "control_group": group, "parent_control_group": parent_group,
                "active_state": "active", "cgroup_present": True,
                "systemctl_show_raw": "\n".join((
                    "ActiveState=active", f"ControlGroup={group}",
                    "Slice=terrascale-workload.slice", "CPUQuotaPerSecUSec=750000",
                    "MemoryMax=536870912", "MemoryMin=0", "MemoryLow=0", "IOWeight=1000",
                )),
            },
            "worker_state_record": state_raw,
            "worker_state_sha256": state_hash,
            "process_pids": pids,
            "worker_process_pids": worker_pids,
            "cgroup_procs_raw": "".join(f"{pid}\n" for pid in pids),
            "processes": processes,
            "process_inventory_sha256": hashlib.sha256(canonical).hexdigest(),
        }
        evidence = {"handle": unit, "worker_harness_sha256": self.runner.harness_sha256,
                    "pressure_cgroup": cgroup}
        response = {"observed_at_utc": timestamp(now)}
        request = {"expect_pressure_completed": False}
        return evidence, response, timestamp(now)

    def test_external_systemd_scope_is_accepted_only_with_exact_effective_caps(self) -> None:
        evidence, response, _ = self.pressure_observation()
        with mock.patch.object(alpha_runner, "validate_block_backing_evidence", return_value={"filesystem_device": "253:0"}):
            self.runner._validate_pressure("pressure_start", evidence, response, {})
        self.assertTrue(self.runner.pressure_path.endswith(".scope"))

        bad = copy.deepcopy(evidence)
        bad["pressure_cgroup"]["memory_low_bytes"] = 4096
        with mock.patch.object(alpha_runner, "validate_block_backing_evidence", return_value={"filesystem_device": "253:0"}):
            with self.assertRaisesRegex(pressure.HarnessError, "memory.min and memory.low at zero"):
                alpha_runner.AdapterRunner(self.manifest, "a" * 64, Path("/unused/evidence"))._validate_pressure(
                    "pressure_start", bad, response, {},
                )

    def test_oom_event_and_receipt_bind_exact_role_and_restored_signed_cap(self) -> None:
        now = dt.datetime.now(dt.timezone.utc)
        report_time = now - dt.timedelta(milliseconds=100)
        managed = {
            "process_pid": 4242, "process_start": "98765", "process_boot_id": "b" * 32,
            "process_cgroup": "/system.slice/terrascale-host/terrabase",
        }
        self.runner.native_runner_path = alpha_runner.CGROUP_ROOT / "system.slice" / "terrascale-host"
        self.runner.database_cgroup_path = self.runner.native_runner_path / "terrabase"
        witness = {
            "host_boot_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "stat_raw": raw_stat(4242, 98765),
            "cgroup_raw": "0::/system.slice/terrascale-host/terrabase\n",
        }
        self.runner.host_snapshot = {
            "members": {"source": {"report": {"managed": managed},
                                    "managed_identity": {}, "report_time": report_time}},
            "process_witnesses": {"source": witness},
        }
        self.runner.pressure_started_at = now - dt.timedelta(seconds=5)
        self.runner.pressure["scenario"] = "terrabase_oom"
        self.runner.pressure["scenario_event_after_seconds"] = 2
        self.runner.pressure["oom_fault"] = {
            "target_memory_max_bytes": 256 * 1024 * 1024, "deadline_seconds": 10,
        }
        target = self.runner._terrabase_target()
        intent = {
            "target": {key: target[key] for key in (
                "kind", "pid", "process_start", "process_nonce", "cgroup", "host_boot_id",
            )},
            "native_runner_cgroup_path": str(self.runner.native_runner_path),
            "database_cgroup_path": str(self.runner.database_cgroup_path),
            "cgroup_inode": 123,
            "prior_memory_max_bytes": self.runner.qualification["database_memory_max_bytes"],
            "temporary_memory_max_bytes": 256 * 1024 * 1024,
        }
        watermark_raw = json.dumps({
            "__REALTIME_TIMESTAMP": str(int((now - dt.timedelta(seconds=10)).timestamp() * 1_000_000)),
            "_BOOT_ID": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "_CURSOR": "before",
            "_TRANSPORT": "kernel", "MESSAGE": "kernel startup record",
        }, sort_keys=True, separators=(",", ":"))
        watermark_hash = hashlib.sha256(watermark_raw.encode()).hexdigest()
        with tempfile.TemporaryDirectory() as temporary:
            self.runner.evidence_dir = Path(temporary)
            self.runner._validate_oom({
                "events": [], "journal_watermark_raw_record": watermark_raw,
                "journal_watermark_raw_record_sha256": watermark_hash,
                "oom_restore_intent": intent,
            }, {"phase": "before", "oom_target": target}, timestamp(now))
            self.assertEqual(self.runner.oom_restore_intent, intent)
            self.assertEqual(json.loads((Path(temporary) / "oom-restore-intent.json").read_text()), intent)
        event_at = self.runner.pressure_started_at + dt.timedelta(seconds=3)
        event_raw = json.dumps({
            "__REALTIME_TIMESTAMP": str(int(event_at.timestamp() * 1_000_000)),
            "_BOOT_ID": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "_CURSOR": "oom-event",
            "_TRANSPORT": "kernel",
            "MESSAGE": f"oom-kill: memory.oom=1,task_memcg={target['cgroup']},pid={target['pid']}",
        }, sort_keys=True, separators=(",", ":"))
        target_identity = {key: target[key] for key in (
            "kind", "pid", "process_start", "process_nonce", "cgroup", "host_boot_id",
        )}
        receipt = {
            "target": target_identity,
            "prior_memory_max_bytes": self.runner.qualification["database_memory_max_bytes"],
            "temporary_memory_max_bytes": 256 * 1024 * 1024,
            "observed_memory_current_bytes": 300 * 1024 * 1024,
            "target_cgroup_members_before": [target["pid"]],
            "target_child_cgroups_before": [], "target_cgroup_inode_before": 123,
            "restored_memory_max_bytes": self.runner.qualification["database_memory_max_bytes"],
            "restore_method": "same_cgroup_fd", "restore_verified": True,
        }
        request_time = now - dt.timedelta(milliseconds=50)
        request = {
            "phase": "during", "wait_for_event": True,
            "journal_watermark": self.runner.oom_watermark,
            "oom_target": target,
            "oom_restore_intent": self.runner.oom_restore_intent,
            "target_report_observed_at_utc": timestamp(report_time),
            "sent_at_utc": timestamp(request_time),
        }
        evidence = {
            "events": [{"source": "kernel", "raw_record": event_raw,
                        "raw_record_sha256": hashlib.sha256(event_raw.encode()).hexdigest()}],
            "memory_limit_receipt": receipt,
        }
        self.runner._validate_oom(evidence, request, timestamp(now))
        self.assertTrue(self.runner.oom_observed)
        self.assertEqual(self.runner.oom_restore_receipt, receipt)

        receipt["restored_memory_max_bytes"] -= pressure.os.sysconf("SC_PAGE_SIZE")
        with self.assertRaisesRegex(pressure.HarnessError, "not safely lowered and restored"):
            self.runner._validate_oom(evidence, request, timestamp(now))


class GuestRoleTopologyTests(unittest.TestCase):
    def test_during_pressure_peer_proof_must_finish_before_workers_end(self) -> None:
        manifest, _ = pressure.load_json(EXAMPLE)
        runner = alpha_runner.AdapterRunner(manifest, "a" * 64, Path("/unused/evidence"))
        runner.pressure_started_at = dt.datetime.now(dt.timezone.utc)
        runner.pressure_completed = False
        snapshot = {"members": {"source": {}, "peer": {}}}
        request: dict[str, object] = {}
        response = {"observed_at_utc": timestamp(runner.pressure_started_at + dt.timedelta(seconds=10)),
                    "evidence": {}}
        with mock.patch.object(alpha_runner, "validate_report_evidence", return_value=snapshot):
            runner._validate_role("host_status", "after_write", request, response)
            response["observed_at_utc"] = timestamp(
                runner.pressure_started_at + dt.timedelta(seconds=manifest["pressure"]["duration_seconds"] + 1)
            )
            with self.assertRaisesRegex(pressure.HarnessError, "did not complete during active pressure"):
                runner._validate_role("host_status", "after_write", request, response)

    def test_manifest_requires_distinct_pinned_controller_guest(self) -> None:
        manifest, _ = pressure.load_json(EXAMPLE)
        del manifest["controller_identity"]
        with self.assertRaisesRegex(pressure.HarnessError, "controller_identity"):
            pressure.validate_manifest(manifest, dry_run=True)

        manifest, _ = pressure.load_json(EXAMPLE)
        manifest["transport"]["ssh"]["targets"]["controller"]["oci_instance_id"] = (
            "ocid1.instance.oc1.sa-saopaulo-1.other-controller-id"
        )
        with self.assertRaisesRegex(pressure.HarnessError, "controller SSH target OCI instance ID"):
            pressure.validate_manifest(manifest, dry_run=True)

    def test_controller_service_and_probe_route_to_controller_target(self) -> None:
        request = {"guest_role": "controller"}
        service = {"guest_role": "controller", "units": {}, "host_boot_id": "boot"}
        with mock.patch.object(alpha_adapter, "_ssh", return_value=service) as ssh:
            self.assertEqual(alpha_adapter._service_state(request), service)
            ssh.assert_called_once_with(request, "controller", "service_state")
        with mock.patch.object(alpha_adapter, "_ssh", return_value={
                "summary": {}, "commands_log": "read-only\n"}) as ssh:
            alpha_adapter._qualify({"guest_role": "controller", "request_id": "request"})
            ssh.assert_called_once_with({"guest_role": "controller", "request_id": "request"},
                                        "controller", "qualify")

    def test_controller_probe_does_not_query_absent_host_unit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            unit_root = Path(temporary)
            (unit_root / qualify.CONTROLLER_UNIT_DEFAULT).write_text("[Service]\n")
            args = types.SimpleNamespace(role="controller", controller_unit=qualify.CONTROLLER_UNIT_DEFAULT,
                                         host_unit=qualify.HOST_UNIT_DEFAULT, database_pid=None,
                                         oci_instance_id="controller-ocid", image_id="image-ocid",
                                         artifact_id="artifact", config_id="config", profile_id="profile")
            probe = qualify.Probe(args)
            service = qualify.CGROUP_ROOT / "system.slice" / qualify.CONTROLLER_UNIT_DEFAULT
            probe.command = mock.Mock(return_value="systemd 255")
            probe.unit = mock.Mock(return_value={"ControlGroup": "/system.slice/" + args.controller_unit})
            probe.verify_baked_profile = mock.Mock(return_value={})
            probe.assert_unit_priority = mock.Mock(return_value=42)
            probe.assert_process = mock.Mock(return_value={"pid": 42, "cgroup": str(service)})
            probe.verify_priority_cgroup = mock.Mock(return_value={"cpu_weight": 10000, "io_weight": 10000})
            probe.verify_memory_budget = mock.Mock(return_value={})
            probe.verify_oomd_policy = mock.Mock(return_value={})
            probe.verify_host_runtime = mock.Mock(side_effect=AssertionError("host role queried"))
            probe.source_identity = mock.Mock(return_value=(None, unit_root))
            probe.memory_usage_sample = mock.Mock(return_value={})
            with mock.patch.object(qualify, "normalize_cpu_max", return_value="max 100000"):
                summary = probe.run()
            self.assertEqual(summary["guest_role"], "controller")
            self.assertEqual(set(summary["unit_sha256"]), {qualify.CONTROLLER_UNIT_DEFAULT})
            probe.unit.assert_called_once_with(qualify.CONTROLLER_UNIT_DEFAULT)
            probe.verify_host_runtime.assert_not_called()


if __name__ == "__main__":
    unittest.main()
