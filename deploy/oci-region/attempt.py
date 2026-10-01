#!/usr/bin/env python3
"""Run one controller-A bootstrap attempt as resumable phases.

    attempt.py --config attempt.json PHASE

Phases, in order:
  material  deployment identity, controller material, Vault provisioning,
            controller IAM object grants, ledger delegation, anchor, host
            enrollment bundle and peer-receipt delegation
  release   signed binary receipt for the CI-qualified orchestrator binary
  image     deployment-neutral QCOW2, OCI import and signed image receipt
  sign      controller A/B/C manifests, founder plan/selection, published
  launch    fresh admission, seed preflight, reservation and controller A
  complete  observe controller A, then sign and publish its seed completion
  continuity  sign install continuity for A/B/C from the markers they publish
            and publish the next read-only founder selection
  operator  render and install this attempt's operator config and credentials,
            replacing a previous attempt's install (recipient keys are kept),
            and verify the cell's qualified operator CLI
  up        every phase above, in order
  status    read-only view of the attempt's cloud and ledger state

Every phase writes into the attempt workdir, refuses to overwrite an output
and skips work whose outputs exist, so rerunning a phase resumes it. Only
`launch` consumes the attempt's single seed slot; it runs its admission,
reservation and launch in one process so no signed window can lapse between
hand-run steps. Private keys are only read by the signing tools.
"""

import argparse
import base64
import contextlib
import hashlib
import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone

HERE = pathlib.Path(__file__).resolve().parent
PREVIEW = HERE / "preview.py"
IMPORT_IMAGE = HERE / "import-image.py"
SLOTS = ("controller-a", "controller-b", "controller-c")
PHASES = ("material", "release", "image", "sign", "launch", "complete", "continuity", "operator")
OPERATOR_DIR = "/var/lib/terrascale-operator"
OPERATOR_CLI = "terrascale-orchestrator-linux-amd64"
OPERATOR_FILES = ("operator.creds", "operator-tls-cert.pem", "operator-tls-key.pem", "ca.pem", "ticket.pub",
                  "operator-signing.key", "operator.json")
REGION = "sa-saopaulo-1"


class Attempt:
    def __init__(self, config_path: pathlib.Path):
        self.config = json.loads(config_path.read_text())
        self.work = pathlib.Path(self.config["workdir"])
        self.work.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.deployment = self.config["deployment_id"]
        self.prefix = self.config["prefix"]
        self.trust = {key: pathlib.Path(value) for key, value in self.config["trust"].items()}
        self.env = dict(os.environ)
        tools = self.config["tools"]
        self.env["PATH"] = ":".join([tools["fj_dir"], tools["guestfs_tools_dir"], tools["libguestfs_dir"],
                                     self.env["PATH"]])
        self.env["LIBGUESTFS_PATH"] = tools["libguestfs_appliance"]

    # Paths ----------------------------------------------------------------
    def path(self, *parts: str) -> pathlib.Path:
        return self.work.joinpath(*parts)

    @property
    def bootstrap_tool(self) -> pathlib.Path:
        return self.path("tools", "ts-bootstrap")

    @property
    def release_tool(self) -> pathlib.Path:
        return self.path("tools", "ts-release")

    @property
    def plan(self) -> pathlib.Path:
        return self.path("plan.json")

    # Helpers --------------------------------------------------------------
    def run(self, *args, capture: bool = False, sudo: bool = False) -> str:
        command = [str(arg) for arg in args]
        if sudo:
            command = ["sudo", "--preserve-env=PATH,LIBGUESTFS_PATH", *command]
        stamp = datetime.now(timezone.utc).strftime("%H:%M:%S")
        print(f"{stamp} $ {' '.join(command[:3])} ...", flush=True)
        result = subprocess.run(command, env=self.env, cwd="/tmp", text=True,
                                stdout=subprocess.PIPE if capture else None, check=False)
        if result.returncode:
            raise SystemExit(f"command failed ({result.returncode}): {' '.join(command[:4])}")
        return result.stdout if capture else ""

    def oci(self, *args) -> dict:
        output = self.run("oci", "--region", REGION, *args, "--output", "json", capture=True)
        return json.loads(output) if output.strip() else {}

    def write_new(self, path: pathlib.Path, data: bytes) -> None:
        if path.exists():
            if path.read_bytes() != data:
                raise SystemExit(f"{path} exists with different content")
            return
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(0o600)

    def pair(self, path: pathlib.Path, flag: str) -> list:
        return [flag, path, flag + "-sha256", sha256(path)]

    def validity(self) -> tuple[str, str]:
        record = self.path("validity.json")
        if not record.exists():
            issued = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(minutes=1)
            expires = issued + timedelta(days=self.config["validity_days"])
            self.write_new(record, json.dumps({"issued_at": utc(issued), "expires_at": utc(expires)}).encode())
        row = json.loads(record.read_text())
        return row["issued_at"], row["expires_at"]

    @contextlib.contextmanager
    def root_material(self):
        """Yield a root-owned tmpfs copy of the material, removed on exit.

        Root-run renderers and installers read only root-owned material.
        """
        copy = self.run("mktemp", "-d", "/run/ts-attempt-material.XXXXXX", capture=True, sudo=True).strip()
        try:
            self.run("cp", "-a", f"{self.path('material')}/.", copy, sudo=True)
            self.run("chown", "-R", "root:root", copy, sudo=True)
            yield copy
        finally:
            self.run("rm", "-rf", "--", copy, sudo=True)

    def root_sha256(self, path: str) -> str:
        return self.run("sha256sum", path, capture=True, sudo=True).split()[0]

    def fresh_admission(self, name: str) -> tuple[pathlib.Path, pathlib.Path]:
        inventory, admission = self.path(f"{name}-inventory.json"), self.path(f"{name}-admission.json")
        for attempt in range(3):
            result = subprocess.run([sys.executable, str(PREVIEW), "inventory", "--plan", str(self.plan),
                                     "--out", str(inventory)], env=self.env, check=False)
            if result.returncode == 0:
                break
            if attempt == 2:
                raise SystemExit("live inventory failed three times")
        self.run(sys.executable, PREVIEW, "admit", "--plan", self.plan, "--inventory", inventory,
                 "--out", admission)
        return inventory, admission

    # Phases ---------------------------------------------------------------
    def phase_material(self) -> None:
        self.build_tools()
        base = json.loads(pathlib.Path(self.config["base_plan"]).read_text())
        base["bootstrap_object_prefix"] = self.prefix
        base["purpose"] = f"GRU bootstrap attempt {self.deployment}"
        base["seed_a_create_identity"] = "seed-a-" + hashlib.sha256(
            f"{self.deployment}\0{self.prefix}".encode()).hexdigest()[:16]
        for slot in base["resource_ids"]["instances"]:
            base["resource_ids"]["instances"][slot] = None
        self.write_new(self.plan, json.dumps(base, indent=1, sort_keys=True).encode())
        identity = json.dumps({"schemaVersion": 1, "deploymentId": self.deployment, "environment": "canary",
                               "cell": "GRU"}, separators=(",", ":")).encode()
        self.write_new(self.path("identity.json"), identity)

        material_dir, record = self.path("material"), self.path("controller-material.json")
        if not record.exists():
            hosts = {host["slot"]: host for host in base["hosts"]}
            config = self.path("controller-material.config.json")
            self.write_new(config, json.dumps({
                "cell": "gru", "clusterId": self.deployment, "deploymentId": self.deployment,
                "environment": "canary", "region": REGION,
                "slots": [{"name": slot, "privateIp": hosts[slot]["private_ip"]} for slot in SLOTS],
                "subnetCidr": base["subnet_cidr"], "validityHours": self.config["validity_days"] * 24,
            }, indent=4).encode())
            self.run(self.bootstrap_tool, "generate-controller-material", "--config", config,
                     "--config-sha256", sha256(config), "--directory", material_dir, "--out", record)

        self.ensure_controller_object_grants(base)
        references = self.path("controller-vault-references.json")
        if not references.exists():
            inventory, admission = self.fresh_admission("material")
            readback = self.path("material-foundation.json")
            readback.unlink(missing_ok=True)
            self.run(sys.executable, PREVIEW, "inspect-foundation", "--plan", self.plan, "--inventory", inventory,
                     "--admission", admission, "--out", readback)
            self.run(self.bootstrap_tool, "provision-controller-material", "--directory", material_dir,
                     "--manual-readback", readback, "--manual-readback-sha256", sha256(readback),
                     "--inventory", inventory, "--inventory-sha256", sha256(inventory),
                     "--cost-admission", admission, "--cost-admission-sha256", sha256(admission),
                     "--cost-plan-sha256", sha256(self.plan), "--oci-config", pathlib.Path.home() / ".oci/config",
                     "--oci-profile", "DEFAULT", "--out", references)

        issued, expires = self.validity()
        ledger = self.path("ledger-delegation.signed.json")
        if not ledger.exists():
            self.run(self.bootstrap_tool, "sign-ledger-delegation", "--deployment", self.deployment, "--cell", "GRU",
                     "--environment", "canary", *sum((["--slot", slot] for slot in SLOTS), []),
                     "--signer-public-key", str(record) + ".ledger.pem", "--root-key", self.trust["root_public"],
                     "--signing-key", self.trust["root_private"], "--issued-at", issued, "--expires-at", expires,
                     "--out", ledger)
        anchor = self.path("anchor.signed.json")
        if not anchor.exists():
            candidate = self.path("anchor.candidate.json")
            storage = {"namespace": self.config["namespace"],
                       "ledgerBucket": base["foundation_buckets"]["ledger"],
                       "ledgerKmsKeyOcid": base["resource_ids"]["key"],
                       "headBucket": base["foundation_buckets"]["head"],
                       "headKmsKeyOcid": base["resource_ids"]["key"], "prefix": self.prefix}
            self.write_new(candidate, json.dumps({
                "schemaVersion": 3, "deploymentId": self.deployment, "environment": "canary",
                "clusterId": self.deployment, "cell": "GRU", "ociRegion": REGION, "storageDomain": storage,
                "controllerSlots": list(SLOTS)}).encode())
            anchor_expiry = datetime.fromisoformat(expires.replace("Z", "+00:00"))
            valid_for = int((anchor_expiry - datetime.now(timezone.utc)).total_seconds()) - 60
            self.run(self.bootstrap_tool, "sign-anchor", "--candidate", candidate,
                     "--region-intent", self.config["region_intent"], "--ledger-delegation", ledger,
                     "--root-key", self.trust["root_public"], "--signing-key", self.trust["root_private"],
                     "--valid-for", f"{valid_for}s", "--out", anchor)
        self.run(self.bootstrap_tool, "verify-anchor", "--anchor", anchor, "--identity", self.path("identity.json"),
                 "--root-key", self.trust["root_public"])

        enrollment = self.path("host-enrollment-public.json")
        if not enrollment.exists():
            with self.root_material() as copy:
                self.run(self.bootstrap_tool, "render-host-enrollment-public", *self.pair(record, "--material-record"),
                         "--material-directory", copy, "--out", enrollment, sudo=True)
            self.run("chown", f"{os.getuid()}:{os.getgid()}", enrollment, sudo=True)
        peer = self.path("peer-receipt-delegation.signed.json")
        if not peer.exists():
            self.run(self.bootstrap_tool, "sign-peer-receipt-delegation", "--identity", self.path("identity.json"),
                     "--anchor", anchor, "--root-key", self.trust["root_public"],
                     "--signing-key", self.trust["root_private"], "--peer-public-key", str(record) + ".peer.pem",
                     "--out", peer, "--valid-for", f"{self.config['validity_days'] * 24}h")

    def ensure_controller_object_grants(self, plan: dict) -> None:
        """Make the controller policy exactly the reviewed statements for this attempt's prefix."""
        ids = plan["resource_ids"]
        expected = preview_module().required_controller_statements(plan, ids, self.prefix)
        policy = self.oci("iam", "policy", "get", "--policy-id", ids["controller_policy"])["data"]
        if policy["statements"] == expected:
            return
        statements_file = self.path("controller-policy-statements.json")
        statements_file.write_text(json.dumps(expected))
        self.oci("iam", "policy", "update", "--policy-id", ids["controller_policy"],
                 "--statements", f"file://{statements_file}", "--version-date", "", "--force")
        print("controller object grants now target prefix", self.prefix, "- waiting for IAM propagation", flush=True)
        time.sleep(60)

    def build_tools(self) -> None:
        orchestrator = self.config["orchestrator"]
        tools = self.path("tools")
        if self.bootstrap_tool.exists() and self.release_tool.exists():
            return
        source = self.path("source")
        if not source.exists():
            self.run("git", "-C", orchestrator["repository"], "worktree", "add", "--detach", source,
                     orchestrator["source_revision"])
        tools.mkdir(mode=0o700, exist_ok=True)
        for name in ("ts-bootstrap", "ts-release"):
            subprocess.run(["go", "build", "-trimpath", "-o", str(tools / name), f"./cmd/{name}"],
                           cwd=source, env=self.env, check=True)

    def phase_release(self) -> None:
        orchestrator = self.config["orchestrator"]
        revision, run_number = orchestrator["source_revision"], orchestrator["ci_run_number"]
        release = self.path("release")
        release.mkdir(mode=0o700, exist_ok=True)
        detail = json.loads(self.run("fj", "actions", "run-detail", run_number, "-r", "TerraScale/ts-orchestrator",
                                     capture=True))
        if detail["head_sha"] != revision or detail["status"] != "success":
            raise SystemExit(f"CI run {run_number} is not a successful run of {revision}: {detail['status']}")
        tag = f"ci-{revision}-run-{detail['run_id']}"
        for asset in ("qualification.json", "terrascale-orchestrator-linux-arm64", OPERATOR_CLI):
            if not (release / asset).exists():
                self.run("fj", "release", "asset", "download", "-r", "TerraScale/ts-orchestrator", tag, asset,
                         "-o", release / asset)
        issued, expires = self.validity()
        delegation = release / "binary-delegation.signed.json"
        if not delegation.exists():
            self.run(self.release_tool, "sign-delegation", "--subject-public-key", self.trust["release_leaf_public"],
                     "--root-key", self.trust["root_public"], "--signing-key", self.trust["root_private"],
                     "--source-revision", revision, "--arch", "arm64", "--environment", "canary",
                     "--issued-at", issued, "--expires-at", expires, "--out", delegation)
        candidate, receipt = release / "binary-receipt.candidate.json", release / "binary-receipt.signed.json"
        binary, qualification = release / "terrascale-orchestrator-linux-arm64", release / "qualification.json"
        if not candidate.exists():
            self.run(self.release_tool, "binary-candidate", "--binary", binary, "--source-revision", revision,
                     "--qualification", qualification, "--out", candidate)
        if not receipt.exists():
            self.run(self.release_tool, "sign-binary", "--candidate", candidate, "--binary", binary,
                     "--qualification", qualification, "--delegation", delegation,
                     "--root-key", self.trust["root_public"], "--signing-key", self.trust["release_leaf_private"],
                     "--environment", "canary", "--out", receipt)
        self.run(self.release_tool, "verify-binary", "--receipt", receipt, "--delegation", delegation,
                 "--root-key", self.trust["root_public"], "--binary", binary, "--qualification", qualification,
                 "--environment", "canary")

    def phase_image(self) -> None:
        image_config = self.config["image"]
        release = self.path("release")
        qcow2 = self.path("image", "terrascale-arm64.qcow2")
        if not qcow2.exists():
            qcow2.parent.mkdir(mode=0o700, exist_ok=True)
            priority = image_config["priority"]
            subprocess.run([
                "bash", str(self.path("source", "deploy/image/build-offline.sh")),
                "--base", image_config["base_qcow2"], "--kernel-release", image_config["kernel_release"],
                "--binary", str(release / "terrascale-orchestrator-linux-arm64"),
                "--qualification", str(release / "qualification.json"),
                "--source-revision", self.config["orchestrator"]["source_revision"],
                "--native-verifier-binary", image_config["native_verifier"],
                "--native-verifier-sha256", image_config["native_verifier_sha256"],
                "--release-tool", str(self.release_tool), "--bootstrap-root", str(self.trust["root_public"]),
                "--timesyncd-config", image_config["timesyncd_config"],
                "--runtime-priority-profile-id", priority["profile_id"],
                "--runtime-priority-system-reserve-bytes", str(priority["system_reserve_bytes"]),
                "--host-memory-min-bytes", str(priority["host_memory_min_bytes"]),
                "--host-memory-low-bytes", str(priority["host_memory_low_bytes"]),
                "--controller-memory-min-bytes", str(priority["controller_memory_min_bytes"]),
                "--controller-memory-low-bytes", str(priority["controller_memory_low_bytes"]),
                "--system-slice-memory-min-bytes", str(priority["system_slice_memory_min_bytes"]),
                "--system-slice-memory-low-bytes", str(priority["system_slice_memory_low_bytes"]),
                "--out", str(qcow2), "--kernel-out", str(self.kernel)], cwd=self.path("source"), env=self.env,
                check=True)
        digest = sha256(qcow2)
        imported = self.path("image", "import.json")
        if not imported.exists():
            plan = json.loads(self.plan.read_text())
            self.run(sys.executable, IMPORT_IMAGE, "--qcow2", qcow2, "--sha256", digest,
                     "--compartment-id", plan["resource_ids"]["control_compartment"],
                     "--namespace", self.config["namespace"], "--bucket", image_config["bucket"],
                     "--display-name", f"terrascale-arm64-{self.config['orchestrator']['source_revision'][:12]}"
                                       f"-{digest[:12]}", "--out", imported)
        image_id = json.loads(imported.read_text())["image_id"]
        issued, expires = self.validity()
        delegation = self.path("image", "image-delegation.signed.json")
        if not delegation.exists():
            self.run(self.release_tool, "sign-delegation", "--subject-public-key", self.trust["release_leaf_public"],
                     "--root-key", self.trust["root_public"], "--signing-key", self.trust["root_private"],
                     "--source-revision", self.config["orchestrator"]["source_revision"], "--arch", "arm64",
                     "--environment", "canary", "--image-cell", "GRU", "--image-ocid", image_id,
                     "--previous-delegation", release / "binary-delegation.signed.json",
                     "--issued-at", issued, "--expires-at", expires, "--out", delegation)
        candidate, receipt = self.path("image", "image-receipt.candidate.json"), self.image_receipt
        common = ["--binary-receipt", release / "binary-receipt.signed.json",
                  "--binary", release / "terrascale-orchestrator-linux-arm64",
                  "--qualification", release / "qualification.json", "--delegation", delegation,
                  "--root-key", self.trust["root_public"], "--environment", "canary", "--image-file", qcow2,
                  "--base-image-file", image_config["base_qcow2"], "--kernel-file", self.kernel]
        if not candidate.exists():
            self.run(self.release_tool, "image-candidate", *common,
                     "--base-image-ocid", image_config["base_image_ocid"], "--base-image-region", "GRU",
                     "--kernel-release", image_config["kernel_release"], "--image-ocid", image_id, "--region", "GRU",
                     "--out", candidate)
        if not receipt.exists():
            self.run(self.release_tool, "sign-image", "--candidate", candidate, *common,
                     "--signing-key", self.trust["release_leaf_private"], "--out", receipt)
        self.run(self.release_tool, "verify-image", "--receipt", receipt, "--delegation", delegation,
                 "--root-key", self.trust["root_public"], "--image-file", qcow2,
                 "--base-image-file", image_config["base_qcow2"], "--kernel-file", self.kernel,
                 "--region", "GRU", "--environment", "canary")

    @property
    def kernel(self) -> pathlib.Path:
        return self.path("image", "guest-kernel")

    @property
    def image_receipt(self) -> pathlib.Path:
        return self.path("image", "image-receipt.signed.json")

    @property
    def image_id(self) -> str:
        return json.loads(self.path("image", "import.json").read_text())["image_id"]

    def manifest(self, slot: str) -> pathlib.Path:
        return self.path("signed", f"{slot}.manifest.signed.json")

    def phase_sign(self) -> None:
        signed = self.path("signed")
        signed.mkdir(mode=0o700, exist_ok=True)
        plan = json.loads(self.plan.read_text())
        hosts = {host["slot"]: host for host in plan["hosts"]}
        anchor = self.path("anchor.signed.json")
        anchor_payload = json.loads(anchor.read_text())["payload"]
        references = json.loads(self.path("controller-vault-references.json").read_text())["references"]
        members = [hosts[slot] for slot in ("member-a", "member-b")]
        region = self.path("signed", "oci-region.json")
        self.write_new(region, json.dumps({
            "region": "GRU", "generation": 1, "endpoint": f"https://iaas.{REGION}.oraclecloud.com",
            "compartment_id": plan["resource_ids"]["workload_compartment"],
            "image_compartment_id": plan["resource_ids"]["control_compartment"],
            "availability_domain": plan["availability_domain"],
            "fault_domains": [host["fault_domain"] for host in members],
            "subnet_id": plan["resource_ids"]["subnet"],
            "network_security_group_ids": [self.config["workload_nsg"]], "image_id": self.image_id,
            "shape": "VM.Standard.A1.Flex", "boot_volume_gb": 50,
            "boot_volume_vpus_per_gb": plan["volume_vpus_per_gb"],
            "data_volume_vpus_per_gb": plan["volume_vpus_per_gb"],
            "max_data_volume_gb": max(host["data_gb"] for host in members), "owner": self.deployment,
        }, sort_keys=True, separators=(",", ":")).encode())
        intent, placement = pathlib.Path(self.config["region_intent"]), pathlib.Path(self.config["placement_config"])
        sidecars = self.pair(intent, "--oci-region-intent") + self.pair(region, "--oci-region-config") + \
            self.pair(placement, "--placement-config")
        receipt = self.image_receipt
        delegation = self.path("image", "image-delegation.signed.json")
        peer = json.loads(self.path("peer-receipt-delegation.signed.json").read_text())
        domain = json.loads(pathlib.Path(self.config["managed_material_domain"]).read_text())
        # Controllers hash the image's packaged native verifier against this
        # signed digest, so it always comes from the image this attempt builds.
        domain["nativeVerifierSha256"] = self.config["image"]["native_verifier_sha256"]
        profiles = []
        for slot in SLOTS:
            profiles.append({"slot": slot, "compartmentOcid": plan["resource_ids"]["control_compartment"],
                             "availabilityDomain": plan["availability_domain"],
                             "faultDomain": hosts[slot]["fault_domain"], "subnetOcid": plan["resource_ids"]["subnet"],
                             "networkSecurityGroupOcids": [plan["resource_ids"]["network_security_group"]], "shape": hosts[slot]["shape"]})
        for slot in SLOTS:
            manifest = self.manifest(slot)
            if manifest.exists():
                continue
            secrets = [row["reference"] for row in references
                       if row["reference"]["purpose"] in ("regional-shared", "host-issuer")
                       or row["reference"].get("slot") == slot]
            candidate, config = signed / f"{slot}.candidate.json", signed / f"{slot}.config.json"
            self.write_new(candidate, json.dumps({
                "schemaVersion": 2, "deploymentId": self.deployment, "environment": "canary",
                "clusterId": self.deployment, "cell": "GRU", "ociRegion": REGION,
                "intentGeneration": anchor_payload["initialRegionIntentGeneration"],
                "intentSha256": anchor_payload["initialRegionIntentSha256"], "controllerRole": "controller",
                "slot": slot, "seedSlot": "controller-a", "controllerSlots": list(SLOTS), "profiles": profiles,
                "imageOcid": self.image_id, "imageArchitecture": "linux-arm64", "releaseReceiptSha256": sha256(receipt),
                "peerReceiptDelegation": peer, "storageDomain": anchor_payload["storageDomain"],
                "managedMaterial": domain, "secrets": secrets,
            }, separators=(",", ":"), ensure_ascii=False).encode())
            if not config.exists():
                self.run(self.bootstrap_tool, "render-controller-config", *self.pair(candidate, "--candidate"),
                         *self.pair(self.path("controller-material.json"), "--material-record"),
                         *self.pair(pathlib.Path(self.config["operator_grant"]), "--operator-grant"), *sidecars,
                         "--out", config)
            self.run(self.bootstrap_tool, "sign-manifest", "--candidate", candidate,
                     *self.pair(config, "--controller-config"), *sidecars, "--anchor", anchor,
                     "--image-receipt", receipt, "--release-delegation", delegation,
                     "--root-key", self.trust["root_public"], "--signing-key", self.trust["root_private"],
                     "--out", manifest, "--valid-for", f"{self.config['validity_days'] * 24}h")
            verified = self.run(self.bootstrap_tool, "verify-manifest", "--anchor", anchor, "--manifest", manifest,
                                "--identity", self.path("identity.json"), "--slot", slot,
                                "--image-ocid", self.image_id, "--root-key", self.trust["root_public"], capture=True)
            self.write_new(signed / f"{slot}.verify.json", verified.encode())

        founder = signed / "founder-plan.signed.json"
        selection = signed / "founder-selection.signed.json"
        manifests = sum((["--manifest", self.manifest(slot)] for slot in SLOTS), [])
        identity = self.path("identity.json")
        if not founder.exists():
            vault = {row["reference"]["targetFile"]: row["reference"]["sha256"] for row in references}
            peers = []
            for slot in ("controller-b", "controller-c"):
                profile = json.loads((signed / f"{slot}.verify.json").read_text())["profile"]
                host = hosts[slot]
                peers.append({
                    "slot": slot, "manifestSha256": sha256(self.manifest(slot)), "imageOcid": self.image_id,
                    "image_compartment_ocid": plan["resource_ids"]["control_compartment"],
                    "compartmentOcid": profile["compartmentOcid"], "availabilityDomain": profile["availabilityDomain"],
                    "faultDomain": profile["faultDomain"], "subnetOcid": profile["subnetOcid"],
                    "networkSecurityGroupOcids": profile["networkSecurityGroupOcids"], "shape": host["shape"],
                    "wholeOcpus": host["ocpus"], "memoryInGb": host["memory_gb"], "bootVolumeGb": host["boot_gb"],
                    "bootVolumeTier": "balanced", "privateIp": host["private_ip"],
                    "routeEndpoints": [{"slot": name, "privateIp": hosts[name]["private_ip"], "port": 6222}
                                       for name in SLOTS if name != slot],
                    "clientEndpoints": [{"slot": slot, "privateIp": host["private_ip"], "port": 4222}],
                    "tlsMaterial": {
                        "clientCaSha256": vault["ca.pem"], "clientCertificateSha256": vault[f"{slot}-tls-cert.pem"],
                        "clientPrivateKeySha256": vault[f"{slot}-tls-key.pem"], "routeCaSha256": vault["ca.pem"],
                        "routeCertificateSha256": vault[f"{slot}-tls-cert.pem"],
                        "routePrivateKeySha256": vault[f"{slot}-tls-key.pem"]},
                })
            deadline = (datetime.now(timezone.utc) + timedelta(hours=22)).replace(second=0, microsecond=0)
            candidate = signed / "founder-plan.candidate.json"
            self.write_new(candidate, json.dumps({
                "schemaVersion": 1, "deploymentId": self.deployment, "cell": "GRU", "environment": "canary",
                "seedSlot": "controller-a", "anchorSha256": sha256(anchor), "controllerSlots": list(SLOTS),
                "seedManifestSha256": sha256(self.manifest("controller-a")),
                "seedPrivateIp": hosts["controller-a"]["private_ip"], "peers": peers,
                "budget": {key: sum(peer[field] for peer in peers) for key, field in
                           (("wholeOcpus", "wholeOcpus"), ("memoryInGb", "memoryInGb"),
                            ("bootVolumeGb", "bootVolumeGb"))},
                "launchDeadline": utc(deadline),
            }, separators=(",", ":")).encode())
            self.run(self.bootstrap_tool, "sign-founder-plan", "--candidate", candidate, "--identity", identity,
                     "--anchor", anchor, *manifests, "--root-key", self.trust["root_public"],
                     "--signing-key", self.trust["root_private"], "--out", founder, "--valid-for", "24h")
        if not selection.exists():
            candidate = signed / "founder-selection.candidate.json"
            self.write_new(candidate, json.dumps({
                "schemaVersion": 1, "deploymentId": self.deployment, "cell": "GRU", "environment": "canary",
                "generation": 1, "planSha256": sha256(founder), "anchorSha256": sha256(anchor),
                "manifests": [{"slot": slot, "sha256": sha256(self.manifest(slot))} for slot in SLOTS],
            }, separators=(",", ":")).encode())
            self.run(self.bootstrap_tool, "sign-initial-founder-selection", "--candidate", candidate,
                     "--identity", identity, "--anchor", anchor, "--plan", founder, *manifests,
                     "--root-key", self.trust["root_public"], "--signing-key", self.trust["root_private"],
                     "--out", selection, "--valid-for", "24h")
        self.run(self.bootstrap_tool, "publish-initial-founder-selection", "--selection", selection,
                 "--identity", identity, "--anchor", anchor, "--plan", founder, *manifests,
                 "--root-key", self.trust["root_public"], "--oci-config", pathlib.Path.home() / ".oci/config",
                 "--oci-profile", "DEFAULT")

    def seed_args(self) -> list:
        signed = self.path("signed")
        return ["--identity", self.path("identity.json"), "--anchor", self.path("anchor.signed.json"),
                "--founder-plan", signed / "founder-plan.signed.json", "--root-key", self.trust["root_public"],
                *sum((["--manifest", self.manifest(slot)] for slot in SLOTS), [])]

    def phase_launch(self) -> None:
        launch = self.path("launch")
        if (launch / "controller-a.ocid").exists():
            print("controller A already launched:", (launch / "controller-a.ocid").read_text().strip())
            return
        if (launch / "seed-reservation.json").exists():
            raise SystemExit("a seed reservation exists without a launched controller A; reconcile before retrying")
        launch.mkdir(mode=0o700, exist_ok=True)
        inventory, admission = self.fresh_admission("launch/launch")
        image_config = self.config["image"]
        reviewed = launch / "reviewed-seed-plan.json"
        reviewed.unlink(missing_ok=True)
        self.run(sys.executable, PREVIEW, "seed-preflight", "--plan", self.plan, "--inventory", inventory,
                 "--admission", admission, "--bootstrap-tool", self.bootstrap_tool,
                 "--anchor", self.path("anchor.signed.json"), "--manifest", self.manifest("controller-a"),
                 "--identity", self.path("identity.json"), "--bootstrap-root", self.trust["root_public"],
                 "--image-ocid", self.image_id, "--release-tool", self.release_tool,
                 "--image-receipt", self.image_receipt,
                 "--release-delegation", self.path("image", "image-delegation.signed.json"),
                 "--release-root", self.trust["root_public"],
                 "--image-file", self.path("image", "terrascale-arm64.qcow2"),
                 "--base-image-file", image_config["base_qcow2"], "--kernel-file", self.kernel,
                 "--out", reviewed)
        launch_input = launch / "controller-a-launch.json"
        launch_input.unlink(missing_ok=True)
        self.run(sys.executable, PREVIEW, "seed-launch", "--plan", self.plan, "--reviewed-plan", reviewed,
                 "--manifest", self.manifest("controller-a"), "--identity", self.path("identity.json"),
                 "--anchor", self.path("anchor.signed.json"),
                 "--host-enrollment", self.path("host-enrollment-public.json"),
                 "--owner-ssh-public-key", self.config["owner_ssh_public_key"], "--out", launch_input)
        plan = json.loads(self.plan.read_text())
        slot_objects = [name for bucket in ("head", "ledger") for name in self.list_objects(
            plan["foundation_buckets"][bucket], f"{self.prefix}/") if "/founder-selection/" not in name]
        if slot_objects:
            raise SystemExit(f"attempt prefix already holds slot records: {slot_objects}")
        remaining = datetime.fromisoformat(json.loads(admission.read_text())["expires_at"]) - \
            datetime.now(timezone.utc)
        if remaining.total_seconds() < 180:
            raise SystemExit(f"cost admission has only {remaining} left")
        reservation = launch / "seed-reservation.json"
        reviewed_sha = sha256(reviewed)
        create_identity = json.loads(reviewed.read_text())["create_identity"]
        self.run(self.bootstrap_tool, "sign-external-seed-reservation", *self.seed_args(),
                 "--reviewed-plan", reviewed, "--reviewed-plan-sha256", reviewed_sha,
                 "--create-identity", create_identity,
                 "--ledger-signing-key", self.path("material", "founder-ledger.key"), "--out", reservation)
        self.run(self.bootstrap_tool, "publish-external-seed-reservation", *self.seed_args(),
                 "--reservation", reservation, "--oci-config", pathlib.Path.home() / ".oci/config",
                 "--oci-profile", "DEFAULT")
        submitted = self.oci("compute", "instance", "launch", "--from-json", f"file://{launch_input}")
        (launch / "controller-a-launch-submit.json").write_text(json.dumps(submitted))
        (launch / "controller-a.ocid").write_text(submitted["data"]["id"] + "\n")
        print("launched controller A", submitted["data"]["id"], flush=True)

    def phase_complete(self) -> None:
        launch = self.path("launch")
        instance = (launch / "controller-a.ocid").read_text().strip()
        for _ in range(60):
            state = self.oci("compute", "instance", "get", "--instance-id", instance)["data"]["lifecycle-state"]
            if state == "RUNNING":
                break
            time.sleep(10)
        else:
            raise SystemExit("controller A did not reach RUNNING")
        reviewed = launch / "reviewed-seed-plan.json"
        reviewed_args = ["--reviewed-plan", reviewed, "--reviewed-plan-sha256", sha256(reviewed)]
        oci_args = ["--oci-config", pathlib.Path.home() / ".oci/config", "--oci-profile", "DEFAULT"]
        observation, completion = launch / "seed-observation.json", launch / "seed-completion.json"
        if not completion.exists():
            observation.unlink(missing_ok=True)
            self.run(self.bootstrap_tool, "observe-external-seed", *self.seed_args(),
                     "--reservation", launch / "seed-reservation.json", *reviewed_args,
                     "--instance-ocid", instance, *oci_args, "--out", observation)
            self.run(self.bootstrap_tool, "sign-external-seed-completion", *self.seed_args(),
                     "--reservation", launch / "seed-reservation.json", "--observation", observation,
                     "--signing-key", self.trust["root_private"],
                     "--ledger-signing-key", self.path("material", "founder-ledger.key"), "--out", completion)
        self.run(self.bootstrap_tool, "publish-external-seed-completion", *self.seed_args(),
                 "--reservation", launch / "seed-reservation.json", "--completion", completion, *reviewed_args,
                 *oci_args)

    def phase_continuity(self) -> None:
        """Sign install continuity for every controller and publish the next selector.

        Managed peers restart only through a root-signed continuity for their
        exact accepted install, which each controller publishes beside its
        slot HEAD during admission.
        """
        continuity = self.path("continuity")
        continuity.mkdir(mode=0o700, exist_ok=True)
        plan = json.loads(self.plan.read_text())
        anchor = self.path("anchor.signed.json")
        for slot in SLOTS:
            marker = continuity / f"{slot}.marker.json"
            key = hashlib.sha256(f"GRU\0controller\0{slot}".encode()).hexdigest()
            name = f"{self.prefix}/bootstrap/v1/{self.deployment}/{key}/accepted-install.json"
            deadline = time.monotonic() + 20 * 60
            while not marker.exists():
                result = subprocess.run(["oci", "--region", REGION, "os", "object", "get", "--namespace-name",
                                         self.config["namespace"], "--bucket-name", plan["foundation_buckets"]["head"],
                                         "--name", name, "--file", str(marker)],
                                        env=self.env, capture_output=True, check=False)
                if result.returncode == 0 and marker.stat().st_size > 0:
                    break
                marker.unlink(missing_ok=True)
                if time.monotonic() > deadline:
                    raise SystemExit(f"{slot} did not publish its accepted-install marker")
                time.sleep(20)
        record = continuity / "generation"
        generation = int(record.read_text()) + 1 if record.exists() else 2
        work = continuity / f"g{generation}"
        work.mkdir(mode=0o700, exist_ok=True)
        proofs = []
        for slot in SLOTS:
            candidate, proof = work / f"{slot}.candidate.json", work / f"{slot}.signed.json"
            if not proof.exists():
                candidate.unlink(missing_ok=True)
                self.run(self.bootstrap_tool, "render-founder-continuity", "--marker", continuity / f"{slot}.marker.json",
                         "--anchor", anchor, "--material-directory", self.path("material"),
                         "--selector-generation", generation, "--out", candidate)
                self.run(self.bootstrap_tool, "sign-founder-continuity", "--candidate", candidate,
                         "--marker", continuity / f"{slot}.marker.json", "--anchor", anchor,
                         "--root-key", self.trust["root_public"], "--signing-key", self.trust["root_private"],
                         "--out", proof, "--valid-for", f"{self.config['validity_days'] * 24}h")
            proofs += ["--proof", proof]
        selection = work / "selection.signed.json"
        if not selection.exists():
            candidate = work / "selection.candidate.json"
            candidate.write_text(json.dumps({
                "schemaVersion": 2, "deploymentId": self.deployment, "cell": "GRU", "environment": "canary",
                "generation": generation,
                "continuities": [{"slot": slot, "sha256": sha256(work / f"{slot}.signed.json")} for slot in SLOTS],
            }, separators=(",", ":")))
            self.run(self.bootstrap_tool, "sign-founder-selection", "--candidate", candidate,
                     "--identity", self.path("identity.json"), "--root-key", self.trust["root_public"],
                     "--signing-key", self.trust["root_private"], "--out", selection,
                     "--valid-for", f"{self.config['validity_days'] * 24}h", *proofs)
        self.run(self.bootstrap_tool, "publish-founder-selection", "--selection", selection,
                 "--identity", self.path("identity.json"), "--anchor", anchor, "--root-key", self.trust["root_public"],
                 "--oci-config", pathlib.Path.home() / ".oci/config", "--oci-profile", "DEFAULT", *proofs)
        record.write_text(str(generation))

    def phase_operator(self) -> None:
        """Install this attempt's operator config, credentials and signing key for the operator CLI."""
        record, grant = self.path("controller-material.json"), pathlib.Path(self.config["operator_grant"])
        key = self.config["operator_signing_key"]
        rendered = f"/run/ts-attempt-operator-{self.deployment}.json"
        with self.root_material() as material:
            self.run("rm", "-f", "--", rendered, sudo=True)
            try:
                self.run(self.bootstrap_tool, "render-operator-config", *self.pair(record, "--material-record"),
                         "--material-directory", material, *self.pair(grant, "--operator-grant"),
                         "--operator-signing-key", key, "--operator-signing-key-sha256", self.root_sha256(key),
                         "--out", rendered, sudo=True)
                self.run("rm", "-f", "--", *(f"{OPERATOR_DIR}/{name}" for name in OPERATOR_FILES), sudo=True)
                self.run(self.bootstrap_tool, "install-operator-material", *self.pair(record, "--material-record"),
                         "--material-directory", material, "--operator-config", rendered,
                         "--operator-config-sha256", self.root_sha256(rendered), "--operator-signing-key", key,
                         "--operator-signing-key-sha256", self.root_sha256(key), sudo=True)
            finally:
                self.run("rm", "-f", "--", rendered, sudo=True)
        # The operator CLI must be the cell's exact qualified release: signed
        # command and artifact claims change between revisions.
        cli = self.path("release", OPERATOR_CLI)
        artifacts = json.loads(self.path("release", "qualification.json").read_text())["artifacts"]
        if [row["sha256"] for row in artifacts if row["name"] == OPERATOR_CLI] != [sha256(cli)]:
            raise SystemExit("operator CLI differs from the qualified CI artifact")
        cli.chmod(0o755)
        print(f"operator CLI for this cell: {cli}", flush=True)

    def phase_up(self) -> None:
        for phase in PHASES:
            print(f"== {phase}", flush=True)
            getattr(self, "phase_" + phase)()

    def list_objects(self, bucket: str, prefix: str) -> list[str]:
        listing = self.oci("os", "object", "list", "--namespace-name", self.config["namespace"],
                           "--bucket-name", bucket, "--prefix", prefix, "--all")
        return [row["name"] for row in listing.get("data", [])]

    def phase_status(self) -> None:
        plan = json.loads(self.plan.read_text())
        for bucket in ("head", "ledger"):
            for name in self.list_objects(plan["foundation_buckets"][bucket], f"{self.prefix}/"):
                print(f"{bucket}: {name.removeprefix(self.prefix + '/bootstrap/v1/' + self.deployment + '/')}")
        instances = self.oci("compute", "instance", "list", "--compartment-id",
                             plan["resource_ids"]["control_compartment"], "--all").get("data", [])
        instances += self.oci("compute", "instance", "list", "--compartment-id",
                              plan["resource_ids"]["workload_compartment"], "--all").get("data", [])
        for instance in instances:
            if instance["lifecycle-state"] != "TERMINATED" and instance["display-name"].startswith(self.deployment):
                print(f"instance {instance['display-name']} {instance['lifecycle-state']} {instance['id']}")


def preview_module():
    spec = importlib.util.spec_from_file_location("preview", PREVIEW)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with pathlib.Path(path).open("rb") as source:
        for block in iter(lambda: source.read(8 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def utc(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--config", type=pathlib.Path, required=True)
    parser.add_argument("phase", choices=(*PHASES, "up", "status"))
    args = parser.parse_args()
    attempt = Attempt(args.config)
    getattr(attempt, "phase_" + args.phase)()


if __name__ == "__main__":
    main()
