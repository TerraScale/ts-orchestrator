#!/usr/bin/env python3
"""Validate and update deploy/image/image-inputs.json, the image's pinned inputs.

check           verify the manifest schema, its canonical formatting and the
                digests of the checked-in trust roots and timesyncd config.
pin-terrabase   replace the TerraBase pin with a published, Fast-qualified
                release, given its qualification.json and `fj actions
                run-detail` readback. Only the "terrabase" block changes.
                (scripts/ci/pin-terrabase.sh downloads, pins and pushes.)
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "deploy/image/image-inputs.json"
SCHEMA = "terrascale.image.inputs.v2"
SHA256 = re.compile(r"[0-9a-f]{64}")
GIT_SHA = re.compile(r"[0-9a-f]{40}")
BASE_ASSETS = ("base-image.qcow2", "ubuntu-SHA256SUMS", "ubuntu-SHA256SUMS.gpg", "ubuntu-cloud-image-keyring.gpg")
PRIORITY_FIELDS = (
    "profile_id", "system_reserve_bytes", "host_memory_min_bytes", "host_memory_low_bytes",
    "controller_memory_min_bytes", "controller_memory_low_bytes", "system_slice_memory_min_bytes",
    "system_slice_memory_low_bytes",
)
TERRABASE_FIELDS = ("source_revision", "source_tree", "run_id", "run_number", "qualification_sha256", "binary_sha256")
TERRABASE_ARTIFACT = "tb-server-linux-arm64"
NETBIRD_SPEC = importlib.util.spec_from_file_location("netbird_client", ROOT / "deploy/netbird/client.py")
NETBIRD = importlib.util.module_from_spec(NETBIRD_SPEC)
NETBIRD_SPEC.loader.exec_module(NETBIRD)


class InputError(Exception):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise InputError(message)


def positive_int(value: object) -> bool:
    return type(value) is int and value > 0


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical(manifest: dict) -> str:
    return json.dumps(manifest, indent=2) + "\n"


def validate_terrabase(pin: object) -> None:
    require(isinstance(pin, dict) and tuple(pin) == TERRABASE_FIELDS,
            f"terrabase must have exactly {', '.join(TERRABASE_FIELDS)}")
    require(bool(GIT_SHA.fullmatch(str(pin["source_revision"]))), "terrabase.source_revision must be a full SHA")
    require(bool(GIT_SHA.fullmatch(str(pin["source_tree"]))), "terrabase.source_tree must be a full SHA")
    require(positive_int(pin["run_id"]) and positive_int(pin["run_number"]), "terrabase run identity is invalid")
    for field in ("qualification_sha256", "binary_sha256"):
        require(bool(SHA256.fullmatch(str(pin[field]))), f"terrabase.{field} must be a SHA-256")


def validate(manifest: dict, text: str) -> None:
    require(text == canonical(manifest), "image-inputs.json is not canonically formatted (json indent 2)")
    require(tuple(manifest) == ("schema", "region", "base", "trust_roots", "timesyncd_config", "priority", "terrabase", "netbird"),
            "image-inputs.json has unexpected or reordered top-level fields")
    require(manifest["schema"] == SCHEMA, f"schema must be {SCHEMA}")
    require(manifest["region"] == "GRU", "region must be GRU")

    base = manifest["base"]
    require(tuple(base) == ("release_tag", "source_url", "checksum_name", "signer_fingerprint",
                            "oci_image_ocid", "kernel_release", "assets"), "base has unexpected fields")
    require(bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", base["release_tag"])), "base.release_tag is invalid")
    require(base["source_url"].startswith("https://cloud-images.ubuntu.com/")
            and base["source_url"].endswith("/" + base["checksum_name"]), "base.source_url must be the Ubuntu image")
    require(bool(re.fullmatch(r"[0-9A-F]{40}", base["signer_fingerprint"])), "base.signer_fingerprint is invalid")
    require(base["oci_image_ocid"].startswith("ocid1.image.oc1.sa-saopaulo-1."), "base OCID must be a GRU image")
    require(bool(re.fullmatch(r"[0-9][A-Za-z0-9._+-]{0,127}", base["kernel_release"])), "base.kernel_release is invalid")
    require(tuple(sorted(base["assets"])) == tuple(sorted(BASE_ASSETS)), "base.assets must list exactly the base files")
    for name, asset in base["assets"].items():
        require(tuple(asset) == ("bytes", "sha256") and positive_int(asset["bytes"])
                and bool(SHA256.fullmatch(str(asset["sha256"]))), f"base asset pin is invalid: {name}")

    NETBIRD.validate_pin(manifest["netbird"])
    for entry in (*manifest["trust_roots"], manifest["timesyncd_config"], manifest["netbird"]["enrollment_config"]):
        require(tuple(entry) == ("path", "sha256") and bool(SHA256.fullmatch(str(entry["sha256"]))),
                "checked-in input pins need exactly path and sha256")
        path = (ROOT / entry["path"]).resolve()
        require(path.is_relative_to(ROOT / "deploy/image/inputs") and path.is_file(),
                f"checked-in input must be a file under deploy/image/inputs: {entry['path']}")
        require(sha256_file(path) == entry["sha256"], f"checked-in input differs from its pin: {entry['path']}")
    NETBIRD.validate_config(ROOT / manifest["netbird"]["enrollment_config"]["path"])
    require(1 <= len(manifest["trust_roots"]) <= 16, "trust_roots must list 1 to 16 roots")

    priority = manifest["priority"]
    require(tuple(priority) == PRIORITY_FIELDS, "priority has unexpected fields")
    require(bool(re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", priority["profile_id"])), "priority.profile_id is invalid")
    require(all(positive_int(priority[field]) for field in PRIORITY_FIELDS[1:]), "priority byte counts must be positive")
    validate_terrabase(manifest["terrabase"])


def load(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    manifest = json.loads(text)
    validate(manifest, text)
    return manifest


def terrabase_pin(qualification_path: Path, run_detail_path: Path) -> dict:
    qualification = json.loads(qualification_path.read_text(encoding="utf-8"))
    verification = qualification.get("verification", {})
    require(qualification.get("schema") == "terrascale.terrabase.qualification.v2"
            and qualification.get("repository") == "TerraScale/TerraBase", "not a TerraBase v2 qualification")
    require(verification.get("workflow") == "fast.yml" and verification.get("job") == "fast"
            and verification.get("conclusion") == "success", "TerraBase qualification is not a successful Fast run")
    artifacts = [artifact for artifact in qualification.get("artifacts", [])
                 if artifact.get("name") == TERRABASE_ARTIFACT and artifact.get("target") == "aarch64-unknown-linux-musl"]
    require(len(artifacts) == 1, f"TerraBase qualification must list one {TERRABASE_ARTIFACT}")
    detail = json.loads(run_detail_path.read_text(encoding="utf-8"))
    # TerraBase's publish job pins its own release while the run is still
    # finishing; the image build requires the finished run to have succeeded.
    require(detail.get("run_id") == verification.get("run_id")
            and detail.get("run_number") == verification.get("run_number")
            and detail.get("head_sha") == qualification.get("source_revision")
            and detail.get("workflow") == "fast.yml" and detail.get("status") in ("success", "running"),
            "TerraBase run detail differs from its qualification or did not succeed")
    require(sum(1 for job in detail.get("jobs", []) if job.get("name") == "fast" and job.get("status") == "success"
                and job.get("run_id") == detail["run_id"]) == 1, "TerraBase Fast job did not succeed")
    pin = {
        "source_revision": qualification["source_revision"],
        "source_tree": qualification["source_tree"],
        "run_id": verification["run_id"],
        "run_number": verification["run_number"],
        "qualification_sha256": sha256_file(qualification_path),
        "binary_sha256": artifacts[0]["sha256"],
    }
    validate_terrabase(pin)
    return pin


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--file", type=Path, default=MANIFEST)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("check")
    pin = commands.add_parser("pin-terrabase")
    pin.add_argument("--qualification", type=Path, required=True)
    pin.add_argument("--run-detail", type=Path, required=True)
    args = parser.parse_args()
    try:
        manifest = load(args.file)
        if args.command == "pin-terrabase":
            previous = manifest["terrabase"]
            manifest["terrabase"] = terrabase_pin(args.qualification, args.run_detail)
            validate(manifest, canonical(manifest))
            args.file.write_text(canonical(manifest), encoding="utf-8")
            print(json.dumps({"previous": previous, "pinned": manifest["terrabase"]}, sort_keys=True))
        else:
            print(f"image inputs valid sha256={sha256_file(args.file)}")
    except (InputError, KeyError, TypeError, ValueError) as error:
        print(f"image-inputs: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
