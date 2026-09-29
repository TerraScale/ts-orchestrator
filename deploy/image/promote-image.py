#!/usr/bin/env python3
"""Promote a qualified host image to a signed OCI image in one command.

Takes a retained image release (--image-release TAG) or a local build
(--image-dir DIR from `make image`) and runs every gate in order, stopping at
the first failure:

  1. read the image back and check SHA256SUMS; for a CI image, require the
     image.yml run and job to have succeeded and its log to carry the exact
     TS_IMAGE_QUALIFICATION_V1 marker for these bytes;
  2. fetch the image's orchestrator candidate from its ci.yml release and
     the pinned base QCOW2, and check them against the image manifest;
  3. build ts-release from the image's source revision and verify the signed
     binary receipt (verify-binary);
  4. import the QCOW2 into OCI (deploy/oci-region/import-image.py: UEFI and
     paravirtualized capability schema, A1-only shapes; idempotent);
  5. create the image candidate for the imported OCID; with
     --image-delegation (the root-signed delegation extended to that OCID),
     sign it with the delegated leaf key (sign-image, which re-checks the
     ci.yml run through the pinned fj) and verify it (verify-image);
  6. write promotion-receipt.json with every digest, identity and tool used.

The root owner can only extend a delegation to an image once its OCID
exists, so a first run without --image-delegation stops after the import
and prints the sign-delegation command for that OCID. Rerun with the new
delegation: every gate runs again and the import finds the same image.

--dry-run performs every read-only gate, builds the image candidate against a
placeholder OCID, and skips the OCI import and signing. Run it under
deploy/image/tools.sh (virt-cat); the script re-executes itself there when
virt-cat is missing. fj must be the pinned build with `actions run-detail`
and `actions logs` (--fj, TS_FJ, or the admission build under
~/.local/share/terrascale-controller-bootstrap-20260927).
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REPOSITORY = "TerraScale/ts-orchestrator"
DEFAULT_FJ = Path.home() / ".local/share/terrascale-controller-bootstrap-20260927/fj-admission-pinned-7f44ff1a/bin/fj"
IMAGE_JOB = "build/qualified-gru-arm64-image"
IMAGE_ASSETS = ("terrascale-gru-arm64.qcow2", "guest-kernel", "image-qualification.json", "SHA256SUMS")
BINARY = "terrascale-orchestrator-linux-arm64"
OCI_REGIONS = {"GRU": "sa-saopaulo-1"}


class PromotionError(Exception):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PromotionError(message)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(8 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def step(message: str) -> None:
    print(f"promote-image: {message}", flush=True)


class Promotion:
    def __init__(self, args: argparse.Namespace, work: Path):
        self.args = args
        self.work = work
        self.out: Path = args.out
        self.fj = self.locate_fj()
        self.receipt: dict = {
            "schema": "terrascale.image.promotion.v1",
            "dry_run": args.dry_run,
            "started_at": now(),
            "environment": args.environment,
            "tools": {"fj": {"path": str(self.fj), "sha256": sha256(self.fj)}},
        }

    def locate_fj(self) -> Path:
        candidate = Path(self.args.fj or os.environ.get("TS_FJ") or DEFAULT_FJ)
        require(candidate.is_file() and os.access(candidate, os.X_OK), f"pinned fj not found: {candidate} (--fj)")
        for command in ("run-detail", "logs"):
            result = subprocess.run([str(candidate), "actions", command, "--help"], capture_output=True, check=False)
            require(result.returncode == 0, f"{candidate} lacks the pinned `fj actions {command}` extension")
        return candidate.resolve()

    def run(self, *command: str | Path, capture: bool = False, **kwargs) -> str:
        environment = dict(os.environ, PATH=f"{self.work / 'bin'}{os.pathsep}{os.environ['PATH']}")
        result = subprocess.run([str(part) for part in command], env=environment, text=True,
                                capture_output=capture, check=False, **kwargs)
        if result.returncode:
            detail = (result.stderr or "").strip() if capture else ""
            raise PromotionError(f"{Path(str(command[0])).name} {command[1] if len(command) > 1 else ''} "
                                 f"failed with status {result.returncode}{': ' + detail if detail else ''}")
        return result.stdout if capture else ""

    def download(self, repository: str, tag: str, asset: str, destination: Path) -> Path:
        destination.parent.mkdir(parents=True, exist_ok=True)
        self.run(self.fj, "release", "asset", "download", "-r", repository, tag, asset, "-o", destination,
                 capture=True)
        return destination

    def download_optional(self, repository: str, tag: str, asset: str, destination: Path) -> Path | None:
        try:
            return self.download(repository, tag, asset, destination)
        except PromotionError:
            destination.unlink(missing_ok=True)
            return None

    # 1. Image readback and CI provenance.
    def acquire_image(self) -> dict:
        image_dir = self.out / "image"
        if self.args.image_release:
            tag = self.args.image_release
            require(bool(re.fullmatch(r"image-[0-9a-f]{40}-run-[1-9][0-9]*-attempt-[1-9][0-9]*", tag)),
                    f"not an image release tag: {tag}")
            for asset in IMAGE_ASSETS:
                self.download(REPOSITORY, tag, asset, image_dir / asset)
        else:
            source = self.args.image_dir.resolve()
            image_dir.mkdir(parents=True)
            for asset in IMAGE_ASSETS:
                require((source / asset).is_file(), f"local image directory lacks {asset}")
                shutil.copyfile(source / asset, image_dir / asset)
        sums = {}
        for line in (image_dir / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
            digest, _, name = line.partition("  ")
            sums[name] = digest
        require(sorted(sums) == sorted(IMAGE_ASSETS[:3]), "SHA256SUMS must list exactly the image, kernel and manifest")
        for name, digest in sums.items():
            require(sha256(image_dir / name) == digest, f"image asset differs from SHA256SUMS: {name}")
        manifest = json.loads((image_dir / "image-qualification.json").read_text(encoding="utf-8"))
        require(manifest.get("schema") == "terrascale.image.qualification.v2", "unsupported image manifest schema")
        require(manifest["image"]["sha256"] == sums["terrascale-gru-arm64.qcow2"]
                and manifest["kernel"]["sha256"] == sums["guest-kernel"], "image manifest digests differ from SHA256SUMS")
        builder = manifest["builder"]
        provenance = {"manifest_sha256": sums["image-qualification.json"], "builder": builder}
        if self.args.image_release:
            require(builder.get("kind") == "ci", "an image release must come from image.yml")
            require(tag == f"image-{manifest['source_revision']}-run-{builder['run_id']}-attempt-{builder['run_attempt']}",
                    "image release tag differs from its manifest")
            detail = json.loads(self.run(self.fj, "actions", "run-detail", str(builder["run_number"]), "-r",
                                         REPOSITORY, capture=True))
            jobs = [job for job in detail.get("jobs", []) if job.get("id") == builder["job_id"]]
            require(detail.get("run_id") == builder["run_id"] and detail.get("workflow") == "image.yml"
                    and detail.get("status") == "success", "image.yml run did not succeed")
            require(len(jobs) == 1 and jobs[0].get("name") == IMAGE_JOB and jobs[0].get("status") == "success"
                    and jobs[0].get("attempt") == builder["run_attempt"], "image job did not succeed on this attempt")
            marker = (f"TS_IMAGE_QUALIFICATION_V1 source_sha={manifest['source_revision']} "
                      f"run_id={builder['run_id']} run_number={builder['run_number']} job_id={builder['job_id']} "
                      f"attempt={builder['run_attempt']} image_sha256={manifest['image']['sha256']} "
                      f"kernel_sha256={manifest['kernel']['sha256']} "
                      f"provenance_sha256={sums['image-qualification.json']} tag={tag}")
            logs = self.run(self.fj, "actions", "logs", str(builder["run_number"]), "-r", REPOSITORY, capture=True)
            matches = [line for line in logs.splitlines() if line.rstrip("\r").partition(" ")[2] == marker]
            require(len(matches) == 1, "image job log lacks one exact TS_IMAGE_QUALIFICATION_V1 marker")
            provenance["release_tag"] = tag
            provenance["job_log_marker"] = marker
            step(f"image release verified tag={tag} run={builder['run_id']} attempt={builder['run_attempt']}")
        else:
            provenance["image_dir"] = str(self.args.image_dir.resolve())
            step(f"local image verified builder={builder.get('kind')} source={manifest['source_revision']}")
        self.receipt["image"] = {**manifest["image"], "kernel": manifest["kernel"],
                                 "source_revision": manifest["source_revision"],
                                 "source_tree": manifest["source_tree"], "provenance": provenance}
        return manifest

    # 2. Orchestrator candidate and base image.
    def acquire_candidate(self, manifest: dict) -> dict[str, Path]:
        candidate = manifest["go_candidate"]
        tag = candidate["release_tag"]
        directory = self.out / "candidate"
        files = {name: self.download(REPOSITORY, tag, asset, directory / asset) for name, asset in (
            ("qualification", "qualification.json"), ("binary", BINARY))}
        require(sha256(files["qualification"]) == candidate["qualification_sha256"]
                and sha256(files["binary"]) == candidate["binary_sha256"],
                f"candidate release {tag} differs from the image manifest")
        receipt = directory / "binary.receipt.json"
        if self.args.binary_receipt:
            shutil.copyfile(self.args.binary_receipt, receipt)
        elif not self.download_optional(REPOSITORY, tag, f"{self.args.environment}-linux-arm64.receipt.json", receipt):
            receipt = None
        files["binary_receipt"] = receipt
        base = manifest["inputs"]["manifest"]["base"]
        files["base"] = self.download(REPOSITORY, base["release_tag"], "base-image.qcow2", self.out / "base-image.qcow2")
        require(sha256(files["base"]) == base["assets"]["base-image.qcow2"]["sha256"],
                "base QCOW2 differs from the image inputs pin")
        self.receipt["candidate"] = dict(candidate)
        self.receipt["base"] = {"release_tag": base["release_tag"], "oci_image_ocid": base["oci_image_ocid"],
                                "sha256": base["assets"]["base-image.qcow2"]["sha256"]}
        step(f"candidate verified tag={tag} binary_sha256={candidate['binary_sha256']}")
        return files

    # 3. Release tool from the image's own source revision.
    def release_tool(self, source: str) -> Path:
        if self.args.release_tool:
            tool = self.args.release_tool.resolve()
        else:
            checkout = self.work / "source"
            subprocess.run(["git", "-C", str(ROOT), "fetch", "--quiet", "origin", "main"], check=True)
            subprocess.run(["git", "-C", str(ROOT), "worktree", "add", "--quiet", "--detach", str(checkout), source],
                           check=True)
            try:
                tool = self.work / "ts-release"
                subprocess.run(["nice", "-n", "19", "go", "build", "-trimpath", "-buildvcs=true", "-o", str(tool),
                                "./cmd/ts-release"], cwd=checkout, check=True)
            finally:
                subprocess.run(["git", "-C", str(ROOT), "worktree", "remove", "--force", str(checkout)], check=False)
            info = subprocess.run(["go", "version", "-m", str(tool)], capture_output=True, text=True, check=True).stdout
            require(f"vcs.revision={source}" in info and "vcs.modified=false" in info,
                    "ts-release was not built from the clean image source revision")
        require(tool.is_file() and os.access(tool, os.X_OK), f"release tool is not executable: {tool}")
        self.receipt["tools"]["ts_release"] = {"path": str(tool), "sha256": sha256(tool)}
        return tool

    def promote(self) -> None:
        self.out.mkdir(parents=True)
        (self.work / "bin").mkdir()
        (self.work / "bin/fj").symlink_to(self.fj)
        virt_cat = shutil.which("virt-cat")
        require(virt_cat is not None, "virt-cat is required; run under deploy/image/tools.sh")
        self.receipt["tools"]["virt_cat"] = {"path": virt_cat,
                                             "version": self.run(virt_cat, "--version", capture=True).strip()}
        manifest = self.acquire_image()
        files = self.acquire_candidate(manifest)
        tool = self.release_tool(manifest["source_revision"])
        image_dir = self.out / "image"
        image = image_dir / "terrascale-gru-arm64.qcow2"
        kernel = image_dir / "guest-kernel"
        region = manifest["inputs"]["manifest"]["region"]
        trust = ("--delegation", self.args.delegation, "--root-key", self.args.root_key,
                 "--environment", self.args.environment)
        self.receipt["trust"] = {"delegation_sha256": sha256(self.args.delegation),
                                 "root_key_sha256": sha256(self.args.root_key)}

        if files["binary_receipt"] is None:
            unsigned = self.out / "binary-candidate.json"
            self.run(tool, "binary-candidate", "--binary", files["binary"], "--source-revision",
                     manifest["source_revision"], "--qualification", files["qualification"], "--out", unsigned)
            if not self.args.sign_binary:
                require(self.args.dry_run, "the candidate has no signed binary receipt; pass --sign-binary "
                                           "with --signing-key, or --binary-receipt")
                self.receipt["candidate"]["binary_receipt"] = "missing: sign with --sign-binary"
                self.finish("dry run stopped before the image candidate: the binary is not signed yet")
                return
            files["binary_receipt"] = self.out / "binary.receipt.json"
            self.run(tool, "sign-binary", "--candidate", unsigned, "--binary", files["binary"], "--qualification",
                     files["qualification"], "--signing-key", self.args.signing_key, *trust,
                     "--out", files["binary_receipt"])
            step("binary receipt signed")
        self.run(tool, "verify-binary", "--receipt", files["binary_receipt"], "--binary", files["binary"],
                 "--qualification", files["qualification"], *trust)
        self.receipt["candidate"]["binary_receipt_sha256"] = sha256(files["binary_receipt"])
        step("signed binary receipt verified")

        display_name = self.args.display_name or (
            f"terrascale-{region.lower()}-arm64-{manifest['source_revision'][:12]}-{manifest['image']['sha256'][:12]}")
        if self.args.dry_run:
            image_ocid = f"ocid1.image.oc1.{OCI_REGIONS[region]}.dryrun{manifest['image']['sha256'][:32]}"
            self.receipt["oci_import"] = {"skipped": "dry run", "display_name": display_name}
            step(f"dry run: would import {image} as {display_name}")
        else:
            import_record = self.out / "oci-import.json"
            self.run(sys.executable, ROOT / "deploy/oci-region/import-image.py", "--qcow2", image,
                     "--sha256", manifest["image"]["sha256"], "--region", OCI_REGIONS[region],
                     "--compartment-id", self.args.compartment_id, "--namespace", self.args.namespace,
                     "--bucket", self.args.bucket, "--display-name", display_name, "--out", import_record)
            record = json.loads(import_record.read_text(encoding="utf-8"))
            require(record.get("qcow2_sha256") == manifest["image"]["sha256"], "OCI import record differs from image")
            image_ocid = record["image_id"]
            self.receipt["oci_import"] = record
            step(f"imported image_ocid={image_ocid}")

        candidate = self.out / "image-candidate.json"
        self.run(tool, "image-candidate", "--binary-receipt", files["binary_receipt"], "--binary", files["binary"],
                 "--qualification", files["qualification"], *trust, "--image-file", image,
                 "--base-image-ocid", manifest["inputs"]["manifest"]["base"]["oci_image_ocid"],
                 "--base-image-region", region, "--base-image-file", files["base"],
                 "--kernel-release", manifest["kernel"]["release"], "--kernel-file", kernel,
                 "--image-ocid", image_ocid, "--region", region, "--out", candidate)
        self.receipt["image_candidate_sha256"] = sha256(candidate)
        step("image candidate created")
        if self.args.dry_run:
            self.receipt["image_receipt"] = {"skipped": "dry run"}
            self.finish("dry run passed every read-only gate")
            return
        if not self.args.image_delegation:
            self.receipt["image_receipt"] = {"awaiting": "root-signed image delegation", "image_ocid": image_ocid}
            print("promote-image: the root owner extends the delegation to this image with:\n"
                  f"  ts-release sign-delegation --previous-delegation {self.args.delegation} "
                  f"--image-cell {region} --image-ocid {image_ocid} --source-revision {manifest['source_revision']} "
                  "--arch arm64 --environment canary --subject-public-key LEAF.pub "
                  f"--root-key {self.args.root_key} --signing-key ROOT.key --issued-at ... --expires-at ... "
                  "--out image-delegation.json\n"
                  "then rerun this command with --image-delegation image-delegation.json", flush=True)
            self.finish(f"imported {image_ocid}; awaiting the root-signed image delegation")
            return
        image_trust = ("--delegation", self.args.image_delegation, "--root-key", self.args.root_key)
        self.receipt["trust"]["image_delegation_sha256"] = sha256(self.args.image_delegation)
        signed = self.out / "image-receipt.json"
        self.run(tool, "sign-image", "--candidate", candidate, "--binary-receipt", files["binary_receipt"],
                 "--binary", files["binary"], "--qualification", files["qualification"], "--image-file", image,
                 "--base-image-file", files["base"], "--kernel-file", kernel, "--signing-key",
                 self.args.signing_key, *image_trust, "--environment", self.args.environment, "--out", signed)
        verified = self.run(tool, "verify-image", "--receipt", signed, *image_trust, "--image-file", image,
                            "--base-image-file", files["base"], "--kernel-file", kernel, "--region", region,
                            "--environment", self.args.environment, capture=True).strip()
        self.receipt["image_receipt"] = {"path": str(signed), "sha256": sha256(signed),
                                         "image_ocid": image_ocid, "verify_image": verified}
        step(verified)
        self.finish("promotion complete")

    def finish(self, outcome: str) -> None:
        self.receipt["outcome"] = outcome
        self.receipt["finished_at"] = now()
        receipt_path = self.out / "promotion-receipt.json"
        receipt_path.write_text(json.dumps(self.receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        step(f"{outcome}; receipt {receipt_path} sha256={sha256(receipt_path)}")


def now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0],
                                     formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--image-release", help="retained image release tag from image.yml")
    source.add_argument("--image-dir", type=Path, help="local build directory from make image")
    parser.add_argument("--out", type=Path, required=True, help="new directory for downloads and the receipt")
    parser.add_argument("--environment", default="canary", choices=("canary", "production"))
    parser.add_argument("--delegation", type=Path, required=True,
                        help="root-signed release delegation for the binary's source revision")
    parser.add_argument("--image-delegation", type=Path,
                        help="the delegation extended to the imported image OCID (signs the image)")
    parser.add_argument("--root-key", type=Path, required=True, help="release root public key PEM")
    parser.add_argument("--binary-receipt", type=Path, help="signed binary receipt (default: from the CI release)")
    parser.add_argument("--signing-key", type=Path, help="delegated leaf private key PEM (to sign)")
    parser.add_argument("--sign-binary", action="store_true",
                        help="sign the binary with --signing-key when its CI release has no receipt")
    parser.add_argument("--compartment-id", help="OCI compartment for the imported image")
    parser.add_argument("--namespace", help="Object Storage namespace for the QCOW2 upload")
    parser.add_argument("--bucket", help="Object Storage bucket for the QCOW2 upload")
    parser.add_argument("--display-name", help="OCI image display name (default: derived from source and digest)")
    parser.add_argument("--fj", help="pinned fj with actions run-detail/logs")
    parser.add_argument("--release-tool", type=Path, help="prebuilt ts-release (default: built from the image source)")
    parser.add_argument("--dry-run", action="store_true", help="run every read-only gate; skip import and signing")
    args = parser.parse_args()
    if not args.dry_run:
        missing = [flag for flag, value in (("--compartment-id", args.compartment_id),
                                            ("--namespace", args.namespace), ("--bucket", args.bucket)) if not value]
        if missing:
            parser.error(f"an OCI import needs {', '.join(missing)} (or use --dry-run)")
    if (args.sign_binary or args.image_delegation) and not args.signing_key:
        parser.error("--sign-binary and --image-delegation need --signing-key")
    if args.dry_run and args.image_delegation:
        parser.error("--dry-run never signs the image; drop --image-delegation")
    if args.out.exists():
        parser.error(f"--out must be a new directory: {args.out}")
    return args


def main() -> int:
    args = parse_arguments()
    if shutil.which("virt-cat") is None and "TS_IMAGE_TOOLS_ID" not in os.environ:
        os.execvp("bash", ["bash", str(ROOT / "deploy/image/tools.sh"), sys.executable, *sys.argv])
    with tempfile.TemporaryDirectory(prefix="ts-promote-") as work:
        try:
            Promotion(args, Path(work)).promote()
        except (PromotionError, KeyError, ValueError, subprocess.CalledProcessError) as error:
            print(f"promote-image: FAILED: {error}", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
