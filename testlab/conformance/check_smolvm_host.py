#!/usr/bin/env python3
"""Perform read-only SmolVM pin and host checks without starting a VM or API server."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import platform
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PIN = ROOT / "testlab" / "pins" / "smolvm-v1.5.0.json"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def run_read_only(executable: str, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [executable, *arguments],
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )


def check(name: str, passed: bool, observed: Any, expected: Any) -> dict[str, Any]:
    return {
        "name": name,
        "passed": passed,
        "observed": observed,
        "expected": expected,
    }


def inspect(pin_path: Path) -> dict[str, Any]:
    pin = json.loads(pin_path.read_text(encoding="utf-8"))
    checks: list[dict[str, Any]] = []

    executable = shutil.which(pin["runtime"])
    checks.append(check("runtime-on-path", executable is not None, executable is not None, True))
    if executable is None:
        return report(pin_path, pin, checks)

    launcher = Path(executable).resolve()
    distribution_root = launcher.parent

    version_result = run_read_only(executable, "--version")
    version_output = (version_result.stdout or version_result.stderr).strip()
    observed_version = version_output.removeprefix(f'{pin["runtime"]} ').strip()
    checks.append(
        check(
            "runtime-version",
            version_result.returncode == 0 and observed_version == pin["version"],
            observed_version,
            pin["version"],
        )
    )

    for artifact in pin["distributionArtifacts"]:
        artifact_path = distribution_root / artifact["path"]
        exists = artifact_path.is_file()
        observed_digest = sha256(artifact_path) if exists else None
        checks.append(
            check(
                f'artifact-sha256:{artifact["role"]}',
                exists and observed_digest == artifact["sha256"],
                observed_digest,
                artifact["sha256"],
            )
        )

    observed_os = platform.system().lower()
    expected_os = pin["hostPlatform"]["operatingSystem"]
    checks.append(check("host-operating-system", observed_os == expected_os, observed_os, expected_os))

    observed_arch = platform.machine().lower()
    expected_arch = pin["hostPlatform"]["architecture"]
    checks.append(check("host-architecture", observed_arch == expected_arch, observed_arch, expected_arch))

    kvm_path = Path("/dev/kvm")
    kvm_is_character_device = kvm_path.exists() and stat.S_ISCHR(kvm_path.stat().st_mode)
    kvm_accessible = kvm_is_character_device and os.access(kvm_path, os.R_OK | os.W_OK)
    checks.append(check("kvm-character-device", kvm_is_character_device, kvm_is_character_device, True))
    checks.append(check("kvm-user-access", kvm_accessible, kvm_accessible, True))
    observed_kvm_api_version = None
    if kvm_accessible:
        try:
            descriptor = os.open(kvm_path, os.O_RDWR | os.O_CLOEXEC)
            try:
                # KVM_GET_API_VERSION = _IO(KVMIO, 0x00); this does not create a VM.
                observed_kvm_api_version = fcntl.ioctl(descriptor, 0xAE00)
            finally:
                os.close(descriptor)
        except OSError:
            pass
    expected_kvm_api_version = pin["hostPlatform"]["kvmApiVersion"]
    checks.append(
        check(
            "kvm-api-version",
            observed_kvm_api_version == expected_kvm_api_version,
            observed_kvm_api_version,
            expected_kvm_api_version,
        )
    )

    api_result = run_read_only(executable, *pin["api"]["discoveryCommand"])
    try:
        api_document = json.loads(api_result.stdout) if api_result.returncode == 0 else {}
    except json.JSONDecodeError:
        api_document = {}
    observed_openapi_version = api_document.get("openapi")
    checks.append(
        check(
            "api-openapi-version",
            observed_openapi_version == pin["api"]["openapiVersion"],
            observed_openapi_version,
            pin["api"]["openapiVersion"],
        )
    )
    observed_paths = sorted(api_document.get("paths", {}).keys())
    expected_paths = sorted(pin["api"]["requiredPaths"])
    checks.append(
        check(
            "api-required-paths",
            all(path in observed_paths for path in expected_paths),
            observed_paths,
            expected_paths,
        )
    )

    return report(pin_path, pin, checks)


def report(pin_path: Path, pin: dict[str, Any], checks: list[dict[str, Any]]) -> dict[str, Any]:
    try:
        displayed_pin = str(pin_path.relative_to(ROOT))
    except ValueError:
        displayed_pin = str(pin_path)
    return {
        "schemaVersion": 1,
        "pin": displayed_pin,
        "runtime": pin["runtime"],
        "version": pin["version"],
        "passed": all(item["passed"] for item in checks),
        "checks": checks,
        "untestedGates": [
            "No VM or system under test was created, started, stopped, or queried.",
            "The HTTP API schema was exported, but no API server was started and no live request was sent.",
            "Guest boot, networking, persistence, fault injection, and nine-VM GRU/FRA/SFO topology remain gated.",
            "Real systemd-as-PID-1 behavior remains gated.",
            "linux-arm64 and real OCI A1/IAM/block-volume/storage-performance boundaries remain gated.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pin", type=Path, default=DEFAULT_PIN)
    parser.add_argument("--output", type=Path, help="Write the same deterministic JSON emitted on stdout")
    arguments = parser.parse_args()

    result = inspect(arguments.pin.resolve())
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if arguments.output:
        arguments.output.write_text(rendered, encoding="utf-8")
    sys.stdout.write(rendered)
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
