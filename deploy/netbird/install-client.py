#!/usr/bin/env python3
"""Install NetBird and a separate enrollment command without replacing the running orchestrator."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("netbird_client", Path(__file__).with_name("client.py"))
client = importlib.util.module_from_spec(spec)
spec.loader.exec_module(client)
UNITS = ("netbird.service", "terrascale-netbird-enroll.service")
ENROLL_BINARY = "/usr/local/lib/terrascale-orchestrator/netbird-enroll"


def directory(root: Path, path: str, mode: int = 0o755, *, enforce_mode: bool = False) -> Path:
    destination = root
    parts = Path(path).parts[1:]
    for part in parts:
        destination /= part
        if destination.is_symlink() or (destination.exists() and not destination.is_dir()):
            raise ValueError(f"installation parent must be a direct directory: {destination}")
        if not destination.exists():
            destination.mkdir(mode=mode if part == parts[-1] else 0o755)
    if enforce_mode:
        destination.chmod(mode)
    return destination


def install(source: Path, destination: Path, mode: int) -> None:
    if destination.is_symlink() or (destination.exists() and not destination.is_file()):
        raise ValueError(f"installation destination must be a direct file: {destination}")
    with tempfile.NamedTemporaryFile(prefix=".netbird-install-", dir=destination.parent, delete=False) as output:
        staged = Path(output.name)
    try:
        shutil.copyfile(source, staged)
        staged.chmod(mode)
        os.replace(staged, destination)
    finally:
        staged.unlink(missing_ok=True)


def systemctl(*arguments: str, allow_failure: bool = False) -> subprocess.CompletedProcess:
    result = subprocess.run(("systemctl", *arguments), capture_output=True, text=True, check=False)
    if result.returncode and not allow_failure:
        raise ValueError(f"systemctl {' '.join(arguments)}: {result.stderr.strip() or result.stdout.strip()}")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True, help="public enrollment config, never a setup key")
    parser.add_argument("--enroll-binary", type=Path, required=True, help="new orchestrator binary staged only for enrollment")
    parser.add_argument("--enroll-sha256", required=True, help="independently verified SHA-256 of enrollment binary")
    parser.add_argument("--client-binary", type=Path, help="already fetched client; checked against the pinned binary digest")
    parser.add_argument("--architecture", choices=("arm64", "amd64"), default={"aarch64": "arm64", "x86_64": "amd64"}.get(platform.machine()))
    parser.add_argument("--inputs", type=Path, default=client.INPUTS)
    parser.add_argument("--cache", type=Path, default=os.environ.get("TS_NETBIRD_CLIENT_CACHE"))
    parser.add_argument("--root", type=Path, default=Path("/"), help="stage into an offline root instead of the live machine")
    args = parser.parse_args()
    try:
        if args.architecture is None:
            raise ValueError("unsupported host architecture")
        root = args.root.resolve(strict=True)
        live = root == Path("/")
        if live and os.geteuid() != 0:
            raise ValueError("live NetBird installation must run as root")
        client.validate_config(args.config)
        pin = json.loads(args.inputs.read_text(encoding="utf-8"))["netbird"]
        client.validate_pin(pin)
        client.verify_binary(args.enroll_binary, args.enroll_sha256, args.architecture)
        with tempfile.TemporaryDirectory(prefix="ts-netbird-install-") as temporary:
            work = Path(temporary)
            client_binary = args.client_binary or work / "netbird"
            if args.client_binary is None:
                client.fetch(pin, args.architecture, client_binary, args.cache)
            client.verify_binary(client_binary, pin["archives"][args.architecture]["binary_sha256"], args.architecture)
            daemon_active = live and systemctl("is-active", "--quiet", "netbird.service", allow_failure=True).returncode == 0
            for path in ("/usr/local/bin", "/usr/local/lib/terrascale-orchestrator", "/etc/terrascale-orchestrator", "/etc/systemd/system"):
                directory(root, path)
            directory(root, "/var/lib/netbird", 0o700, enforce_mode=True)
            install(client_binary, root / "usr/local/bin/netbird", 0o755)
            install(args.enroll_binary, root / ENROLL_BINARY.lstrip("/"), 0o755)
            install(args.config, root / "etc/terrascale-orchestrator/netbird.json", 0o644)
            for name in UNITS:
                install(ROOT / "deploy/systemd" / name, root / "etc/systemd/system" / name, 0o644)
            dropin = directory(root, "/etc/systemd/system/terrascale-netbird-enroll.service.d")
            override = work / "command.conf"
            override.write_text(f"[Service]\nExecStart=\nExecStart={ENROLL_BINARY} netbird-enroll --config /etc/terrascale-orchestrator/netbird.json\n", encoding="utf-8")
            install(override, dropin / "command.conf", 0o644)
            if live:
                systemctl("daemon-reload")
                systemctl("enable", *UNITS)
                systemctl("restart" if daemon_active else "start", "netbird.service")
                systemctl("--no-block", "restart", "terrascale-netbird-enroll.service")
            else:
                wants = directory(root, "/etc/systemd/system/multi-user.target.wants")
                for name in UNITS:
                    link = wants / name
                    target = f"../{name}"
                    if link.is_symlink() and os.readlink(link) == target:
                        continue
                    if link.is_symlink() or link.exists():
                        raise ValueError(f"service enablement destination already exists: {link}")
                    link.symlink_to(target)
        print(f"NetBird {pin['version']} installed; enrollment {'started' if live else 'enabled in offline root'}")
        return 0
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"netbird-install: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
