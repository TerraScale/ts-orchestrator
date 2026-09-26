#!/usr/bin/env python3
"""Prepare a disposable ext4 base for the offline production restart packet."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


def run(*args: str, timeout: int = 300) -> str:
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"{args[0]} exited {result.returncode}: {result.stderr[-1200:]}")
    return result.stdout.strip()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(4 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source-root", "rootfs", "binary", "client-public", "host-private", "host-public",
                 "output", "known-hosts"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--rootfs-sha256", required=True)
    parser.add_argument("--binary-sha256", required=True)
    return parser.parse_args()


def main() -> None:
    args = arguments()
    if os.geteuid() != 0:
        raise RuntimeError("offline ext4 preparation requires root")
    for name in ("source_root", "rootfs", "binary", "client_public", "host_private", "host_public"):
        path = getattr(args, name).resolve(strict=True)
        if name != "source_root" and not path.is_file():
            raise ValueError(f"{name} is not a regular file")
        setattr(args, name, path)
    if sha256(args.rootfs) != args.rootfs_sha256 or sha256(args.binary) != args.binary_sha256:
        raise ValueError("base or production executable differs from its reviewed SHA-256")
    if args.output.exists() or args.known_hosts.exists() or args.output.resolve() == args.rootfs:
        raise ValueError("base output and known-hosts output must be new paths")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.known_hosts.parent.mkdir(parents=True, exist_ok=True)
    host_public = args.host_public.read_text().strip()
    derived_public = run("ssh-keygen", "-y", "-f", str(args.host_private))
    if host_public.split()[:2] != derived_public.split()[:2]:
        raise ValueError("host SSH public key differs from private key")
    client_public = args.client_public.read_text().strip()
    if not client_public.startswith("ssh-ed25519 "):
        raise ValueError("client SSH key must be Ed25519")
    run("cp", "--reflink=never", "--sparse=always", str(args.rootfs), str(args.output), timeout=600)
    if sha256(args.output) != args.rootfs_sha256 or args.output.samefile(args.rootfs):
        raise RuntimeError("disposable ext4 copy differs from pinned base")
    mount = Path(tempfile.mkdtemp(prefix="tspr-base-", dir=str(args.output.parent)))
    mounted = False
    try:
        run("mount", "-o", "loop", str(args.output), str(mount))
        mounted = True
        sysusers = args.source_root / "deploy/image/terrascale-orchestrator.sysusers"
        destination = mount / "etc/sysusers.d/terrascale-orchestrator.conf"
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(sysusers, destination)
        destination.chmod(0o644)
        run("systemd-sysusers", f"--root={mount}")
        for unit in ("bootstrap", "controller"):
            name = f"terrascale-orchestrator-{unit}.service"
            installed = mount / "etc/systemd/system" / name
            shutil.copyfile(args.source_root / "deploy/systemd" / name, installed)
            installed.chmod(0o644)
        timeout_file = mount / "etc/systemd/system/systemd-time-wait-sync.service.d/terrascale-timeout.conf"
        timeout_file.parent.mkdir(parents=True, exist_ok=True)
        timeout_file.write_text("[Service]\nTimeoutStartSec=300s\n")
        timeout_file.chmod(0o644)
        executable = mount / "usr/local/bin/terrascale-orchestrator"
        executable.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(args.binary, executable)
        executable.chmod(0o755)
        authorized = mount / "root/.ssh/authorized_keys"
        authorized.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        authorized.parent.chmod(0o700)
        authorized.write_text(client_public + "\n")
        authorized.chmod(0o600)
        ssh_host_private = mount / "etc/ssh/ssh_host_ed25519_key"
        shutil.copyfile(args.host_private, ssh_host_private)
        ssh_host_private.chmod(0o600)
        shutil.copyfile(args.host_public, mount / "etc/ssh/ssh_host_ed25519_key.pub")
        for unit in ("systemd-networkd.service", "systemd-timesyncd.service",
                     "systemd-time-wait-sync.service", "terrascale-orchestrator-controller.service",
                     "ssh.service"):
            run("systemctl", f"--root={mount}", "enable", unit)
            enabled = run("systemctl", f"--root={mount}", "is-enabled", unit)
            if enabled != "enabled":
                raise RuntimeError(f"{unit} was not enabled: {enabled}")
        passwd = (mount / "etc/passwd").read_text()
        group = (mount / "etc/group").read_text()
        user = [line.split(":") for line in passwd.splitlines() if line.startswith("terrascale-orchestrator:")]
        groups = [line.split(":") for line in group.splitlines() if line.startswith("terrascale-orchestrator:")]
        if len(user) != 1 or len(groups) != 1 or user[0][3] != groups[0][2]:
            raise RuntimeError("guest service account was not created with a matching primary group")
        print(f"service uid={user[0][2]} gid={user[0][3]}")
    finally:
        if mounted:
            run("umount", str(mount))
        mount.rmdir()
    host_key = " ".join(host_public.split()[:2])
    args.known_hosts.write_text("".join(f"{address} {host_key}\n" for address in
                                        ("10.44.0.10", "10.44.0.11", "10.44.0.12")))
    args.known_hosts.chmod(0o644)
    owner = args.output.parent.stat()
    os.chown(args.output, owner.st_uid, owner.st_gid)
    os.chown(args.known_hosts, owner.st_uid, owner.st_gid)
    print(f"base ext4 sha256={sha256(args.output)}")
    print(f"known-hosts sha256={sha256(args.known_hosts)}")


if __name__ == "__main__":
    main()
