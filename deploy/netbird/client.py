#!/usr/bin/env python3
"""Fetch and extract only the checksum-pinned NetBird client executable."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import struct
import sys
import tarfile
import tempfile
import urllib.request
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[2]
INPUTS = ROOT / "deploy/image/image-inputs.json"
SHA256 = re.compile(r"[0-9a-f]{64}")
MAX_BINARY_BYTES = 128 << 20


def sha256(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def validate_pin(pin: dict) -> None:
    if tuple(pin) != ("version", "archives", "enrollment_config") or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", pin["version"]):
        raise ValueError("NetBird pin needs version, archives and enrollment_config")
    if tuple(pin["archives"]) != ("arm64", "amd64"):
        raise ValueError("NetBird archives must pin arm64 and amd64")
    for architecture, archive in pin["archives"].items():
        url = f"https://github.com/netbirdio/netbird/releases/download/v{pin['version']}/netbird_{pin['version']}_linux_{architecture}.tar.gz"
        if tuple(archive) != ("url", "bytes", "sha256", "binary_sha256") or archive["url"] != url:
            raise ValueError(f"invalid NetBird {architecture} archive source")
        if type(archive["bytes"]) is not int or not 0 < archive["bytes"] <= MAX_BINARY_BYTES:
            raise ValueError(f"invalid NetBird {architecture} archive size")
        if any(not SHA256.fullmatch(str(archive[key])) for key in ("sha256", "binary_sha256")):
            raise ValueError(f"invalid NetBird {architecture} SHA-256")


def validate_config(path: Path) -> dict:
    if path.stat().st_size > 16384:
        raise ValueError("NetBird enrollment configuration is too large")
    config = json.loads(path.read_text(encoding="utf-8"))
    required = {"management_url", "region", "setup_key_secret_id"}
    if not isinstance(config, dict) or not required <= config.keys() or config.keys() - required - {"management_ip"}:
        raise ValueError("NetBird enrollment configuration has unexpected or missing fields")
    url = urlsplit(config["management_url"])
    if (url.scheme != "https" or url.netloc not in ("netbird.terrascale.tech", "netbird.terrascale.tech:443")
            or "?" in config["management_url"] or "#" in config["management_url"] or url.path not in ("", "/")):
        raise ValueError("NetBird management_url must be https://netbird.terrascale.tech")
    if not re.fullmatch(r"[a-z]{2}-[a-z]+-[1-9][0-9]*", config["region"]):
        raise ValueError("NetBird region must be an OCI region name")
    prefix = "ocid1.vaultsecret.oc1." + config["region"] + "."
    secret = config["setup_key_secret_id"]
    if (len(secret) > 255 or not secret.startswith(prefix)
            or not re.fullmatch(r"[a-z0-9]+(?:\.[a-z0-9]+)*", secret.removeprefix(prefix))):
        raise ValueError("NetBird setup_key_secret_id must identify an OCI Vault secret in the configured region")
    if "management_ip" in config:
        address = ipaddress.ip_address(config["management_ip"])
        networks = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")
        if (getattr(address, "scope_id", None) or getattr(address, "ipv4_mapped", None)
                or not any(address in ipaddress.ip_network(network) for network in networks)):
            raise ValueError("NetBird management_ip must be a private IPv4 or IPv6 address")
    return config


def verify_binary(path: Path, expected: str, architecture: str) -> None:
    if not SHA256.fullmatch(expected):
        raise ValueError("NetBird binary SHA-256 must be 64 lowercase hex characters")
    if not path.is_file() or path.is_symlink() or not 64 <= path.stat().st_size <= MAX_BINARY_BYTES:
        raise ValueError("NetBird binary must be a regular executable between 64 bytes and 128 MiB")
    with path.open("rb") as source:
        header = source.read(64)
    machine = {"arm64": 183, "amd64": 62}[architecture]
    if (header[:7] != b"\x7fELF\x02\x01\x01" or struct.unpack_from("<H", header, 16)[0] not in (2, 3)
            or struct.unpack_from("<H", header, 18)[0] != machine
            or struct.unpack_from("<I", header, 20)[0] != 1
            or struct.unpack_from("<H", header, 52)[0] != 64):
        raise ValueError(f"NetBird binary must be an ELF64 little-endian {architecture} executable")
    if sha256(path) != expected:
        raise ValueError("NetBird binary bytes differ from the pinned SHA-256")


def archive_matches(path: Path, pin: dict) -> bool:
    return (path.is_file() and not path.is_symlink() and path.stat().st_size == pin["bytes"]
            and sha256(path) == pin["sha256"])


def download(pin: dict, path: Path) -> None:
    request = urllib.request.Request(pin["url"], headers={"User-Agent": "TerraScale-image-builder"})
    with urllib.request.urlopen(request, timeout=60) as response, path.open("xb") as output:
        total = 0
        while chunk := response.read(1 << 20):
            total += len(chunk)
            if total > pin["bytes"]:
                raise ValueError("NetBird archive exceeds its pinned size")
            output.write(chunk)
    if not archive_matches(path, pin):
        raise ValueError("NetBird archive bytes differ from the pinned SHA-256 or size")


def extract(archive: Path, destination: Path, pin: dict, architecture: str) -> None:
    # No archive path is extracted: only the single root-level regular binary
    # is streamed into our chosen file, so traversal and links are inert.
    with tarfile.open(archive, "r:gz") as source:
        members = [member for member in source.getmembers() if member.name == "netbird"]
        if len(members) != 1 or not members[0].isfile() or not 64 <= members[0].size <= MAX_BINARY_BYTES:
            raise ValueError("NetBird archive must contain one regular root-level netbird executable")
        with source.extractfile(members[0]) as binary, destination.open("xb") as output:
            shutil.copyfileobj(binary, output)
    verify_binary(destination, pin["binary_sha256"], architecture)
    destination.chmod(0o755)


def fetch(pin: dict, architecture: str, output: Path, cache: Path | None = None) -> None:
    validate_pin(pin)
    archive_pin = pin["archives"][architecture]
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".netbird-", dir=output.parent) as directory:
        work = Path(directory)
        archive = work / "netbird.tar.gz"
        cached = cache / archive_pin["sha256"] if cache else None
        if cached and archive_matches(cached, archive_pin):
            shutil.copyfile(cached, archive)
        else:
            download(archive_pin, archive)
            if cached:
                cache.mkdir(parents=True, exist_ok=True)
                with tempfile.NamedTemporaryFile(prefix=".netbird-cache-", dir=cache, delete=False) as temporary:
                    cache_temp = Path(temporary.name)
                try:
                    shutil.copyfile(archive, cache_temp)
                    os.replace(cache_temp, cached)
                finally:
                    cache_temp.unlink(missing_ok=True)
        if not archive_matches(archive, archive_pin):
            raise ValueError("NetBird archive bytes differ from the pinned SHA-256 or size")
        binary = work / "netbird"
        extract(archive, binary, archive_pin, architecture)
        os.replace(binary, output)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", type=Path, default=INPUTS)
    commands = parser.add_subparsers(dest="command", required=True)
    fetch_parser = commands.add_parser("fetch")
    fetch_parser.add_argument("--architecture", choices=("arm64", "amd64"), required=True)
    fetch_parser.add_argument("--out", type=Path, required=True)
    fetch_parser.add_argument("--cache", type=Path, default=os.environ.get("TS_NETBIRD_CLIENT_CACHE"))
    verify_parser = commands.add_parser("verify-binary")
    verify_parser.add_argument("--architecture", choices=("arm64", "amd64"), required=True)
    verify_parser.add_argument("--binary", type=Path, required=True)
    verify_parser.add_argument("--sha256", required=True)
    config_parser = commands.add_parser("check-config")
    config_parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "fetch":
            pin = json.loads(args.inputs.read_text())["netbird"]
            fetch(pin, args.architecture, args.out, args.cache)
            print(f"NetBird client version={pin['version']} architecture={args.architecture} sha256={sha256(args.out)}")
        elif args.command == "verify-binary":
            verify_binary(args.binary, args.sha256, args.architecture)
        else:
            validate_config(args.config)
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError) as error:
        print(f"netbird-client: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
