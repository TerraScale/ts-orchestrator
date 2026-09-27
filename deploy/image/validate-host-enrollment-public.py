#!/usr/bin/env python3
"""Validate the reviewed, image-pinned public host enrollment bundle."""

import base64
import binascii
import hashlib
import ipaddress
import json
import re
import ssl
import sys
from pathlib import Path
from urllib.parse import urlsplit


FIELDS = {
    "schema_version", "cell", "region", "controller_endpoints", "nats_urls",
    "ca_pem", "controller_response_public_key", "cell_account_nkey",
    "environment", "install_root", "state_root", "managed_runtime_root",
    "workload_uid", "workload_gid",
}
REGIONS = {"gru": "GRU", "sfo": "SFO", "fra": "FRA"}
PRIVATE_NETWORKS = tuple(ipaddress.ip_network(cidr) for cidr in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))


def object_without_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON member: {key}")
        result[key] = value
    return result


def private_ip(raw):
    address = ipaddress.ip_address(raw)
    if not isinstance(address, ipaddress.IPv4Address) or not any(
        address in network for network in PRIVATE_NETWORKS
    ):
        raise ValueError("endpoint must be a private non-loopback IPv4 address")
    return str(address)


def absolute_clean_path(raw):
    if not isinstance(raw, str) or not raw.startswith("/") or raw == "/" or "\x00" in raw:
        raise ValueError("host path must be an absolute directory path")
    if any(part in ("", ".", "..") for part in raw[1:].split("/")):
        raise ValueError("host path must be clean")
    return raw


def validate(path, expected_digest, environment, identity_cell):
    wire = Path(path).read_bytes()
    if not 0 < len(wire) <= 16 << 10:
        raise ValueError("public bundle must be between 1 byte and 16 KiB")
    actual_digest = hashlib.sha256(wire).hexdigest()
    if actual_digest != expected_digest:
        raise ValueError("public bundle differs from its reviewed SHA-256")
    bundle = json.loads(wire, object_pairs_hook=object_without_duplicates)
    if not isinstance(bundle, dict) or set(bundle) != FIELDS:
        raise ValueError("public bundle members differ from schema version 1")
    if type(bundle["schema_version"]) is not int or bundle["schema_version"] != 1:
        raise ValueError("public bundle schema_version must be 1")
    cell = bundle["cell"]
    if not isinstance(cell, str) or cell not in REGIONS or bundle["region"] != REGIONS[cell]:
        raise ValueError("public bundle cell and region differ")
    if bundle["region"] != identity_cell:
        raise ValueError("public bundle region differs from bootstrap identity")
    if bundle["environment"] != environment:
        raise ValueError("public bundle environment differs from release environment")
    for key in ("workload_uid", "workload_gid"):
        if type(bundle[key]) is not int or not 0 < bundle[key] < 4294967295:
            raise ValueError(f"public bundle {key} must be a nonzero Linux ID")
    paths = [absolute_clean_path(bundle[key]) for key in (
        "install_root", "state_root", "managed_runtime_root")]
    for index, left in enumerate(paths):
        for right in paths[index + 1:]:
            if left == right or left.startswith(right + "/") or right.startswith(left + "/"):
                raise ValueError("public bundle host paths overlap")
    key = bundle["controller_response_public_key"]
    if not isinstance(key, str) or len(base64.b64decode(key, validate=True)) != 32:
        raise ValueError("public bundle response key must be Ed25519 public key bytes")
    account = bundle["cell_account_nkey"]
    if not isinstance(account, str) or not re.fullmatch(r"A[A-Z2-7]{55}", account):
        raise ValueError("public bundle cell account key is invalid")
    account_raw = base64.b32decode(account)
    if len(account_raw) != 35 or account_raw[0] != 0 or binascii.crc_hqx(account_raw[:-2], 0) != int.from_bytes(account_raw[-2:], "little"):
        raise ValueError("public bundle cell account key has an invalid checksum")
    pem = bundle["ca_pem"]
    if not isinstance(pem, str) or not re.fullmatch(
        r"-----BEGIN CERTIFICATE-----\n(?:[A-Za-z0-9+/=]+\n)+-----END CERTIFICATE-----\n?", pem
    ):
        raise ValueError("public bundle must contain one CA PEM certificate")
    ssl.PEM_cert_to_DER_cert(pem)
    controllers = bundle["controller_endpoints"]
    nats_urls = bundle["nats_urls"]
    if not isinstance(controllers, list) or not isinstance(nats_urls, list) or len(controllers) != 3 or len(nats_urls) != 3:
        raise ValueError("public bundle requires three controller and NATS endpoints")
    controller_ips = []
    nats_ips = []
    for endpoint in controllers:
        if not isinstance(endpoint, str) or not endpoint.endswith(":8443"):
            raise ValueError("controller endpoint must use port 8443")
        controller_ips.append(private_ip(endpoint.removesuffix(":8443")))
    for raw in nats_urls:
        if not isinstance(raw, str):
            raise ValueError("NATS URL must be a string")
        parsed = urlsplit(raw)
        if parsed.scheme != "tls" or parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment or not parsed.netloc.endswith(":4222"):
            raise ValueError("NATS URL must be a direct TLS endpoint on port 4222")
        nats_ips.append(private_ip(parsed.netloc.removesuffix(":4222")))
    if len(set(controller_ips)) != 3 or len(set(nats_ips)) != 3 or sorted(controller_ips) != sorted(nats_ips):
        raise ValueError("controller and NATS IP sets must match exactly")
    print(f"host enrollment public bundle sha256={actual_digest} region={identity_cell}")


if __name__ == "__main__":
    if len(sys.argv) != 5:
        raise SystemExit("usage: validate-host-enrollment-public.py FILE SHA256 ENVIRONMENT CELL")
    try:
        validate(*sys.argv[1:])
    except (ValueError, TypeError, UnicodeError, OSError) as error:
        raise SystemExit(f"invalid host enrollment public bundle: {error}") from error
