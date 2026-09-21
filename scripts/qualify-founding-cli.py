#!/usr/bin/env python3
"""Qualify published founding commands offline; never submit a valid grant to OCI."""

import argparse
import base64
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile


def invoke(arguments, expected=0, env=None):
    result = subprocess.run(arguments, capture_output=True, text=True, timeout=15, env=env)
    if result.returncode != expected:
        raise RuntimeError(f"{Path(arguments[0]).name} exited {result.returncode}, expected {expected}")
    return result.stdout


def artifact(path, expected_machine):
    with path.open("rb") as source:
        header = source.read(20)
        if header[:6] != b"\x7fELF\x02\x01" or int.from_bytes(header[18:20], "little") != expected_machine:
            raise ValueError("Expected a little-endian ELF64 artifact for the requested architecture")
        source.seek(0)
        digest = hashlib.file_digest(source, "sha256").hexdigest()
    return {"sha256": digest, "bytes": path.stat().st_size, "elfMachine": expected_machine}


def der_signature(signature):
    if len(signature) != 64:
        raise ValueError("Expected the P-256 P1363 signature")
    integers = []
    for half in (signature[:32], signature[32:]):
        value = half.lstrip(b"\0") or b"\0"
        if value[0] & 128:
            value = b"\0" + value
        integers.append(b"\x02" + bytes([len(value)]) + value)
    content = b"".join(integers)
    return b"\x30" + bytes([len(content)]) + content


def qualify(x64, arm64):
    artifacts = {"linux-x64": artifact(x64, 62), "linux-arm64": artifact(arm64, 183)}
    with tempfile.TemporaryDirectory(prefix="ts-founding-cli-") as temporary:
        root = Path(temporary)
        private = root / "ci-private.pem"
        public = root / "ci-public.pem"
        invoke(["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-out", str(private)])
        invoke(["openssl", "pkey", "-in", str(private), "-pubout", "-out", str(public)])
        now = datetime.datetime.now(datetime.timezone.utc)
        bootstrap = b"#cloud-config\nruncmd: []\n"
        purpose = "terrascale-oci-gru-founding-peers-v1"
        plan = {
            "schemaVersion": 1, "purpose": purpose, "bootstrapId": "a" * 32,
            "regionIntentGeneration": 1, "region": "GRU",
            "seedInstanceId": "ocid1.instance.oc1.sa-saopaulo-1.synthetic-seed",
            "compartmentId": "ocid1.compartment.oc1..synthetic-control",
            "availabilityDomain": "SYNTHETIC:SA-SAOPAULO-1-AD-1", "seedFaultDomain": "FAULT-DOMAIN-1",
            "subnetId": "ocid1.subnet.oc1.sa-saopaulo-1.synthetic-subnet",
            "networkSecurityGroupIds": ["ocid1.networksecuritygroup.oc1.sa-saopaulo-1.synthetic-nsg"],
            "imageId": "ocid1.image.oc1.sa-saopaulo-1.synthetic-image", "ocpus": 1, "memoryGb": 8,
            "notBefore": (now - datetime.timedelta(minutes=1)).isoformat(),
            "expiresAt": (now + datetime.timedelta(minutes=10)).isoformat(),
            "peers": [{
                "slot": f"peer-{slot}", "privateIp": f"10.20.0.{10 + slot}",
                "faultDomain": f"FAULT-DOMAIN-{slot + 1}",
                "bootstrapBase64": base64.b64encode(bootstrap).decode(),
                "bootstrapSha256": hashlib.sha256(bootstrap).hexdigest(),
            } for slot in (1, 2)],
        }
        intent = root / "intent.json"
        intent.write_text(json.dumps({"schemaVersion": 1, "generation": 1, "bootstrapRegion": "GRU",
                                     "regions": [{"cell": "GRU", "ociRegion": "sa-saopaulo-1"}]}))
        unsigned = root / "unsigned.json"
        unsigned.write_text(json.dumps(plan))
        signed = root / "signed.json"
        environment = dict(os.environ, TS_ORCH_CONFIG=str(root / "must-not-load-runtime.json"))
        arguments = [str(x64), "oci-sign-founding", "--plan", str(unsigned), "--signing-key", str(private),
                     "--region-intent", str(intent), "--output", str(signed)]
        result = json.loads(invoke(arguments, env=environment))
        assert result["state"] == "signed"
        original = signed.read_bytes()
        envelope = json.loads(original)
        payload = base64.b64decode(envelope["payload"], validate=True)
        assert payload == unsigned.read_bytes()
        assert result["planSha256"] == hashlib.sha256(payload).hexdigest()
        signing_bytes = root / "signing.bin"
        signing_bytes.write_bytes((purpose + "\n").encode() + payload)
        signature_file = root / "signature.der"
        signature_file.write_bytes(der_signature(base64.b64decode(envelope["signature"], validate=True)))
        invoke(["openssl", "dgst", "-sha256", "-verify", str(public), "-signature", str(signature_file), str(signing_bytes)])
        invoke(arguments, expected=1, env=environment)
        assert signed.read_bytes() == original
        envelope["signature"] = base64.b64encode(bytes(64)).decode()
        invalid = root / "invalid.json"
        invalid.write_text(json.dumps(envelope))
        state = root / "state"
        state.mkdir(mode=0o700)
        invoke([str(x64), "oci-founding-peers", "--plan", str(invalid), "--trust-key", str(public),
                "--region-intent", str(intent), "--state-dir", str(state)], expected=1, env=environment)
        assert list(state.iterdir()) == []
    return {
        "schemaVersion": 1, "state": "passed", "artifacts": artifacts,
        "checks": ["x64-offline-signing", "openssl-signature-verification", "existing-grant-preserved",
                   "invalid-grant-rejected-before-state-or-provider", "elf-architecture"],
        "liveOci": False, "arm64Executed": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--x64-binary", required=True, type=Path)
    parser.add_argument("--arm64-binary", required=True, type=Path)
    parser.add_argument("--receipt", required=True, type=Path)
    arguments = parser.parse_args()
    os.umask(0o077)
    receipt = qualify(arguments.x64_binary.resolve(), arguments.arm64_binary.resolve())
    with arguments.receipt.open("x") as output:
        json.dump(receipt, output, indent=2)
        output.write("\n")
    print(json.dumps(receipt))


if __name__ == "__main__":
    main()
