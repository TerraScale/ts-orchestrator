#!/usr/bin/env python3
"""Import a qualified ARM64 QCOW2 into OCI as a launchable A1 image.

One idempotent command: upload the exact bytes, import them, and apply the
launch contract every TerraScale instance depends on (UEFI firmware,
paravirtualized devices, consistent volume naming, A1-only shapes). A rerun
with the same inputs resumes from the first incomplete step. Records are
written to --out; the command never deletes an existing image.
"""

import argparse
import hashlib
import json
import pathlib
import subprocess
import sys
import time

A1_SHAPE = "VM.Standard.A1.Flex"
A1_OCPUS = {"min": 1, "max": 4}
A1_MEMORY_GB = {"min": 6, "max": 24}
CAPABILITIES = {
    "Compute.Firmware": {"descriptor-type": "enumstring", "source": "IMAGE",
                         "values": ["UEFI_64"], "default-value": "UEFI_64"},
    "Compute.LaunchMode": {"descriptor-type": "enumstring", "source": "IMAGE",
                           "values": ["PARAVIRTUALIZED"], "default-value": "PARAVIRTUALIZED"},
    "Network.AttachmentType": {"descriptor-type": "enumstring", "source": "IMAGE",
                               "values": ["PARAVIRTUALIZED"], "default-value": "PARAVIRTUALIZED"},
    "Storage.BootVolumeType": {"descriptor-type": "enumstring", "source": "IMAGE",
                               "values": ["PARAVIRTUALIZED"], "default-value": "PARAVIRTUALIZED"},
    "Storage.RemoteDataVolumeType": {"descriptor-type": "enumstring", "source": "IMAGE",
                                     "values": ["PARAVIRTUALIZED"], "default-value": "PARAVIRTUALIZED"},
    "Storage.ConsistentVolumeNaming": {"descriptor-type": "boolean", "source": "IMAGE", "default-value": True},
    "Storage.ParaVirtualization.EncryptionInTransit": {"descriptor-type": "boolean", "source": "IMAGE",
                                                       "default-value": True},
}


def oci(region: str, *args: str) -> dict:
    result = subprocess.run(["oci", "--region", region, *args, "--output", "json"],
                            capture_output=True, text=True, check=False)
    if result.returncode:
        raise SystemExit(f"oci {' '.join(args[:3])} failed: {result.stderr.strip()}")
    return json.loads(result.stdout) if result.stdout.strip() else {}


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(8 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def find_image(region: str, compartment: str, name: str) -> dict | None:
    images = oci(region, "compute", "image", "list", "--compartment-id", compartment,
                 "--display-name", name, "--all").get("data", [])
    live = [image for image in images if image["lifecycle-state"] in ("IMPORTING", "PROVISIONING", "AVAILABLE")]
    if len(live) > 1:
        raise SystemExit(f"more than one live image is named {name}")
    return live[0] if live else None


def wait_available(region: str, image_id: str) -> dict:
    deadline = time.monotonic() + 45 * 60
    while time.monotonic() < deadline:
        image = oci(region, "compute", "image", "get", "--image-id", image_id)["data"]
        if image["lifecycle-state"] == "AVAILABLE":
            return image
        if image["lifecycle-state"] not in ("IMPORTING", "PROVISIONING"):
            raise SystemExit(f"image {image_id} entered {image['lifecycle-state']}")
        time.sleep(20)
    raise SystemExit(f"image {image_id} did not become AVAILABLE within 45 minutes")


def ensure_capabilities(region: str, compartment: str, image_id: str, name: str) -> dict:
    schemas = oci(region, "compute", "image-capability-schema", "list", "--compartment-id", compartment,
                  "--image-id", image_id, "--all").get("data", [])
    if schemas:
        schema = oci(region, "compute", "image-capability-schema", "get",
                     "--image-capability-schema-id", schemas[0]["id"])["data"]
    else:
        global_schema = oci(region, "compute", "global-image-capability-schema", "list", "--all")["data"][0]
        schema = oci(region, "compute", "image-capability-schema", "create", "--compartment-id", compartment,
                     "--image-id", image_id, "--display-name", name[:255],
                     "--global-image-capability-schema-version-name", global_schema["current-version-name"],
                     "--schema-data", json.dumps(CAPABILITIES))["data"]
    for key, expected in CAPABILITIES.items():
        actual = schema["schema-data"].get(key, {})
        if actual.get("default-value") != expected["default-value"] or actual.get("values") != expected.get("values"):
            raise SystemExit(f"image capability {key} differs from the launch contract")
    return schema


def ensure_shapes(region: str, image_id: str) -> list[dict]:
    rows = oci(region, "compute", "image-shape-compatibility-entry", "list", "--image-id", image_id,
               "--all").get("data", [])
    a1 = next((row for row in rows if row["shape"] == A1_SHAPE), None)
    if a1 is None or a1.get("ocpu-constraints") != A1_OCPUS or \
            a1.get("memory-constraints") != {"min-in-gbs": A1_MEMORY_GB["min"], "max-in-gbs": A1_MEMORY_GB["max"]}:
        oci(region, "compute", "image-shape-compatibility-entry", "add", "--image-id", image_id,
            "--shape-name", A1_SHAPE, "--ocpu-constraints", json.dumps(A1_OCPUS),
            "--memory-constraints", json.dumps({"minInGBs": A1_MEMORY_GB["min"], "maxInGBs": A1_MEMORY_GB["max"]}))
    for row in rows:
        if row["shape"] != A1_SHAPE and not row["shape"].endswith(".Generic"):
            oci(region, "compute", "image-shape-compatibility-entry", "remove", "--image-id", image_id,
                "--shape-name", row["shape"], "--force")
    rows = oci(region, "compute", "image-shape-compatibility-entry", "list", "--image-id", image_id,
               "--all").get("data", [])
    if not any(row["shape"] == A1_SHAPE for row in rows) or \
            any(row["shape"] != A1_SHAPE and not row["shape"].endswith(".Generic") for row in rows):
        raise SystemExit("image shape compatibility is not A1-only")
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--qcow2", type=pathlib.Path, required=True)
    parser.add_argument("--sha256", required=True, help="expected QCOW2 SHA-256")
    parser.add_argument("--region", default="sa-saopaulo-1")
    parser.add_argument("--compartment-id", required=True)
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--bucket", required=True)
    parser.add_argument("--display-name", required=True)
    parser.add_argument("--out", type=pathlib.Path, required=True)
    args = parser.parse_args()

    if sha256(args.qcow2) != args.sha256:
        raise SystemExit("QCOW2 bytes differ from the expected SHA-256")
    object_name = f"images/{args.sha256}.qcow2"
    image = find_image(args.region, args.compartment_id, args.display_name)
    if image is None:
        head = subprocess.run(["oci", "--region", args.region, "os", "object", "head", "--namespace-name",
                               args.namespace, "--bucket-name", args.bucket, "--name", object_name],
                              capture_output=True, text=True, check=False)
        if head.returncode:
            print(f"uploading {object_name}", flush=True)
            oci(args.region, "os", "object", "put", "--namespace-name", args.namespace, "--bucket-name",
                args.bucket, "--name", object_name, "--file", str(args.qcow2), "--metadata",
                json.dumps({"sha256": args.sha256}), "--no-overwrite", "--parallel-upload-count", "8")
        print("importing image", flush=True)
        image = oci(args.region, "compute", "image", "import", "from-object", "--compartment-id",
                    args.compartment_id, "--namespace", args.namespace, "--bucket-name", args.bucket,
                    "--name", object_name, "--display-name", args.display_name,
                    "--source-image-type", "QCOW2", "--launch-mode", "PARAVIRTUALIZED",
                    "--operating-system", "Custom", "--operating-system-version", "Custom")["data"]
    image = wait_available(args.region, image["id"])
    schema = ensure_capabilities(args.region, args.compartment_id, image["id"], args.display_name)
    shapes = ensure_shapes(args.region, image["id"])
    record = {"schema": "terrascale.oci.image-import.v1", "image_id": image["id"],
              "display_name": args.display_name, "qcow2_sha256": args.sha256,
              "object": f"{args.namespace}/{args.bucket}/{object_name}",
              "billable_size_gb": image.get("billable-size-in-gbs"),
              "capability_schema_id": schema["id"], "shapes": sorted(row["shape"] for row in shapes)}
    args.out.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    print(json.dumps(record, sort_keys=True))


if __name__ == "__main__":
    sys.exit(main())
