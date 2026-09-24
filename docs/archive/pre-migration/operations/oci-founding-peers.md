# Founding the first GRU quorum

`oci-founding-peers` is a bounded, pre-NATS stage of first boot. It lets the
exact `ts-infra` seed create two peers before the regional R3 quorum exists.
It does not admit controllers, provision a NATS topology, transfer the seed,
or authorize normal workload/provider operations. Those stages still need
the [bootstrap and ownership handoff](control-bootstrap.md).

## Authority and inputs

CI signs a public plan with an offline P-256 private key. Only its public key
is installed on the seed. The command runs before ordinary runtime
configuration, connects only to the canonical GRU OCI endpoint, and uses
Instance Principal. There is no production API-key option.

The unsigned plan has this shape; the example values are placeholders and
must be generated from the reviewed `ts-infra` outputs and pinned artifacts:

```json
{
  "schemaVersion": 1,
  "purpose": "terrascale-oci-gru-founding-peers-v1",
  "bootstrapId": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "regionIntentGeneration": 1,
  "region": "GRU",
  "seedInstanceId": "ocid1.instance.oc1.sa-saopaulo-1.seed",
  "compartmentId": "ocid1.compartment.oc1..control",
  "availabilityDomain": "TENANCY:SA-SAOPAULO-1-AD-1",
  "seedFaultDomain": "FAULT-DOMAIN-1",
  "subnetId": "ocid1.subnet.oc1.sa-saopaulo-1.control",
  "networkSecurityGroupIds": ["ocid1.networksecuritygroup.oc1.sa-saopaulo-1.control"],
  "imageId": "ocid1.image.oc1.sa-saopaulo-1.pinned",
  "ocpus": 1,
  "memoryGb": 8,
  "notBefore": "2026-09-20T00:00:00Z",
  "expiresAt": "2026-09-20T00:30:00Z",
  "peers": [
    {
      "slot": "peer-1",
      "privateIp": "10.20.0.11",
      "faultDomain": "FAULT-DOMAIN-2",
      "bootstrapBase64": "replace-with-base64-of-public-cloud-init",
      "bootstrapSha256": "replace-with-lowercase-sha256-of-decoded-cloud-init"
    },
    {
      "slot": "peer-2",
      "privateIp": "10.20.0.12",
      "faultDomain": "FAULT-DOMAIN-3",
      "bootstrapBase64": "replace-with-base64-of-public-cloud-init",
      "bootstrapSha256": "replace-with-lowercase-sha256-of-decoded-cloud-init"
    }
  ]
}
```

The contract fixes GRU, the exact seed and two peer slots, one subnet and
1–5 unique NSGs, distinct RFC1918 IPv4 addresses, all three fault domains, and
an A1 Flex shape with 1–4 OCPUs and 1–16 GiB per OCPU. Each public cloud-init
payload is at most 32 KiB and must match its digest. Secret values must never
be included in metadata; rejection of recognizable private-key/NATS markers
is only a guard, not a general secret detector. Install secret references
and use the [Vault delivery command](oci-vault-bootstrap.md).

The grant lasts at most one hour. Region-intent generation must match exactly.
Unknown/duplicate JSON properties and noncanonical base64 are rejected.
The signed envelope is `{"payload":"base64", "signature":"base64"}`;
the signature is 64-byte ECDSA P1363/SHA-256 over the purpose plus a newline
followed by the original UTF-8 payload bytes. Formatting changes require a
new signature. Payload and envelope limits are 96 KiB and 128 KiB respectively.

## Commands

Run the signer in trusted CI while the plan's validity window is open. The
private key must be an owner-private regular file. Inputs must not traverse
symlinks or allow group/other writes; region intent must be owner-private.
Signing performs no OCI calls and never overwrites an existing grant:

```sh
terrascale-orchestrator oci-sign-founding \
  --plan /private/founding-unsigned.json \
  --signing-key /private/ci-founding-key.pem \
  --region-intent /private/region-intent.json \
  --output /private/founding-signed.json
```

Deliver the signed grant and the independently pinned public trust key to
the seed. Pre-create the persistent state directory with mode `0700`, owned
by the bootstrap service user. Its contents must survive process restarts:

```sh
terrascale-orchestrator oci-founding-peers \
  --plan /etc/terrascale/founding-signed.json \
  --trust-key /etc/terrascale/founding-public.pem \
  --region-intent /etc/terrascale/region-intent.json \
  --state-dir /var/lib/terrascale/founding
```

The command verifies its exact local instance identity via IMDSv2, then
observes the seed and its private VNIC through OCI. The seed must still be
running with `ManagedBy=ts-infra`, `Role=initial-controller`, `Region=GRU`,
the signed compartment/AD/fault domain and network binding. The command
creates peers with private VNICs, legacy IMDS disabled, encryption in transit,
and a 50 GiB boot disk. Peer ownership tags bind the bootstrap ID, slot and
full plan digest. Existing peers must match the exact launch template and
private network; drift or a terminated peer stops reconciliation.

## Progress, retries, and limits

Each invocation takes one bounded reconciliation step. Exit `2` means peers
are submitted/provisioning; exit `0` means both provider instances are running
on the expected private network; exit `1` means reconciliation failed. JSON
output includes `bootstrapId`, `state`, `progressPercent`, each peer's OCID and
state, and `needs`. At `peers-running`, needs still include
`regional-nats-quorum`, `controller-admission`, and `seed-ownership-handoff`.
The percentage measures only provider peer readiness. It does not measure
overall deployment progress. The supervisor/aggregated status integration is
not yet implemented.

An exclusive file lock prevents concurrent invocations sharing a state
directory. A private receipt pins the exact grant digest before provider
calls. Each peer has a deterministic retry token and a fixed private IP.
Lost responses reuse the token; lost local receipts recover only exact
provider peers by their deterministic names and verified bindings. Files are
flushed and renamed atomically, but directory fsync/power-loss durability
has not been qualified. Never delete or edit state to retry with a new grant.

Expired grants can observe previously created peers but cannot create a
missing peer. A partial bootstrap that exceeds its grant lifetime remains
incomplete: signed renewal/recovery is not implemented. Changing the expiry
changes the digest and is rejected by the pinned receipt. There is no delete,
replacement, seed mutation, IAM mutation, or R1 downgrade under this authority.

The reconciliation cancellation budget is three minutes; a first-boot
supervisor must also enforce an overall process deadline because Instance
Principal discovery includes synchronous SDK work. Bounded repeated polling,
artifact installation, authenticated NATS startup, journal isolation,
controller admission and seed handoff still require composition and tests.

Local tests cover signatures and authority limits, exact two-peer creation,
lost responses/receipts, restarts, expiry, drift, lock contention and redaction.
The real SDK loopback test checks signed HTTP launch serialization and response
decoding with a disposable synthetic API key. None of these tests prove live
Instance Principal policy enforcement, real OCI capacity or first-boot quorum
formation. Keep the estate disabled until the remaining readiness gates pass.

After publishing both architectures, the offline executable probe is:

```sh
nice -n 19 python3 scripts/qualify-founding-cli.py \
  --x64-binary /path/to/linux-x64/terrascale-orchestrator \
  --arm64-binary /path/to/linux-arm64/terrascale-orchestrator \
  --receipt /private/new-founding-cli-receipt.json
```

It uses disposable synthetic keys, verifies the actual x64 signature with
OpenSSL, tests no-overwrite behavior, and submits only an invalid grant to the
reconciler, which must reject it before creating local state or contacting OCI.
It records binary SHA-256 and ELF architectures; it does not execute ARM64.
