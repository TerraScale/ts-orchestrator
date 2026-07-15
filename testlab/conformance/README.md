# SmolVM host conformance

`check_smolvm_host.py` validates the pinned SmolVM distribution, Linux host
architecture, `/dev/kvm` access and API version, and the exported HTTP API
schema. It is intentionally read-only: it invokes only `KVM_GET_API_VERSION`,
`smolvm --version`, and `smolvm serve openapi`.

The API check pins HTTP method, path, and OpenAPI operation ID for every driver
capability currently exposed: create, start, status, exec, stream, log,
bidirectional copy, stop, and delete. SmolVM 1.5.0 does not export a general
update operation; only resource resize is present. The pin records `update` as
a gated host-adapter gap rather than treating resize as equivalent.

The pin also records the installed version marker, upstream lightweight tag and
commit, release/archive/checksum metadata, and the absence of an upstream
release signature or source-provenance attestation. TerraScale's required
internal mirror and internal signature are explicitly `not-established`; this
Phase 0 report is not supply-chain completion evidence.

Run the check from the repository root:

```bash
python3 testlab/conformance/check_smolvm_host.py
```

To refresh the checked-in report after deliberately changing the pin or host:

```bash
python3 testlab/conformance/check_smolvm_host.py \
  --output testlab/conformance/smolvm-host-report.json
```

The script exits nonzero when any pinned artifact, host prerequisite, or API
surface check fails. A passing report is only Phase 0 evidence. It does not
authorize VM creation or satisfy the nine-VM topology, real systemd PID 1,
ARM64/A1, IAM, block-volume, or storage-performance gates.
