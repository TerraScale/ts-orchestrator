# Phase 0 ADR and toolchain readiness handoff

- Work package predecessor: `de9be9f`
- Branch starting point observed by this lane: `bc04125`
- Scope changed: `docs/adr/**`, `docs/audits/toolchain/**`, and this handoff only
- Destructive/external actions: none

## Result

All 24 initial ADR backlog items are represented exactly once in `docs/adr/readiness-index.yaml`. The readiness distribution is:

- 4 `draft-ready`
- 3 `evidence-required`
- 17 `owner-input-required`
- 0 `accepted`

The four choice-preserving drafts that can proceed now are ADR 4 (Pulumi/provider ownership), ADR 13 (native GitOps), ADR 18 (placement boundary), and ADR 20 (provider-actuator threat model). Draft-ready does not accept their remaining implementation details.

Numbered owner questions 1 through 10 all control at least one mapped ADR. The additional owner planning blockers are team/date, maximum three-region cost, storage performance/latency, regional RPO/RTO, and Phase 0 security/memory/survival targets. No recommendation was converted into an owner decision.

## Local audit summary

Observed locally: .NET SDK 10.0.301, `nats-server` 2.14.3, systemd 261, SmolVM 1.5.0 with accessible KVM, OCI CLI 3.89.1, Pulumi 3.251.0, ext4 tooling, util-linux block discovery, and LVM with insufficient device-mapper permission for a valid version/usability claim.

Absent locally: NATS CLI, containerd, runc, BuildKit, XFS tools, growpart, parted, cosign, notation, oras, syft, trivy, grype, qemu-aarch64, and an AArch64 compiler. Observed versions are not approved pins unless a checked-in pin says so. ARM64, systemd-as-PID-1, OCI, filesystem, and destructive-operation qualification remain assigned to their required real-system layers.

## Validation commands

```text
python3 docs/adr/validate_readiness.py
python3 -m unittest discover -s docs/adr/tests -v
python3 -m json.tool docs/adr/readiness-index.yaml
python3 testlab/conformance/check_smolvm_host.py > /tmp/orch-adr-smolvm-host-report.json
cmp /tmp/orch-adr-smolvm-host-report.json testlab/conformance/smolvm-host-report.json
git diff --check
```

The validator derives and checks the exact owner lane names and ADR titles against `ORCHESTRATOR.md`. It resolves every local evidence `path:start-end` anchor, rejects missing/out-of-bounds/blank ranges, and requires each `draft-ready` item to cite both the specification and an audit or retirement-ledger range. Adversarial fixtures prove rejection of a missing ADR, stale line anchor, accepted/open-owner conflict, unknown lane, and unknown dependency.

The tool audit additionally used bounded local `command -v` and version queries, host/kernel/architecture reads, `/dev/kvm` metadata, and checked-in pin/report reads. It did not start a service, VM, container, or cloud operation.

## Suggested next work packages

1. Owner-decision and SLO freeze packet for questions 1–10 plus cost/storage/RPO/RTO/team/date/security/memory/survival inputs.
2. Draft the four `draft-ready` ADRs as explicitly proposed records with alternatives and exit gates, leaving implementation selections open.
3. Supply-chain/toolchain pin package covering ordinary-Linux .NET, property/model/fuzz/mutation tooling, signing/attestation, SBOM/security scanning, BuildKit, containerd/runc, and internal mirrors.
4. NATS version/N/N-1 and L0C package covering server/client/CLI pins, JWT permissions, gateways, JetStream durability, snapshot/restore, and peer replacement.
5. ARM64 host/runtime package selecting the LTS image/kernel/glibc/filesystem candidates and defining L1R/L4 evidence.
6. Provider TCO/region/storage benchmark package and sanitized read-only OCI inventory; these unblock ADRs 5, 8, 9, 19, and 24 without granting mutation authority.
