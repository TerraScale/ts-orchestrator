# Phase 1 runtime self-update soak audit handoff

## Scope

- Audits only the pure A/B self-update decision and its immutable evidence.
- Starts no process, unit, container, VM, network, filesystem, provider, deployment, or sibling-repository action.
- Selects no soak duration, timeout, artifact, architecture, compatibility, or rollback default.

## Production defect proven and corrected

`SelfUpdateRequest.SoakDuration` was captured but never evaluated. A healthy update at `OldSlotRetainedUntilSoak` immediately emitted `CompleteSelfUpdateIntent`, so one second and the required duration were indistinguishable. The pure policy could therefore complete the A/B update without evidence that its caller-selected soak elapsed.

Completion now requires typed `UpdateSoakEvidence` bound to the exact operation, node, allocation, writer epoch, target generation, and committed active slot. Missing evidence and insufficient elapsed duration hold. Replayed scope is rejected. Evidence supplied before the soak phase is rejected rather than cached as future proof.

Soak is only a healthy-completion prerequisite. An exact target-health or compatibility failure at the soak checkpoint still emits rollback immediately, even when soak evidence is missing, stale, or incomplete. This preserves the local-known-good recovery policy.

## Adversarial coverage

- Missing soak and the exact 599-second boundary hold a configured 600-second soak.
- Exact 600-second and greater 601-second evidence complete.
- Operation, node, allocation, epoch, target-generation, and active-slot replay are independently rejected.
- Prepopulated evidence at every non-soak phase is rejected.
- Exact health and compatibility failures bypass the soak gate and retain rollback authority.
- Existing 1,000-case artifact, recovery, precedence, and culture/property families use the appended reason and preserve their exact prior trace prefix.

## Contract inventory

- `RuntimeDecisionCode`: 22 values with existing IDs `1..21` unchanged and `SoakComplete=22` appended.
- Self-update trace: 14 entries; the prior 13-entry trace is an exact prefix.
- Runtime intent subtypes: 21, unchanged.
- Update phases/slots: 12/2, unchanged.
- Lifecycle traces, decisions, and enum inventories are unchanged.

## Evidence boundary

This is pure feature-shard evidence only. It does not qualify clock/timer adapters, persisted event application, A/B filesystem slots, systemd rollback timers, L0/L0C, mutation testing, deployment, or production acceptance.
