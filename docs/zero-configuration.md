# Zero-configuration operating contract (TS-795)

This is the required production contract adopted on 2026-10-09. It is not a
claim that the current runtime or deployed fleet already implements it.

- Every feature is always available and every region serves automatically.
  There are no feature flags, region activation steps, deploy toggles or kill switches.
- Membership in the private NetBird network admits a node automatically. The
  node discovers all regions and infers its own region from where it runs.
- OCI Vault automatically provisions, delivers and configures every first-party
  production secret. Vendor-issued credentials are stored once in Vault and
  picked up automatically; operators do not copy production credentials.
- Each value has one correct setting in code. Production exposes no tuning
  knobs. Fakes, demo stores and authentication bypasses belong only in test
  code and test binaries.
- CI rejects new switch-style configuration. A narrow allowance for an
  unavoidable third-party name needs a one-line reason.

## Safety boundaries

Automatic admission does not grant customer access or relax tenant isolation,
least privilege, TLS, issuer/audience checks, residency or database placement.
Authorization, customer security enrollment and notification consent still apply.
Destructive operations still require reviewed targets and explicit approval;
health, quorum, ownership, integrity and rollback checks remain mandatory.
Missing credentials or unverified safety evidence must fail closed, without a
production fake or bypass.

## Implementation status

TS-795 corrects policy, documentation and CI feature/deploy opt-ins. It does
not change product code, schemas or runtime configuration assignments.
Orchestrator runtime removal and automation belong to TS-796; TerraBase
runtime toggles belong to TS-773. Other services still need their existing
configuration and secret-delivery paths reconciled with this contract.

Legacy option names, deployed-state observations and test fixture inputs in
technical references describe the current implementation or recorded evidence.
They are not production setup recipes. Existing automation is evidence only
for the operations it actually performs, not for the complete contract.
