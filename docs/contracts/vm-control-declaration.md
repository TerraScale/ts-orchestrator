# Qualification control declaration

`TS_VM_CONTROL_DECLARATION_FILE` selects a protected owner declaration for the
initial GRU/SFO/FRA qualification inventory. It does not grant live election
identity or imply that the reserved IAD guests have been admitted.

The outer JSON document has `ownerKey` and `payload` file references, each with
`source` and lowercase `sha256`, and a base64 `signature`. The owner key is a
P-256 public PEM file. The signature is ECDSA ASN.1 over SHA-256 of
`TS-VM-CONTROL-DECLARATION-V1`, a NUL byte, and the exact payload file bytes.
The independently protected outer declaration pins both the key and the signed
payload; an embedded self-asserted key is insufficient.

The payload supplies:

- `version: 1`, exact network `runId`, `issuedAt`, and `expiresAt`. Admission
  lasts no more than 24 hours and must be current at load.
- `artifacts`, the three exact guest artifact records already selected by the
  factory, including their release URLs, digests, versions and architecture.
- `stores`, a map of names to `reader` (`nodeauthority.ReaderConfig`) and `files`.
  Every reader's four guest credential paths maps to a protected runner
  `{source, sha256}` reference. Certificate and CA pins, NKey identity and TLS
  key pairing must agree. Stores must address launch guests. The actual NATS
  server name must equal the declared reader server name when connecting.
- `members`, six entries carrying `member` (`bootstrap.ControlRuntimeMember`),
  positive `generation`, and a protected `membershipKey` reference. Membership
  private keys must derive the exact declared public pins. OCI member IDs,
  guest identities, store names and server identities are immutable inputs.
- `regions`, the three `bootstrap.ControlRegionBinding` records, each with two
  exact OCI members and its compartment and OCI Region.
- `actions`, entries containing `plan` (`bootstrap.ControlRuntimeActionPlan`)
  and optional `revokedStore`. Handoff manifests pin the published bytes and
  content-addressed launch versions. Election term, candidate and lease ID in
  checks must be absent/zero; the source resolves these from live guest stores
  after each handoff. `revokedStore` references an independently admitted
  credential which must actually fail authorization after revocation.
- `candidates`, the two first SFO/FRA peers with `nodeId`, pinned `bundle` file,
  `privateMaterialDirectory`, and `planSha256`. The existing `candidateplan`
  output and `vmcandidateseed` private store remain the preparation authority.
  Their original signatures and exact private material must verify.

The factory imports declared membership identities before deriving GRU initial
configuration. Candidate bootstrap additionally requires the actual source GRU
ready transition and the exact issued source grant, owner key, broker name and
store scope. The declaration does not authorize an additional SFO/FRA member;
that host needs its own ordinary admission. It cannot turn candidate preparation
into a regional election or bypass the promoted global R3 production stage.

Initial issuer and grants persist in the protected per-run admission directory.
`initial-issuer.json` retains the finite issuer identity and issue time;
`grant-<host>.json` retains exact signed bytes. Valid pending publication is
recovered unchanged. Corruption, a changed run, a changed manifest or expiry
fails closed instead of issuing a replacement source hash.

For staged creation, use `candidatePlan` instead of `candidates`. This is the
`candidateplan.Plan` schema: explicit `sourceNodeId`, transition identity and
epoch bounds, finite issue/expiry times, protected `privateMaterialDirectory`,
and the two `candidates` entries. Each entry carries its exact base `manifest`,
preparation `config`, `bootstrapGrantId`, and `syncGeneration` reader credential
references. The plan must fit the signed declaration's time window and declared
member/artifact inventory. It contains no owner private-key file.

Before allocating a remote candidate, the factory reads the original GRU broker
with its admitted NKey and TLS credentials. It checks a fresh signed membership
record against the actual regional lease, signs the declared candidate plan
through the persisted issuer, then rereads that lease. A changed source election
fails the attempt. Persisted candidate material and signed bundle remain exact
on retry. The issuer registers the two original candidate grants for the
existing finite bootstrap command verifier. Candidate activation therefore
requires no invented regional election authority.
