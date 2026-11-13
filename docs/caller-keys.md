# Service caller keys

`ts-orch caller-key add|activate|retire|list` manages regional ES256 service
identities with operator OCI credentials. It does not restart services.
Output contains secret names, key ids, current/pending stages and expiry times.

Regions come from the authenticated, signed foundation footprint, using the
same OCI discovery as other operator commands. Supply an operational JSON file
to `--targets` containing exactly one entry per discovered region:

```json
[
  {
    "cell": "sjc",
    "vault": "ocid1.vault.oc1.us-sanjose-1.EXAMPLE",
    "key": "ocid1.key.oc1.us-sanjose-1.EXAMPLE",
    "compartment": "ocid1.compartment.oc1.EXAMPLE"
  }
]
```

The example shows one entry; include every deployed region. Targets must use each
cell's regional Vault and encryption key. There is no `--regions` option.

| Caller | Key id | Private secret |
| --- | --- | --- |
| ts-auth | `ts-auth.CELL.N` | `CELL-1-ts-auth-terrabase-key` |
| dashboard | `dashboard.CELL.N` | `CELL-1-ts-dashboard-terrabase-key` |
| edge | `edge.CELL.N` | `CELL-1-orch-terrabase-key` |

The private secret is a P-256 JWK with kid, kty, crv, x, y, d.

Public registry entries contain `kid`, `caller`, `kind`, `jwk` (without `d`),
`grants`, and `notAfter`, inside
`{ "version": 1, "callers": [...], "retired": [...] }`.
The optional `retired` array retains retired service key ids; the database
verifier ignores this extra field. Operator entries retain `op:<name>` and agent
entries retain `agent:<name>` as their caller names.

For a service's first key in a region:

1. Run `add` to publish the public entry to every region and create the service's
   private secret with that key as its current version.
2. Roll TerraBase in every region to load the registry.
3. Ship the service spec reference to the private secret, then roll the service.

```sh
ts-orch caller-key add --targets /secure/caller-targets.json --service dashboard --region sjc --kid dashboard.sjc.1 --not-after 2027-11-12T00:00:00Z
ts-orch caller-key list --targets /secure/caller-targets.json
```

Before the spec reference ships, nothing reads the first private secret.
`list` shows the first key as current; activating it reports `already current`.

For every rotation of an existing secret:

1. Run `add` with a fresh, larger sequence. It publishes every public registry,
   then appends a pending private version while preserving the current version.
2. Roll TerraBase in every region to load both public keys.
3. Run `activate --kid NEW` to promote the pending private version. It requires
   the key id in every region and a matching pending private version.
4. Roll the service to load the current key. After the old key's use has ceased,
   retire it with `--replacement-kid NEW`, then roll TerraBase again.

```sh
ts-orch caller-key add --targets /secure/caller-targets.json --service dashboard --region sjc --kid dashboard.sjc.2 --not-after 2027-11-12T00:00:00Z
ts-orch caller-key activate --targets /secure/caller-targets.json --kid dashboard.sjc.2
ts-orch caller-key retire --targets /secure/caller-targets.json --kid dashboard.sjc.1 --replacement-kid dashboard.sjc.2
```

Only one pending rotation may be staged at a time. The operator completes the
database rollout before activation; the command checks registry publication,
not which registry each running database has loaded.

New keys require more than 30 days of lifetime. Both `add` and `activate` refuse
if any listed entry is expired or expires within 30 days, naming that key id.
`list` shows each public entry's `notAfter`. `retire` remains available for
expired entries.

`retire` refuses the service's current or pending private key and the last
listed key for that caller and originating region, even if that caller has keys
in other regions. Retiring any stored historical private key requires
`--replacement-kid` naming the same service and region's current key, listed in
every region. An incomplete public-only key can be retired without a replacement
argument when another key remains. Historical private versions are preserved.

Sequences must exceed every listed, retired and stored private key id for that
service and region. A retired id must not be reused. Publication reads every
registry first. `add` and `activate` require identical regional registries,
including retired ids. `retire` converges publication differences by retaining
public entries and the union of retired ids, excluding retired entries.

Updates use the version read during preflight and OCI `If-Match`; staging and
activation also condition on the private secret's metadata ETag and verify
readback. A failed or uncertain publication stops without rolling back successful
writes. Inspect `list` after interruption. Use `retire` to finish an interrupted
retirement or remove an incomplete public-only key, then use a fresh sequence.
A registry publication failure leaves the private key unchanged. Conflicting
public key material for an unrelated key requires operator reconciliation.
