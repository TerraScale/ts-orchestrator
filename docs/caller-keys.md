# Service caller keys

`ts-orch caller-key add|activate|retire|recover|list` manages regional ES256 service
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
`{ "version": 1, "callers": [...], "highWater": {...}, "intent": {...} }`.
The optional high-water map retains only the highest sequence used for each
caller and originating cell; the optional intent records the operation, key id,
caller, cell, operation id and start time. The database verifier ignores these
extra fields. Operator entries retain `op:<name>` and agent entries retain
`agent:<name>` as their caller names.

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

New keys require more than 30 days of lifetime. Both `add` and `activate`
warn about expired entries and entries expiring within 30 days, and continue.
`list` shows each public entry's `notAfter` and expiry status.

`retire` refuses a service's current or pending private key. Retiring any
stored historical private key requires `--replacement-kid` naming the same
service and region's current key, listed in every region. After all use of an
operator or agent key has ceased, retire it with `--kid op.NAME.N` or
`--kid agent.NAME.N`; a replacement argument is unnecessary. Public-only and
expired keys may also be retired, including a caller's last unused public key.
Historical private versions are preserved.

Sequences must exceed the caller and cell's high-water mark and every listed
and stored private key id for that service and region. The map size depends on
the number of callers and cells, rather than the number of rotations.

Every change first conditionally records its intent in every region, always
visiting regions in sorted cell order. Another changing command encountering an
intent stops and names the operation id. After all public and private writes
complete, the command clears the intents in the same sorted order. Every
changing command reads all regions and stops if any still carries an intent. Private staging and activation also condition on the private
secret's metadata ETag and verify readback.

After a command stops or crashes, stop any remaining process for that operation
before recovery. Do not run recovery alongside an operator command that is
still executing. Run:

```sh
ts-orch caller-key recover --targets /secure/caller-targets.json
ts-orch caller-key list --targets /secure/caller-targets.json
```

Recovery resumes the recorded operation id:
- For `add`, a matching current or pending private version retains the public
  entry in every region; otherwise recovery removes that entry everywhere and
  advances the sequence high-water mark.
- For `activate`, recovery promotes the matching pending version if its public
  entry is in every region. Otherwise it reports that activation was not applied
  and leaves the public and private entries unchanged.
- For `retire`, recovery finishes removing the entry everywhere.

Recovery clears the intent last. It can itself be interrupted and run again;
running it with no intent reports that no operation is in progress. Complete
the same database and service rollouts described above after recovery.

After a failed add, run `recover`, then add again with the next sequence. This
also covers a final public write whose response was interrupted after the store
accepted it: when no private version was stored, recovery removes the public
entry and consumes its sequence. If recovery finds the private version, complete
its first-key or rotation procedure before adding another key.
