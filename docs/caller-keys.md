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
caller, cell, operation id, dispatch bound and private version identity. The database
verifier ignores these extra fields. Operator entries retain `op:<name>` and agent entries retain
`agent:<name>` as their caller names.

For a service's first key in a region:

1. Run `add` to publish the public entry to every region and create the service's
   private secret with that key as its current version.
2. Run `list` and confirm the registry is present in every region before pointing
   any database at it, then roll TerraBase in every region to load it. A first
   add interrupted during initial publication can leave regions with no registry;
   `list` explicitly prints `NO REGISTRY` for each missing region.
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
warn about expired entries and entries expiring within 30 days; activation refuses
a pending key with 30 days or less remaining. Recovery applies the same minimum
remaining lifetime immediately before promotion; an interrupted activation that
no longer qualifies becomes a recoverable cancellation and reports that outcome.
`list` shows each public entry's `notAfter` and expiry status.

`retire` refuses a service's current private key. For a pending key that has
never been activated, it cancels the rotation, including a pending key with 30 days or less remaining. Recovery applies the same minimum
remaining lifetime immediately before promotion; an interrupted activation that
no longer qualifies becomes a recoverable cancellation and reports that outcome.
`list` shows its pending stage, expiry and when it can only be cancelled.
Cancellation conditionally supersedes the pending version with a copy of the
current key, verifies that the cancelled version is deprecated, and schedules
its deletion with an explicit seven-day grace period before removing its public
entry. It reads the scheduled timestamp back and prints `deletion scheduled TIME`.
During that period, cancel the deletion using
`oci vault secret-version cancel-deletion --secret-id SECRET_OCID --secret-version-number N`.
This restores a deprecated version, not a pending or current signing key; its
removed public entry stays removed. Use a new numbered add for another rotation. The current signing key stays
current. Activation requires the public entry in every region and a matching
usable pending version, so a cancelled key cannot be activated. Cancellation
consumes its sequence and permits a new `add` with a higher sequence.

Retiring any
public key for a service that has a private secret requires `--replacement-kid` naming the same
service and region's current key, listed in every region. After all use of an
operator or agent key has ceased, retire it with `--kid op.NAME.N` or
`--kid agent.NAME.N`; a replacement argument is unnecessary. If management metadata says a service has no private secret, retirement first
records its intent and uses the same settled absence decision as recovery. It
exits non-zero with `waiting until TIME` until that decision is safe; `recover`
or repeating the same `retire` then completes the orphan removal. An empty
listing by itself never permits retirement. Operator and agent entries have no
private half managed by this command and can be retired directly.
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

Recovery has three outcomes for the recorded operation id:

- **Finished forward:** management metadata confirms the secret or rotation
  version exists, even while it is being created. Recovery waits for readable
  contents using the store readback path, then keeps the added public entry,
  finishes activation, retirement or pending cancellation as recorded.
- **Finished backward:** an add's private half is authoritatively absent.
  Recovery removes its public entry, consumes its sequence and clears the intent
  only after the store reports an age greater than 10 minutes and two fresh
  management metadata reads agree that the secret or version is absent, with
  the second read after the window.
- **Waiting:** metadata is unavailable, absence is not settled, or an existing
  private version is not readable yet. Recovery changes nothing, retains the
  intent and exits non-zero with `waiting until TIME`, naming what must settle. Re-running recovery is safe.

After any recovery write, a subsequent failure instead reports `interrupted`
and instructs the operator to run recovery again.

The intent carries a two-minute private dispatch bound. Each running command
measures elapsed time with its monotonic clock. Its fence starts no later than
acknowledgement of its first intent write: conservatively, it retains the
monotonic timestamp taken immediately before that request, so delayed
acknowledgements and scheduling cannot extend the bound. Immediately before
every private mutation, including each wire attempt, elapsed time must remain
below two minutes. Otherwise it refuses dispatch and asks for recovery. Each
private operation has a 60-second request timeout, including readback. Recovery
gets a new bound only after recording its own intent writes.

Absence decisions never consult workstation wall time. The registry snapshot's
creation time is `GetSecretVersion.SecretVersion.timeCreated` for the exact
registry version that carries the intent. If several regions carry an intent,
the newest such timestamp is used. Store time now is the HTTP `Date` header of
the fresh management metadata response made by this command:
`ListSecretsResponse.RawResponse.Header["Date"]`, or the last
`ListSecretVersionsResponse.RawResponse.Header["Date"]` when checking a named
version. Listing reads consume all pages and lifecycle states. Missing/invalid
timestamps, backwards store time, differing reads or unavailable metadata retain
the intent. The threshold is two minutes of dispatch allowance plus 60 seconds
of request lifetime plus a seven-minute margin: ten minutes total. Operator
clock skew of either sign cannot age an intent; operator wall time is used for
key lifetime validation and display only.

All removals that rely on absence use the same metadata-based private-half decision.
Retirement also attempts a current-content read when a listing omits the secret;
readable current contents override that negative listing.
Retirement with an existing private secret instead reads a different, named
current replacement and requires its public entry in every region. A contents
read returning not-found never authorizes removal of a public key. Recovery
never promotes a key without its public entry in every region.

Recovery clears the intent last. It can itself be interrupted and run again;
running it with no intent reports that no operation is in progress. Complete
the same database and service rollouts described above after recovery.

After a failed add, run `recover`, then add again with the next sequence. This
also covers a final public write whose response was interrupted after the store
accepted it: when no private version was stored, recovery removes the public
entry and consumes its sequence. If recovery finds the private version, complete
its first-key or rotation procedure before adding another key.

The e2e lane substitutes only the store adapter and clocks at build time.
It checks the current-private/public-registry invariant after each mutation,
including interrupted recovery, independently advanced clocks, delayed dispatch,
listing lag and cancellation of expired activations. It cannot prove the
following provider contracts.

| Adapter contract | Enforcement and limit if the store differs |
| --- | --- |
| Listings include all lifecycle states and all pages | Management reads consume every page without a lifecycle filter and reject ambiguous identities. Omitted items/pages are not detectable from an otherwise valid response; two agreeing reads are insufficient if listings remain incomplete beyond the settling bound. |
| Late writes settle within the fence | Monotonic dispatch checks and the 60-second request deadline bound the writer; store age plus the margin delays absence rollback. The provider must settle accepted requests and listing visibility within that total, and its Date/timeCreated clocks must agree. Completion or listing lag beyond it is not detectable in advance; do not use this adapter if rehearsal violates the bound. |
| Names are unique and create-once | Creation looks up the regional name and reads the exact value back. Duplicate IDs or mismatched contents stop the operation. A provider allowing an omitted duplicate name is not fully detectable by readback. |
| Conditional writes fence every transition | Registry writes compare the previously read current version and metadata ETag; staging, promotion and cancellation use conditional metadata. Registry/current/version readbacks reject divergence. A provider ignoring conditions can race between checks; readback detects many failures only after mutation and cannot restore the invariant. |
| Version inventories are coherent | Private reads compare metadata ETags before/after all version pages, require the current bundle in the inventory and validate its contents/stage. Missing non-current versions under an unchanged ETag are not detectable. |
| Pending publication preserves current | Stage reads back the same current version/content and the requested pending content. A changed current stops with an interrupted operation; detection occurs after mutation. |
| Promotion selects exactly the requested version | Activation reads back the exact requested version and content. A different selection stops; readback cannot undo a provider-side unsafe promotion. |
| Deletion honours the version condition and preserves current | Cancellation first supersedes pending, requires deprecated/non-current/non-pending version metadata, uses that version's ETag, supplies seven days explicitly, reads the deletion timestamp back and verifies unchanged current with the cancelled version excluded. Ignored conditions or an unsafe concurrent promotion can be detected only after mutation. |

Before the first real key, rehearse against a disposable store with the real
adapter and disposable targets. Keep all key material in the store and record
only ids, stages, metadata and timestamps:

1. Interrupt a first add and a rotation add at publication/private boundaries;
   recover both forward (private accepted) and backward (no private accepted),
   including the store-aged absence window.
2. Accept a private creation but lose its response; delay contents and listing
   visibility independently, skew operator time by plus/minus ten minutes, and
   verify recovery retains all public entries until existence is resolved.
3. Add a pending rotation, cancel it, verify current is unchanged and the
   explicit deletion timestamp is seven days away, then cancel that scheduled
   deletion within its grace period and verify the version remains deprecated.
4. Add, activate and retire with a named current replacement present in every
   registry; verify the selected private versions and every public registry.
5. Attempt to retire the current key, including while listing visibility lags
   behind readable contents; verify no public entry is removed.
6. Interrupt cancellation before/after superseding pending and scheduling
   deletion while a competing activation attempts to proceed. Verify its
   conditions fail, current remains published everywhere, and recovery finishes.

If any undetectable contract fails rehearsal, keep databases and services
unreferenced and fix the adapter/provider contract before using it for real keys.
