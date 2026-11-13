# Service caller keys

`ts-orch caller-key add|activate|retire|recover|list` manages regional ES256 service
identities with operator OCI credentials. It does not restart services.
Output contains secret names, key ids, stages, expiry times and deletion schedules;
private key material stays in memory and the secret store.

Never remove a public entry because a secret or version is absent from a read or listing.
Remove an entry only with positive evidence of a different named current key, its matching public entry everywhere, and cancellation of any pending version being removed.
An orphan entry cannot be used to sign unless someone holds its private key, and registry write access is the authority to publish keys.
Whoever can write a registry secret can already publish any public key; this command does not defend against that party.
It refuses internally inconsistent intents before private evidence reads or repairs: the caller, cell and any replacement must agree with the service and cell encoded in the kid, for every operation kind.
The refusal identifies the field and registry region and makes no writes.

Regions come from the authenticated, signed foundation footprint. Supply a JSON
file to `--targets` containing exactly one entry per discovered region:

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

Include every deployed region using its regional Vault and encryption key.

| Caller | Key id | Private secret |
| --- | --- | --- |
| ts-auth | `ts-auth.CELL.N` | `CELL-1-ts-auth-terrabase-key` |
| dashboard | `dashboard.CELL.N` | `CELL-1-ts-dashboard-terrabase-key` |
| edge | `edge.CELL.N` | `CELL-1-orch-terrabase-key` |

The private secret is a P-256 JWK with `kid`, `kty`, `crv`, `x`, `y`, `d` and
`metadata` holding the caller, grants, expiry and public entry. Public registry
entries contain `kid`, `caller`, `kind`, `jwk` (without `d`), `grants` and
`notAfter`, inside `{ "version": 1, "callers": [...], "highWater": {...}, "intent": {...} }`.
The optional high-water map records the highest sequence used per caller and
originating cell. The optional intent contains the operation id, key id, caller,
cell, replacement and private version identity; an add also carries its public
entry so recovery can finish publication even after the first intent write.
The database verifier ignores these registry bookkeeping fields.

## Add and rotate

For a first key, `add` publishes the public entry in every region before creating
the private secret with that key as CURRENT. Run `list`, roll TerraBase everywhere
to load the public registry, then ship the service spec reference and roll the
service. `list` prints `NO REGISTRY` for each region without a registry.

```sh
ts-orch caller-key add --targets /secure/caller-targets.json --service dashboard --region sjc --kid dashboard.sjc.1 --not-after 2027-11-12T00:00:00Z
ts-orch caller-key list --targets /secure/caller-targets.json
```

For a rotation, `add` publishes the new public entry everywhere and appends a
PENDING private version, preserving CURRENT. Roll TerraBase everywhere, activate
the pending key, then roll the service. After the old key is no longer in use,
retire it with the current replacement and roll TerraBase again:

```sh
ts-orch caller-key add --targets /secure/caller-targets.json --service dashboard --region sjc --kid dashboard.sjc.2 --not-after 2027-11-12T00:00:00Z
ts-orch caller-key activate --targets /secure/caller-targets.json --kid dashboard.sjc.2
ts-orch caller-key retire --targets /secure/caller-targets.json --kid dashboard.sjc.1 --replacement-kid dashboard.sjc.2
```

New keys require more than 30 days of lifetime. Only one pending rotation may
exist at a time. Activation requires matching private contents and the same
public key in every registry, with more than 30 days remaining. The operator
completes the database rollout before activation; the command checks publication,
not what each running database has loaded. Activating an already-current key
reports `already current`.

## Retire and cancel

Retirement requires readable private contents and coherent version metadata:
the service has a CURRENT key with a different id, `--replacement-kid` names that
same service and region's current key, its matching public key is listed in every
region, and the removed id is not pending. These checks run again before each
public removal write. Empty listings never authorize removal. Without a current
secret, retirement refuses until another key becomes current.
Operator and agent keys have no managed regional
private secret from which to establish this evidence, so this command refuses
their retirement too.

For a pending key, `retire --kid KEY` performs cancellation first, including for
expired keys. It conditionally stages a copy of CURRENT to supersede the named
pending version, verifies that version is deprecated, schedules deletion with a
seven-day grace period, and reads back the schedule before removing its public
entry. It reports `deletion scheduled TIME`. A missing cancellation version is
an error, never permission to remove. Cancellation can also clean up a late
pending version whose public entry was previously retired with a replacement.

A cancelled version's deletion can be cancelled through the store's version API
during the grace period; it remains deprecated. Activation requires a matching
pending version and its public entry everywhere. Use a fresh numbered add for
another rotation. Historical private versions stay stored; cancellation schedules
only the identified unactivated version for deletion.

Sequences must exceed the high-water mark and every listed and stored id for
that caller and region. Interrupted adds consume their ids, including those
whose private creation never becomes visible.
Registry size depends on retained public keys and caller/cell high-water marks.
Admission first verifies that every readable CURRENT key already has matching public entries everywhere; repair an existing violation with recover before retrying a change.
Before recording a new intent, the command serializes the initial, publication, completion and possible cancellation documents for every region.
Add and activation admission require each document to fit within 14 KiB of the store's 16 KiB limit, reserving a fixed 2 KiB for recovery.
Add payloads are stored once: after publication the intent references its entry by kid.
Recovery accepts an older full-payload intent, publishes the entry with the compact intent, then records the high-water mark when clearing the intent.
This lets an older add whose entry plus duplicated intent exceeded the store limit finish forward without dropping any public key.

Capacity-releasing retirement or cancellation may consume the reserve up to the hard 16 KiB limit, after checking every intermediate document fits.
This is a capacity-release exception: requiring cleanup intents to preserve the admission reserve would block retirement near that threshold.
Retirement records its intent atomically with each public removal, after fresh positive replacement evidence, so the removed entry supplies space for the record even in a full legacy registry.
Cancellation retains the public entry until deletion scheduling is confirmed.
Recover any outstanding operation, retire retained entries or orphans with a published current replacement until there is room under the admission limit, then add, activate and retire normally.
The command never deletes public entries automatically to make space.

At most eight entries without visible private versions may be outstanding per caller and cell before a new add is refused.
Retire these entries with a current replacement to reopen admission.
Without CURRENT, there is no evidence for safe retirement: let an accepted creation land, or use the issuing secret-store workflow to establish a new CURRENT private key after publishing its public entry in every registry.
This administrative bootstrap requires holding the new private key; it does not authorize deleting or replacing an orphan on absence or age.
Run recover and list to verify the current key before retiring the orphan entries.
A finite orphan bound deliberately stops further first-add attempts when all eight private creations remain invisible.

## Recover and inspect

Every change conditionally records its intent in every region in sorted cell
order. Other changes stop on an outstanding intent. Registry writes compare the
previous version; private writes compare metadata ETags. Stop any remaining
operator process before recovery; do not run recovery alongside a live command.
Store requests retain ordinary request timeouts. No timeout, elapsed age or
agreement between empty listings proves that an accepted creation cannot land.

```sh
ts-orch caller-key recover --targets /secure/caller-targets.json
ts-orch caller-key list --targets /secure/caller-targets.json
```

Recovery outcomes:

- An interrupted add always finishes forward: restore its public entry everywhere,
  consume its sequence and clear the intent. Whenever that kid's private version is readable, derive its public half in memory and require the entire public payload to equal the recorded entry before any repair or publication.
  A difference refuses with no writes. Registry writers already have publication authority; no signing scheme is added.
  If readable and matching, report `current` or `pending`. Otherwise report `public entry kept; private key not visible: run add
  again for a new key, or wait: retire this entry only with a current replacement`.
  Recovery never recreates a lost private half.
- Activation finishes forward if already current or still eligible. An expired
  or short-lived pending key becomes cancellation, using the same positive
  evidence and deletion readback. An already-promoted expired key reports
  `current key expired`.
- Retirement and cancellation finish only with positive evidence. Missing,
  unreadable or inconsistent private state stops recovery and preserves remaining
  public entries. If a write interrupts completion, the error says
  `interrupted: run recover`; there is no timed waiting outcome.
- With no intent, report `no operation in progress` and inspect current keys.
  The only automatic write without an intent repairs a current key's missing or
  mismatched public entry, using the public half derived in memory from its
  private scalar and the caller metadata stored with that key. Each repaired
  region is reported. Recovery also performs this inspection with an intent.

`list` labels public entries `current`, `pending`, `orphan (no private key visible)`
or `retained` for visible historical versions, together with their expiry status.
Expired pending keys say `can only be cancelled`. For every service with a secret,
it checks that its CURRENT id has the same public key in every region. It exits
non-zero and prints one loud line per violation:
`current key KEY in region CELL has no public entry in regions CELLS`.
A mismatched public key is also a violation. `list` makes no writes.

A first creation may land arbitrarily late after an interrupted command: its
public entry stays present, so becoming CURRENT is safe. A subsequent add uses
a new id: if the first creation already landed it stages a rotation; otherwise
it attempts a create-once name. If competing creations overlap, that name admits
only one CURRENT secret and both possible keys already have public entries.
Rehearse both delivery orders when two accepted first creations outlive both adds.
A late rotation remains PENDING; retirement of its public entry requires a
published current replacement. Without its public entry activation refuses,
and cancellation can clean up that pending version.

## Adapter contracts and disposable-store rehearsal

Rehearse an adapter on a disposable store before using it with real identities.
These contracts remain necessary; there is no late-write completion bound or
shared-clock requirement:

| Contract | Readback and limits |
| --- | --- |
| Create-once regional secret names | The store rejects a duplicate name rather than overwriting CURRENT. Private reads bind the named secret, CURRENT contents, id and version metadata; registry readback checks the exact published document. Conflicting first creations must leave one secret, never replace its contents. |
| Conditional writes | Registry publication checks the previously read version and metadata ETag; staging and promotion condition on the private ETag, deletion on the version ETag. Readback detects changed contents or inventory. A provider ignoring these conditions can race between reads and mutations and is unsupported. |
| Version stages and coherent contents | CURRENT and every usable version are read with their metadata; CURRENT must agree with its version bundle, and metadata ETags must agree before and after inventory. Scheduled versions must be deprecated, never CURRENT or PENDING. Readback rejects missing or inconsistent inventory. |
| Promotion | Updating the current version must promote exactly the identified pending contents without changing those contents. CURRENT readback rejects a different version or value. |
| Pending supersession and deletion | Staging the current contents must leave CURRENT unchanged and supersede the old pending version. Deletion requires deprecated, non-current, non-pending metadata, then an exact schedule readback and coherent inventory. A missing schedule or still-usable version blocks public removal. The provider must honor the seven-day deletion grace. |

On a disposable store with subprocess termination and deferred request delivery:

1. Interrupt a first add at every write boundary and recover. Its public entry
   appears everywhere and its sequence stays consumed, even with no private key.
2. Deliver an accepted first creation at an arbitrary later time: immediately,
   after recovery, during or after another add, and after a retire attempt. Assert
   after every mutation that any CURRENT key has its matching public entry in
   every region. A no-secret retire attempt must refuse without writes. Competing
   creates must honor create-once names; a key becoming current must stay published.
3. Add again with the next id. If a secret exists, confirm this is a rotation;
   otherwise create a new first key. Rotate, verify CURRENT stays unchanged until
   activation, then promote and verify exact CURRENT contents.
4. Cancel a pending key, including an expired one and a late pending version
   without a public entry. Check supersession, deprecation, deletion schedule and
   the unchanged current replacement. Refuse activation without publication.
5. Retire with a different published current replacement. Refuse without that
   replacement, without a secret, or while the removed version is still pending.
6. Interrupt add, activate, retire, cancel and recovery at every write boundary,
   including uncertain responses, unreadable accepted writes and arbitrarily late
   requests. Recover twice and assert convergence, consumed sequences and no key
   material in output. Exercise concurrent commands with opposite target orders.
7. Remove a CURRENT public entry behind the tool's back, then repeat with a
   different public key under the same id. `list` must exit non-zero without
   writing. `recover`, with and without an intent, must derive and republish the
   correct public half, report each repair and leave `list` successful.
8. Complete 50 rotations, checking matching publication after each mutation and
   bounded registry size after retirement. Confirm an already-promoted key that
   expires before recovery is reported as `current key expired`.
