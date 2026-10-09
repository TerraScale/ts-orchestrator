# Explicit retirement storage upgrade

A TS-632 rename deliberately keeps the old registration retired. The legacy
`TS_HOST_STATE` key `retired.<cell>.<node>` must remain byte-for-byte unchanged
while old controllers can lead. A quarantine is permanent: it denies that
identity's registration, sessions, allocation, unretirement and another
reclamation, even after
cutover or an ordered-log record claiming `retired:false`. It is not a general
legacy reader or an automatic migration.

1. Quiesce all legacy retirement writers. Verify no node rename or other node
   lifecycle operation is queued/running, no reclamation is in flight, and
   hostpool wiring cannot invoke a provisioner/retirer. Keep lifecycle commands
   paused until every controller is upgraded. Freezing rollout alone does not
   pause these writers. Preserve private evidence of the exact legacy entry,
   revision, retained history, completed rename, and withdrawn old desired roles.
2. Create the immutable, operator-authorized quarantine before deploying the
   new controller. `host.CreateRetirementQuarantine(ctx, js, claim)` validates
   the leader's exact legacy bytes/revision and creates only the quarantine
   key. It never changes the active mark. A failed or uncertain write requires
   read-only reconciliation; do not overwrite an existing claim or blindly retry.
3. Deploy to each controller in place. Claims are validated independently of
   legacy-key enumeration, so deleting a legacy key still prevents startup.
   Every unmatched legacy key, mismatched claim, cleared mark, malformed record,
   changed revision/hash, and deleted mark is refused. The current new authority
   leader retries the dedicated retirement import under its epoch and the
   ordered log's global/subject CAS. Its final verifier rechecks both records.
   Repeating the same import does not move the historical boundary.
4. Verify every controller's actual binary and confirmed release, the retained
   KV mark, and the imported ordered `retired:true` event. Obtain the complete
   claim-set digest with `host.RetirementQuarantineSetSHA256(ctx, js, cell)`.
   It binds the sorted claims, their exact bytes, and their KV revisions.
5. Authorize ordinary retirement/unretirement writes only after every old
   controller is gone: call `host.AuthorizeRetirementCutover(ctx, js, cell,
   reviewedSetSHA256, previousMarkerRevision)`. Pass zero for the first create;
   replacements require the exact previous revision. A missing, malformed,
   stale, or deleted marker keeps these writes disabled. Adding or rewriting a
   claim invalidates the marker and requires restarting controllers to load
   the new immutable quarantine set plus a newly reviewed cutover authorization.
   Quarantined identities stay denied permanently.

The claim key is `retirement-quarantine.<cell>.<node>` in `TS_HOST_STATE`:

```json
{
  "schema": "terrascale.host.retirement-quarantine.v1",
  "cell": "gru",
  "node": "gru-1-ctl-2",
  "legacy_key": "retired.gru.gru-1-ctl-2",
  "legacy_revision": 1203685,
  "legacy_sha256": "<SHA-256 of the exact retained legacy bytes>"
}
```

The cutover key is `retirement-cutover.<cell>` in the same bucket:

```json
{
  "schema": "terrascale.host.retirement-cutover.v1",
  "cell": "gru",
  "quarantine_set_sha256": "<digest returned by RetirementQuarantineSetSHA256>"
}
```

These APIs use existing authenticated JetStream access and the allowed bootstrap
store. They do not read or print secrets. No private keys or bearer tokens belong
in either record. An operator must independently verify permanent retirement
and fleet completion; creating a record is not that verification.

Before the import exists, usage inventory is unavailable. A window whose start
precedes the actual JetStream timestamp of any quarantine import is also
unavailable (the usage API reports incomplete inventory/HTTP 503). At or after
that boundary, the usual cached-baseline and freshness rules still apply.
The old legacy `at` value is evidence for the quarantine, not a backdated event.

Old controllers read their legacy mark and lease subject; the new quarantine
and retirement subjects do not change those parsers. They cannot see ordinary
new ordered retirement marks, which is why writer quiescence and the explicit
fleet cutover are required. Preserve both quarantine and legacy keys permanently;
never remove or clear the active mark to bypass validation.
