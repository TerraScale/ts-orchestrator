# ts-orchestrator control check failure brief

Evidence source: `/tmp/terrascale-control-check-current.log`, from clean
commit `be9010aee89393feaa19f49b9dd6d2f2bcf7f805`. No production or test code
was changed during diagnosis. Focused race runs of each failing test passed
three consecutive times, so these are suite-sensitive failures rather than
deterministic reproductions.

## hostbootstrap

`hostbootstrap.TestOfflineInitialGrantActivatesWithoutBrokerAndRetires`
failed at `run_test.go:128` with `context deadline exceeded`. The fixture
sets `LocalBootstrapConfig.Timeout` to only three seconds (`run_test.go:115`).
`RunLocalBootstrap` always performs `WaitInitialServices`, which requires
three 250ms observations, including on the second invocation after the
component is already installed. Under the full race suite, the second call
can consume the entire three-second operation budget. The isolated test and
three-repeat focused run pass.

Bounded repair: keep the production deadline semantics and add a deterministic
test budget that accommodates the documented readiness observation, or make
the fixture’s readiness observer explicitly immediate while retaining a
separate test for deadline expiry. Do not remove the context bound or simply
retry after `DeadlineExceeded`.

## initialcontrol

`initialcontrol.TestInitialProfilesSnapshotRestoreR3Recovery` failed at
`profile_promotion_test.go:664`, inside `source.start`, with
`broker listener unavailable GRU_SOURCE` after the 10-second
`ReadyForConnections` wait. The test allocates client and route ports by
listening on `127.0.0.1:0`, closes the listener, and later reuses the saved
port (`profilePromotionPort`, lines 26-36). This is a TOCTOU port reservation;
the full `go test ./...` run starts many NATS fixtures concurrently. The
failure diagnostics show all three existing servers healthy with 15 streams,
but the GRU restart never became ready. The focused test passed, including
three repetitions.

Bounded repair: make the broker fixture own stable reserved ports across its
full stop/start lifetime, or allocate and wire a complete fresh port set for
each restart before starting the cluster. Preserve the explicit readiness
deadline and report the configured client/route ports on failure. Do not
convert the 10-second wait into an unbounded wait or hide a bind failure with
blind retries.

## keylease

`keylease.TestLeaseRestartRotationAndRevocation` failed at
`server_test.go:122` (`WriteCatalog` returned an error, reported as
`revocation failed`). In `Server.handle`, the catalog lock acquired for the
post-unwrap recheck is deferred until the handler returns; the success frame
is written before that return. The test reads the frame and immediately calls
`WriteCatalog`, whose `catalogLock` uses `LOCK_NB`. Therefore the test can
observe a complete response while the server still owns the flock, producing
a transient `ErrUnavailable`. The isolated test and three-repeat focused run
pass.

The lock must remain held through socket transmission. `keylease/README.md:44`
explicitly defines that lifetime, and `database-crypto-shred-decision.md:95`
requires deletion to share the lock with final lease transmission. Releasing
it before the response would let a revocation commit before stale key bytes
are delivered, violating the linearization contract: a response is authorized
by the catalog state protected at the final check and remains an already-issued
lease afterward.

Bounded repair: treat `WriteCatalog` lock contention as the documented
retryable `ErrUnavailable` result. In this test, replace the immediate single
write after reading the response with a short, deadline-bounded retry helper
that retries only `ErrUnavailable`, then assert the revoked request returns
the refusal frame and does not call the unwrap function. Add a deterministic
unit-level lock contention test by holding `catalogLock` while calling the
writer, asserting immediate `ErrUnavailable`; retain the existing
revocation-during-unwrap test for the final lookup race. Do not release the
server lock before transmission, weaken revocation checks, or add unbounded
lock retries.

## Verification limits and next action

`make check` has no live OCI or Cloudflare gate. The provider and sandbox
provider packages passed as local tests; VM qualification targets are
separate. The checkout now contains concurrent edits in production/test
paths plus the pre-existing `.tmp-derive-rootfs/main.go` deletion; those
changes were not inspected or altered for this brief. Implement the three
bounded repairs in their owning lanes, then rerun the focused tests before a
coordinated full `make check`.
