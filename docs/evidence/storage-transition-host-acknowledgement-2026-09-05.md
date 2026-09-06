# Host acknowledgement composition

Local `ts-node` plan intake now creates the host's durable signed acknowledgement
through `EpochStore.AcknowledgeStorageTransitionPlan`. Pre-NATS agreement recovery
also creates a missing acknowledgement or returns the retained bytes. The signed
delivery configuration requires a separate root-owned host receipt-key path.
The owner-signed plan binds its expected public identity.

The epoch-store API returns `ErrStorageTransitionReceiptSignerRequired` only
when a validated pin has no receipt. The caller uses that result to load the
first-use signer. Other errors do not trigger key loading or receipt replacement.
Successful retries need no signer and preserve the original receipt.

The isolated root race suite verifies:

- missing, wrong and publicly readable key material produces no receipt while
  preserving the already admitted plan;
- restoring the correct protected key produces a verifiable destination receipt
  bound to that private pin and host;
- deleting the key after acknowledgement permits byte-identical restart recovery;
- corrupt receipts are refused and retained, without being treated as missing
  signer state or overwritten;
- the source receipt binds its original live capture command, survives key-free
  restart, and still cannot retire the source before the preparation barrier;
- candidate startup/expired-initial recovery and existing source publication,
  retirement and crash tests still pass.

Portable tests cover the new sentinel result, missing key paths, relative and
colliding paths, writable storage overlap, and unchanged canonical encoding
when optional delivery is absent. The configured two-field prelaunch draft is
refused; no persisted transition history is rewritten.

The root command uses a private mount namespace and temporary `/var/lib`:

```sh
sudo -n unshare -m --propagation private bash -c 'mount -t tmpfs -o mode=0755 tmpfs /var/lib && mkdir /var/lib/transition-tests && TMPDIR=/var/lib/transition-tests TS_INITIAL_R1_ISOLATED_TEST=1 /tmp/ts-host-plan-ack.test -test.run "^Test(StorageTransition|CandidatePreparation|InitialR1Host)" -test.v -test.timeout 60s'
```

Root, focused race and portable check logs accompany this record. These tests
use synthetic signed plans and local journals. Remote plan/key provisioning,
independent receipt publication and collection, the complete preparation
barrier, final capture, R3 promotion and production qualification remain open.
