# Storage-transition local intake

The source seed and SFO/FRA candidate configurations can now carry a signed
transition ID and exact local plan-file location. The host receiver verifies
that file using its original bootstrap owner key and pins the plan in its
existing private epoch journal. Candidate startup, expired-initial candidate
recovery, the source manifest handler and pre-NATS agreement recovery compose
this intake. Remote transfer and phase execution remain unfinished.

The root race suite runs in a private mount namespace with a temporary
`/var/lib`. It verifies:

- candidate initialization automatically pins the delivered plan, with the
  original preparation and expired-initial recovery paths still working;
- destination agreement recovery opens no NATS transport, retains exact private
  pin bytes, and refuses a differently signed plan without overwriting history;
- foreign-owner, expired, malformed and noncanonical plans create no pin;
- a live source capture command pins its plan but refuses the missing preparation
  barrier before changing the manifest, service units or live source admission;
- a runtime-only verifier cannot bypass the original source's barrier; and
- an opted-in candidate's ordinary command cannot advance its epoch or revoke
  preparation before the barrier exists.

The same isolated run includes the existing source publication, retirement,
retry and crash-before-manifest-rename tests without optional delivery. Portable
configuration tests verify omission from old canonical wires, signed roundtrip,
transition identity, and separation from writable/capture/admission paths.

The root run used the compiled race test binary with this command:

```sh
sudo -n unshare -m --propagation private bash -c 'mount -t tmpfs -o mode=0755 tmpfs /var/lib && mkdir /var/lib/transition-tests && TMPDIR=/var/lib/transition-tests TS_INITIAL_R1_ISOLATED_TEST=1 /tmp/ts-storage-delivery-host.test -test.run "^Test(StorageTransition|CandidatePreparation|InitialR1Host)" -test.v -test.timeout 60s'
```

The first source attempt used the tmpfs default mode and was refused by the
existing proof-ancestry permission check. The corrected isolated mount uses
`0755`; production permission checks were not weakened. Root, focused race and
portable check logs accompany this record.

These are local intake and refusal/recovery tests using synthetic signed plans.
They do not establish independent acknowledgement publication, actual host
health, remote plan delivery, a full preparation barrier, final capture, R3
promotion, a separate GRU destination launch, or production readiness.
