# Receiver authority

This package verifies the shared signed command envelope against the exact
admitted node, subject, authority candidate, lease and signing key. It reads
`authority.regional` through `$JS.API.STREAM.MSG.GET.KV_<bucket>` and compares
the current lease before accepting a mutation. The pinned NATS server only
answers that API from the assigned stream leader; this package does not claim
a stronger per-read quorum barrier. Production reads require authenticated
NKey/JWT plus verified TLS 1.3 and a client certificate.

`EpochStore` writes and syncs a root-owned epoch floor before effects, validates
it on restart, and retains a process-wide file lock for the receiver lifetime.
Its directory is the existing private ts-node command-journal directory.

Production ts-node JSON must contain:

```json
{
  "authorityBucket": "ORCH_LEADERS",
  "commandTrustKeys": [
    {
      "candidateId": "gru-controller-MATCH_ACTUAL_INSTANCE",
      "publicKeyFile": "/etc/terrascale/command-public.pem"
    }
  ]
}
```

The public key is P-256 SPKI PEM. Candidate IDs must match the actual regional
runtime lease. These fields supplement the existing NKey/TLS and signed
release configuration. `hostcontrol.Config.SigningKey` holds the matching
private key on the controller; it does not belong on the node.

Read-only status requires no regional lease. Mutations require a live lease;
bootstrap before that lease exists needs its separately authenticated initial
manifest/grant path. There is no unsigned mutation fallback. A process crash
leaves pending outcomes in the durable journal for a freshly authorized
reissue. Already-running systemd effects cannot be made atomic with an external
lease transition and may complete after cancellation.
