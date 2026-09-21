# Regional NATS authentication before OCI

Regional `run`/`check` and the operator CLI accept either a private NKey seed
or a NATS user JWT credentials file. Set exactly one of
`TS_ORCH_NATS_NKEY_FILE` and `TS_ORCH_NATS_CREDENTIALS_FILE`. Both require
`tls://` and complete mutual TLS credentials for `run` and operator commands:
`TS_ORCH_NATS_TLS_CA_FILE`, `TS_ORCH_NATS_TLS_CERT_FILE`, and
`TS_ORCH_NATS_TLS_KEY_FILE`. Runtime JSON maps `natsCredentialsFile` to the
same setting. Provisioning and journal-writer roles reject regional credentials.

The bounded, owner-private credentials file must contain one JWT block and
one seed block. The parser rejects duplicate blocks/claims, malformed or
noncanonical base64url, non-user claims, unsupported JWT shape, and a JWT
subject that differs from the seed's public key. The NATS server verifies
issuer trust, signature, expiry and permissions. Local parsing is not an
authorization decision. Distinct regional/global roles must use distinct
NATS public keys and TLS identities, even when one supplies a seed file and
another supplies JWT credentials for that seed.

The operator CLI accepts `--credentials-file` as well as the environment
setting. For a separately issued read-only operator identity:

```bash
terrascale-orchestrator operator operator-status \
  --cell gru --nats-url tls://control-gru.internal:4222 \
  --credentials-file /run/terrascale/operator.creds \
  --tls-ca-file /run/terrascale/ca.pem \
  --tls-cert-file /run/terrascale/operator.pem \
  --tls-key-file /run/terrascale/operator-key.pem
```

## Controller permissions

`RegionalNatsPermissions.Create(cell, instance, publicKey)` produces a bounded
runtime allowlist for an already provisioned regional NATS account. The R3
JWT fixture uses this plan directly. It includes exact stream inspection,
startup and per-instance CellSpec consumers, controller KV/object operations,
service discovery, private caller replies, and the regional host report relay.
The immutable protocol-package object store is read-only. It grants no stream
creation/update, isolated operation/proof journal access, another controller's
private journal replies, or another region's control subjects. Separate NATS
accounts pin the unqualified JetStream bucket names to their regions.

The protocol manifest remains the control-subject contract; the runtime plan
adds the specific NATS API subjects its callers need. Controllers and operators
share only the closed read-only status and membership request subjects.
Controllers can probe instance health. Mutation publishing remains owned by
one account kind. Host credentials remain pinned to one hashed host identity.

Use this runtime plan with `TS_ORCH_AUTO_PROVISION=0`. A separate provisioning
identity must install the exact streams, consumers and canonical protocol
package before startup. The first-boot account/JWT issuer and rotation workflow
still need composition; this library plan does not issue or deploy credentials.
Do not replace it with `$JS.API.>` to make bootstrap pass.

## Local proof and remaining boundary

`NatsControlR3L0cTests.Regional_runtime_starts_with_JWT_mTLS_credentials_and_serves_operator_status`
starts the actual regional runtime against three real NATS servers using this
restricted controller plan. It checks authenticated operator status and invokes
the operator CLI with a separate read-only operator identity. Other
tests exercise private-journal denial, immutable-package write denial,
cross-region denial, host report persistence and restart. Configuration tests
cover mixed-format identity reuse and malformed credentials.

OCI-format node IDs now produce stable DNS-safe allocation names derived from
cell/node/artifact identity. Full node identity remains in enrollment/report
bodies, and upgrades keep the same allocation. This fixes allocation naming;
the current controller instance parser still cannot serve as the OCI host
entry point.

Fresh host startup remains blocked on a dedicated host role, bounded remote
enrollment/desired/artifact/lease protocols, restart/renewal, and durable drain.
Signed enrollment now binds the exact environment and workload roles. The
[host session authentication component](host-session-authentication.md)
adds proof of possession for the enrolled user key; durable session authority
and its broker/runtime callers are still pending.
OCI Instance Principal, Vault policy, first boot, region formation and seed
ownership handoff still require their own qualification. See the
[OCI readiness record](../evidence/oci-readiness-2026-09-20.md).
