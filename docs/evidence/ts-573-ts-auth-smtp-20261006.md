# TS-573: ts-auth SMTP relay through OCI Email Delivery, 2026-10-06

ts-auth on gru-1 had no SMTP relay, so it logged sign-in passcodes instead
of mailing them (TS-550 refound result). This records the relay's OCI
objects (names and OCIDs only, never values) and the in-place rollout.

## OCI Email Delivery (sa-saopaulo-1, ready before this ticket)

| Object | State |
| --- | --- |
| Email domain `terrascale.tech` (tenancy root) | ACTIVE, DKIM `terrascale-tech-dkim` ACTIVE, SPF includes `rp.oracleemaildelivery.com` |
| Approved sender `noreply@terrascale.tech` (tenancy root) | ACTIVE |
| Suppression list | does not hold `mariogk@terrascale.tech` |

## Least-privilege sender, 2026-10-06T08:04Z

| Object | OCID |
| --- | --- |
| Group `gru-1-ts-auth-smtp` | `ocid1.group.oc1..aaaaaaaahddxx5lwnov74e2jwsr7odv5abdjtvnbutdui6lfyeghjkjgevnq` |
| User `gru-1-ts-auth-smtp` (Default domain) | `ocid1.user.oc1..aaaaaaaaoi7xcjwymqjckmtckti5y2qq5l4hxxsitxrpxzs37pwh42hlnh3a` |
| Policy `gru-1-ts-auth-smtp` (tenancy) | `ocid1.policy.oc1..aaaaaaaaqkqq7blh25bsfomp266mhqefiidziemkfiv33atxumfxnxar6qma` |
| SMTP credential | `ocid1.credential.oc1..aaaaaaaa4m32fha3kssv5ck3tj2kephmvvzdmxqgqtnmdy5va6bjti3rwh7a` |

The user may use SMTP credentials only: console password, API keys, auth
tokens, customer secret keys, DB credentials and OAuth 2 client credentials
are off. The policy's one statement:

```text
Allow group gru-1-ts-auth-smtp to use approved-senders in tenancy where target.approved-sender.emailaddress = 'noreply@terrascale.tech'
```

## Vault secrets, 2026-10-06T08:06Z

The credential's output went to an owner-only file on tmpfs, each field was
piped to `ts-orch vault put --file /dev/stdin`, and the file was shredded.
`vault put` read each secret back and compared it to its input.

| Secret | Compartment | OCID |
| --- | --- | --- |
| `gru-1-ts-auth-smtp-username` | `gru-1-control` | `…kgsbv6ly3nbgeethga` |
| `gru-1-ts-auth-smtp-password` | `gru-1-control` | `…ndv3prl3cbwlja` |

## Relay check, 2026-10-06T08:12Z

From delta, with the two secrets read from the Vault into the environment of
one process: `smtp.email.sa-saopaulo-1.oci.oraclecloud.com:587`, STARTTLS
with certificate validation, AUTH, `MAIL FROM:<noreply@terrascale.tech>` 250,
`RCPT TO:<mariogk@terrascale.tech>` 250, then RSET (nothing sent). AUTH
answered 535 for about six minutes after the credential was created.

## Path from the cell

The relay resolves to `192.29.129.230`, inside `192.29.128.0/23`, an `OSN`
range of sa-saopaulo-1. `gru-1-private-routes` sends
`all-gru-services-in-oracle-services-network` to the service gateway, and
`gru-1-private-security` allows all egress there, so the controllers reach
the relay without internet egress. The ts-auth metadata firewall drops only
169.254.169.254.

## In-place rollout, 2026-10-06T08:56Z to 09:01Z

No re-found and no relaunch. Run from mariogk-dev with TS-550's operator
config, after TS-550 recorded re-found 6 serving (spec generation 6).

1. Update receipt for `main` `52fda5a2` (with #227; CI run 1281, arm64
   `2346c4db1437…`), leaf-signed under the root-signed binary update
   delegation (canary, GRU, arm64, lineage base `b545cea8`), valid to
   2026-10-13.
2. `selfupdate stage --allow-scoped-auto-sign` and `activate --proof-window
   10m --restart` on gru-1-ctl-3 (08:57Z), ctl-2 (08:58Z), then ctl-1
   (08:59Z). Each watchdog confirmed, `current` names `2346c4db…`, and each
   host agent was restarted onto it. ctl-2's host agent failed its first
   start (`connect regional NATS: EOF` while its controller restarted) and
   came up on systemd's retry 6 s later. `gru.api` and `gru.auth` answered
   200 throughout.
3. Spec generation 7, root-signed (`745b42ea…`): the live ts-auth profile
   (seven refs, `TS_AUTH_SERVICE_CLIENTS` included) plus
   `TS_AUTH_SMTP_HOST`, `TS_AUTH_SMTP_PORT`, `TS_AUTH_SMTP_FROM_ADDRESS` and
   the two SMTP refs. `root_required`: `service ts-auth Vault secrets`.
   Applied 08:59:37Z.
4. `operator ts-auth-release` of ts-auth `f8e35965` (digest `e7f8a5ff…`) with
   that profile: `ready` on 2 replicas at 09:00:38Z. Both replicas
   (gru-1-ctl-1, gru-1-ctl-2) hold all five `TS_AUTH_SMTP_*` keys (names
   checked, not values) and logged no "not configured" warning.

## Passcode, 2026-10-06T09:06Z: not delivered

- ts-auth serves no user API yet, and the re-found left
  `mariogk@terrascale.tech` without an account, so no code could be issued.
  A one-off program on ts-auth's own `Users.CreateAsync` (release source
  `f8e35965`) created it: user `af96597a-1c4a-4634-b543-14280b1762c0`,
  09:05:37Z.
- dash/login, authorize, then `POST /ui/terrascale/sign-in` at 09:06:15Z
  answered "Check your email". The passcode record shows
  `issuedInWindow=1`.
- At 09:07:16Z gru-1-ctl-1's replica logged `SMTP delivery failed`:
  `MailKit.Security.SslHandshakeException`.
- OCI Email Delivery: no `EmailsAccepted` or `EmailsRelayed` datapoint since
  09:00Z (checked until 10:22Z); the last accepted email was on
  2026-09-26. `mariogk@terrascale.tech` is not suppressed.

Cause: from gru-1-ctl-1, `openssl s_client -starttls smtp` verifies the
relay's chain (DigiCert Global G2 TLS RSA SHA256 2020 CA1, return code 0),
but its OCSP and CRL URLs (`ocsp.digicert.com`, `crl3`/`crl4.digicert.com`,
`cacerts.digicert.com`, on Akamai) time out: the cell's only internet egress
is TCP 443 to Cloudflare. MailKit checks revocation online by default, so
it refuses the relay.

## Revocation opt-out and delivery, 2026-10-06T11:01Z to 11:05Z

ts-auth#38 adds `TS_AUTH_SMTP_CHECK_REVOCATION` (default `true`; `false` is
a documented security exception: STARTTLS, chain and host name are still
checked). #238 sets it to `false` in the gru-1 profile.

1. ts-auth `aa69651` (#38): release `v0.1.0-dev.aa69651…`, binary
   `b1af83ef…`. Its CI publish job failed its read-back (as on `f8e3596`;
   fixed by ts-auth#39), but the published pair verifies.
2. Spec generation 9, root-signed (`6f613208…`): the live ts-auth profile
   plus `TS_AUTH_SMTP_CHECK_REVOCATION=false`; `root_required` empty.
   Applied 11:01:25Z.
3. `operator ts-auth-release` of `aa69651` (previous `e7f8a5ff…`): `ready` on
   2 replicas at 11:03:25Z, `/readyz` version `0.1.0+aa69651b7448`.
   `gru.api` and `gru.auth` answered 200 throughout.
4. Passcode for `mariogk@terrascale.tech` through dash/login, authorize and
   `POST /ui/terrascale/sign-in` at 11:03:34Z ("Check your email"). The
   gru-1-ctl-1 replica logged no SMTP failure.
5. OCI Email Delivery, sender `noreply@terrascale.tech`
   (`resourceDomain` `terrascale.tech`): `EmailsAccepted` 1 and
   `EmailsRelayed` 1 at 11:04Z. `mariogk@terrascale.tech` is not on the
   suppression list.
