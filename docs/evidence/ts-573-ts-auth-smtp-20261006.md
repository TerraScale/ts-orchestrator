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

## In-place rollout

Pending. gru-1 is being re-found by TS-550 (refound-6, controllers on `main`
`8ea7e6ca`). That build refuses a `TS_AUTH_SMTP_USERNAME` ref, so the
rollout waits for a `main` build with this change, then runs in place:

1. `selfupdate stage` and `activate` of that build on gru-1-ctl-3, ctl-2,
   then ctl-1, each confirmed by its watchdog, and each host agent restarted
   onto it.
2. `ts-orch service update --role ts-auth` with the live profile (`ts-orch
   get`) plus the three SMTP settings and the two SMTP refs; before
   refound-6 the live profile also named `TS_AUTH_SERVICE_CLIENTS`
   (`gru-1-ts-auth-service-clients`). `release sign-spec --root`, `diff`,
   `apply`.
3. `operator ts-auth-release` of the running ts-auth release with that
   profile; the gate replaces one replica at a time.
4. A passcode for `mariogk@terrascale.tech`, then OCI Email Delivery's
   accepted and delivered counts and the suppression list.
