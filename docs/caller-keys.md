# Service caller keys

`ts-orch caller-key add|retire|list` manages regional ES256 service identities with
operator OCI credentials. It does not restart services. Its output contains only
secret names and key ids.

Supply an operational JSON file to `--targets` containing one entry per region
in `deploy/m1/regions.json` (or the file supplied to `--regions`):

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
cell's regional Vault and encryption key. The command reads all registries before
writing and refuses conflicting entries with the same key id.

```sh
ts-orch caller-key add --targets /secure/caller-targets.json --service ts-auth --region sjc --kid ts-auth.sjc.1 --not-after 2027-11-12T00:00:00Z
ts-orch caller-key list --targets /secure/caller-targets.json
ts-orch caller-key retire --targets /secure/caller-targets.json --kid ts-auth.sjc.1
```

Supported callers are `ts-auth`, `ts-dashboard`, and `edge`. Grants follow the
caller's service role. Key ids have the form `SERVICE.REGION.SEQUENCE`; rotation
requires a larger sequence than the current private key. Add writes each
`CELL-1-terrabase-callers` registry before writing the caller's private secret:

| Caller | Private secret |
| --- | --- |
| ts-auth | `CELL-1-ts-auth-terrabase-key` |
| ts-dashboard | `CELL-1-ts-dashboard-terrabase-key` |
| edge | `CELL-1-orch-terrabase-key` |

The private value is a P-256 JWK with `kid`, `kty`, `crv`, `x`, `y`, and `d`. Public
registry entries contain `kid`, `caller`, `kind`, `jwk` (without `d`), `grants`,
and `notAfter`, inside `{ "version": 1, "callers": [...] }`.

For rotation, add a new key while retaining the old registry entry. Roll TerraBase
in every cell before rolling the caller to load its new private key. Retire the
old key after its use has ceased, then roll TerraBase again. Retire removes only
the public entry, preserving other callers and historical private secret versions.

Updates to existing secrets use the version read during preflight and OCI
`If-Match`. A failed or uncertain publication stops the command; it does not
roll back successful registry writes. If add fails partway, inspect `list`, retire
the incomplete key id from all registries, and retry with a fresh sequence. A
registry publication failure leaves the caller's private secret unchanged.
