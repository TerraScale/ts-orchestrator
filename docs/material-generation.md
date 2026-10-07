# Material generations (TS-568)

A material generation renews a running cell's bootstrap material in place,
so the cell does not have to be re-founded before its material expires. See
[self-healing](self-healing.md), step 3, for the whole renewal plan. This
page covers what a generation is and how the owner signs one. Controllers
do not adopt generations yet. That is the next step.

## What a generation pins

The owner's root signs one generation per cell. It has the same envelope as
the bootstrap manifest and is scoped to the deployment, the cell and the
environment. Each generation pins, by OCI Vault reference (secret OCID,
version, SHA-256 and size bound), exactly these renewable files:

| File | Vault purpose |
| --- | --- |
| `ca.pem`, `operator.jwt`, `system.jwt`, `cell.jwt`, `system.creds` | `regional-shared` |
| `host-tls-issuer-cert.pem`, `host-tls-issuer-key.pem` | `host-issuer` |
| `controller-tls-issuer-cert.pem`, `controller-tls-issuer-key.pem`, `controller-account-signer.seed` | `controller-issuer` |

- **Pins replace the manifest's.** A generation's pin replaces the
  manifest's pin for the same file.
- **The cell issues its own leaves and user JWTs.** Controller TLS leaves and
  NATS user JWTs come from the controller TLS issuer and the account signer.
  They last at most `issuedLifetimeHours`, which can be up to 90 days.
- **Some secrets never renew.** Founder, response, ticket and route secrets
  do not expire and keep their manifest pins.
- **Fixed keys:** these never change, because brokers and hosts pin them:
  - the NATS operator (`operator`);
  - the system and cell accounts (`systemAccount`, `cellAccount`);
  - the host NATS issuer (`hostSigner`), whose scope `cell.jwt` carries.
- **Account signer:** `accountSigner` is an unscoped signing key of the cell
  account, because controller user JWTs carry their own grants and a scoped
  key cannot sign those.
  - **Risk:** every controller can mint any cell user, and a compromised
    controller could keep such a user until the signer is rotated.
  - **Lifetime cap:** `issuedLifetimeHours` is enforced by the controllers'
    own issuing and by restart admission, not by NATS.
  - **Cleanup after a compromise:** rotate the signer with a new generation.
- **Interregion material** is not part of a schema-1 generation. Schema 2
  can carry it (below).

## Schema 2 (TS-668)

Schema 2 lets a generation link a running cell into the interregion leaf
fabric without re-founding it. Restart admission accepts an installed
schema-2 chain ([below](#restart-admission-with-a-generation)); controllers
install one from TS-668 PR 6 on.
Until then nothing in production installs a generation, and a binary from
before schema 2 refuses one. Schema 2 adds the following:

- **`controllerConfigs`**: one `{slot, manifestSha256, sha256, size}` per
  controller slot, in `controllerSlots` order. Each pins the slot's new
  `controller.json`, bound to that slot's accepted manifest digest. The
  config bytes travel beside the chain, not in it. A config may be at most
  16 KiB, the manifest's own limit.
- **`roleSigner`**: required. It is the public key of the cell account's
  role signer ([role identities](nats-fabric.md#role-identities)).
  `cell.jwt` must carry exactly the host scope and the role scope, plus the
  unscoped account signer when the controller issuers are pinned.
- **Controller issuers all or none.** gru-1 and sfo-1 were founded without
  controller issuers. Without them, `accountSigner` is empty,
  `issuedLifetimeHours` is 0, and the cell issues nothing under the
  generation. Every other renewable file is still required.
- **Interregion files**, Vault purpose `interregion`, all or none:
  - `interregion.jwt` and `interregion-ca.pem`;
  - each slot's `interregion-tls-<slot>-cert.pem` and
    `interregion-tls-<slot>-key.pem`, bound to that slot;
  - on a child, its one `leaf-<parent>.creds`.

  `interregion-ca.key` and `child-<cell>.seed` stay offline and can never
  be pinned. Interregion files require the controller configs.

A chain may move from schema 1 to schema 2 but never back. The role signer
never changes. Once a generation carries controller configs, every later
generation must carry them too, because a controller would otherwise
restart on a config that nothing pins.

The signer adds these checks for schema 2:

- **Controller configs:** each `controller-<slot>.json` in the material
  directory matches its digest and size. Its `nats` block decodes strictly.
  It enables interregion exactly when the interregion files are pinned.
- **Interregion blocks:** each block passes startup's validation. It
  references only pinned files, by absolute path. Each remote pins the
  account that issued its credentials.
- **Contract:** `system.jwt`, `cell.jwt` and `interregion.jwt` pass each
  config's contract (`natscell` `VerifyClaims`). For example, the system
  and cell accounts must set `LeafNodeConn = 0`.
- **`interregion.jwt`** is an account of its own, signed by the operator.
- **Leaf credentials:** `leaf-<parent>.creds` is a leaf user with no
  permissions of its own. It is issued by a scoped key of another
  region's interregion account.
- **Leaf TLS:** each slot's certificate and key match. The certificate is
  not a CA, chains to `interregion-ca.pem`, and holds only DNS names under
  `.interregion.terrascale.internal`.

A controller holds only its own slot's files. `CheckGenerationFiles` skips
another slot's files when they are absent. It needs at least one config
to take the contract from.

## The chain

Generations form a hash chain. Generation 1 has no `previous`. Every later
generation names its predecessor's envelope fingerprint and keeps the fixed
keys.
- **Verification:** a chain is checked by its links and by the newest
  generation's root signature alone, which covers the rest.
- **Root rotation:** the owner can extend a chain after the roots that
  signed older generations were rotated, but a retired root cannot extend it.
- **Adoption:** a controller adopts only a generation that extends the one
  it holds.

## Sign a generation

Put the files in one directory under their target names, publish them to
Vault, and write the unsigned candidate (`bootstrap.MaterialGeneration` JSON)
with their references. For schema 2, also put each pinned controller config
in the directory as `controller-<slot>.json`. The command refuses a
candidate if any pinned file or config is missing. Then run:

```sh
ts-orch bootstrap sign-material-generation \
  --candidate generation-2.json --material ./generation-2-files \
  --chain gru-generations.json \
  --root-key root.pub --signing-key root.key \
  --out gru-generations-2.json
```

Leave out `--chain` for generation 1. Only the new generation's signature
is checked against `--root-key`. The command checks every file with the
rules the running cell applies (`bootstrapmaterial.CheckGenerationFiles`):

- **Digest and size:** each file matches its pin.
- **CA bundle:** `ca.pem` holds one to four self-signed root CAs.
- **Both issuers:**
  - each is a path-length-zero intermediate signed by a bundle CA, and is
    not itself a CA in the bundle;
  - each has a single-block EC key that matches it.
- **Controller TLS issuer:** it issues server and client leaves.
- **Host TLS issuer:** it is client-only and name-constrained to
  `hosts.<cell>.terrascale.internal`, as `hostenroll` loads it.
- **Account signer:** the seed is `accountSigner`.
- **JWTs:**
  - `operator.jwt` is the operator's own, names the system account and has
    no signing keys.
  - `system.jwt` and `cell.jwt` are signed by the operator.
  - `cell.jwt` grants JetStream and has exactly two signing keys: the host
    scope of `hostSigner` and the unscoped account signer. Schema 2 differs
    (see above).
  - `system.creds` is a system account user with only its claim-update and
    reply grants.
- **Validity:** everything is valid now.

A broker also checks a new `cell.jwt` against the running claim (a later
issue time, the interregion exports) when it applies it.

The signature expires at the earliest certificate or JWT expiry the files
hold, and never more than 400 days after signing. The command writes the
whole chain with the new generation appended to a new file. It never
overwrites an existing file. It prints the generation number and
fingerprint.

## Restart admission with a generation

A controller holds its adopted chain as `material-generations.json` in its
credential directory (`/var/lib/terrascale-orchestrator-secrets`), beside the
files the chain pins. On every restart, admission reads that file before
anything else in the directory.

**Without the file**, admission pins the manifest's digests, exactly as
before any generation.

**With the file**, admission does the following:

1. **Verify the chain.** It checks the hash links and the newest root
   signature against the baked roots and the adopted root chain. It does not
   check the current time, because the chain was current when it was
   adopted.
2. **Pin the newest generation.** Its digests replace the manifest's for the
   renewable files, and it adds the controller issuers, the interregion
   files (of the leaf TLS, only this slot's) and the chain file itself.
3. **Pick the controller config.** When the generation pins a config for
   the slot, the loaded `controller.json` must be exactly that config, and
   the entry must name the accepted manifest's digest; an entry bound to
   another manifest is refused. Otherwise the loaded config must be the
   manifest's, as before. Local restart admission and the managed region
   config apply the same rule; the managed region config also validates the
   loaded config with the manifest's role checks. The current-proof check
   then only checks that the proofs are current. The config's interregion
   block may name only files the generation pins as interregion files, in
   the credential directory.
4. **Check issued files by rule.** The slot's TLS leaf, its key and its NATS
   credentials are checked against the generation's issuance rules instead
   of a digest:
   - **Leaf:** it is followed by the generation's controller issuer and
     chains to the bundle. It has the slot's subject, slot name and private
     IP, and a lifetime within `issuedLifetimeHours`.
   - **Credentials:** the account signer issued them for the cell account,
     within the same lifetime.
   - **Before the first renewal:** an issued file that is still
     byte-identical to its manifest pin is accepted.
   - **Without controller issuers** (schema 2) nothing is issued: the issued
     files keep their manifest pins and no issuer is read.
5. **Check the directory.** It must hold exactly these files, owned by the
   service user with mode 0600.

## Installing a generation

A controller installs a verified generation crash-safely, in its credential
directory:

1. **Stage the files.** It writes the generation's files into a
   `.generation-staging` subdirectory and syncs them.
2. **Commit.** It writes the chain into the same subdirectory. The staged
   chain is the commit record.
3. **Install.** It renames every file over its installed name, the chain
   last, and then removes the subdirectory.

Running processes pick up each file as soon as it is renamed into place;
TLS, for example, rechecks its files every 5 seconds.

**Recovery after a crash.** At startup, before restart admission reads the
directory, the controller cleans up a leftover stage:
- A committed stage is installed.
- A stage without its chain, or whose staged files no longer match their
  pins, is dropped.

This happens once per start, so it never races an install the running
controller is writing. Admission therefore always sees either the previous
set or the complete new one.

## Install continuity with a generation

After the manifest's current proofs lapse, a restart needs an owner-signed
install continuity proof. For an install that adopted a generation, the
proof binds the generation instead of the credential files:

- `materialGenerationSha256` is the newest generation's fingerprint.
- `credentialSha256` is `InstallContinuityGenerationDigest` of that
  fingerprint.
- `credentialValidUntil` is that generation's expiry.

So one proof lasts across every leaf and credential renewal under the
generation. Render and sign it from the install's chain:

```sh
ts-orch bootstrap render-founder-continuity --marker accepted-install.json \
  --anchor anchor.json --material-generations gru-generations.json \
  --selector-generation 3 --out continuity.json
ts-orch bootstrap sign-founder-continuity --candidate continuity.json \
  --marker accepted-install.json --anchor anchor.json \
  --material-generations gru-generations.json \
  --root-key root.pub --signing-key root.key --out continuity.signed.json
```

Signing checks three things before it signs:
- the chain is the anchor's deployment;
- the chain is current under the root key;
- the candidate binds the chain's newest generation and does not outlive it.

The controller makes the same binding from its adopted chain, after checking
its credential directory against the generation.

The `oci-region attempt` continuity phase does this by itself when the
attempt directory holds `material-generations.json`. Otherwise it renders
from the attempt's bootstrap material, as before.

Restart admission refuses an adopted generation past its signed expiry, even
when its certificates and JWTs are still valid.
