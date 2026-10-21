# Material generations (TS-568)

A material generation renews a running cell's bootstrap material in place,
so the cell does not have to be re-founded before its material expires. See
[self-healing](self-healing.md), step 3, for the whole renewal plan. This
page covers what a generation is, how the owner signs one and how an
operator installs it on each controller.

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

- **Pins replace the accepted baseline.** A verified generation's pin
  replaces the accepted material reference for the same renewable file.
- **The cell issues its own leaves and user JWTs.** Controller TLS leaves and
  NATS user JWTs come from the controller TLS issuer and the account signer.
  They last at most `issuedLifetimeHours`, which can be up to 90 days.
- **Some secrets never renew.** Founder, response, ticket and route secrets
  do not expire and keep their exact accepted pins.
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
## The v1 contract

Material generations use only schema 1. The signed contract covers the
interregion leaf fabric, role signer, slot configurations and offline-issued
controller credentials. Breaking changes update v1 in place; obsolete identity-scoped chains are replaced only by the root-authorized
[in-place identity re-key transaction](identity-rekey.md).

- **`controllerConfigs`**: one `{slot, acceptanceSha256, sha256, size}` per
  controller slot, in `controllerSlots` order. Each pins the slot's new
  `controller.json`, bound to that slot's signed acceptance digest. The
  config bytes travel beside the chain, not in it. A config may be at most
  16 KiB, the manifest's own limit.
- **`roleSigner`**: required. It is the public key of the cell account's
  role signer ([role identities](nats-fabric.md#role-identities)).
  `cell.jwt` must carry exactly the host scope and the role scope, plus the
  unscoped account signer when the controller issuers are pinned.
- **Controller issuers all or none.** gru-1 and sjc-1 were founded without
  controller issuers. Without them, `accountSigner` is empty,
  `issuedLifetimeHours` is 0, and the cell issues nothing under the
  generation. Every other renewable file is still required.
- **Offline-issued controller credentials (TS-774).** Without online issuers,
  a generation may pin `<slot>.creds` with purpose `controller` and that
  slot. It must pin every slot's credentials and config. Observability is
  always active; its config block may be absent. The JWT must be
  signed by the cell account, match its user seed and slot's fence/inbox,
  grant local `obs.>` subscriptions and the `ts.orch.v1.*.obs.region` and
  `ts.orch.v1.*.obs.decisions` publish patterns. Remote snapshots,
  raw journals and mutations are refused. A later generation must retain
  credential pins, so a restart cannot revert to the founding JWTs.
- **Interregion files**, Vault purpose `interregion`, all or none:
  - `interregion.jwt` and `interregion-ca.pem`;
  - each slot's `interregion-tls-<slot>-cert.pem` and
    `interregion-tls-<slot>-key.pem`, bound to that slot;
  - on a child, its one `leaf-<parent>.creds`.

  `interregion-ca.key` and `child-<cell>.seed` stay offline and can never
  be pinned. Interregion files require the controller configs.

Every generation uses the same v1 shape. The role signer never changes. Once a generation carries controller configs, every later
generation must carry them too, because a controller would otherwise
restart on a config that nothing pins.

The signer verifies these bindings:

- **Controller configs:** each `controller-<slot>.json` in the material
  directory matches its digest and size. Its `nats` block decodes strictly.
  Its mandatory interregion block matches the pinned interregion files.
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

Founding controller credentials already carry the telemetry pattern grants
for every region, so a generation pins each slot's founding `.creds` as
they are. Adding a region needs no new controller credentials. Publish
the exact bytes to Vault, add slot-bound `controller` references to the
candidate. Pin each current config with the path of that slot's `.creds`.
Deploy binary support to every controller before publishing/arming this
generation, then use the installation procedure below one slot at a time.
Issuing or publishing credentials alone does not install them.

Put the files in one directory under their target names, publish them to
Vault, and write the unsigned candidate (`bootstrap.MaterialGeneration` JSON)
with their references. For v1, also put each pinned controller config
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
  - `cell.jwt` grants JetStream and carries the required host and role
    scopes, plus the unscoped account signer when controller issuers are present.
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
   - **Without controller issuers** (v1) nothing is issued: the issued
     files keep their manifest pins and no issuer is read.
5. **Check the directory.** It must hold exactly these files, owned by the
   service user with mode 0600.

## Install a generation

A published chain does nothing until an operator arms a controller slot,
and an armed slot installs only when its controller restarts. Before the
first publish:

- **Grant.** The operator's trusted signer needs `can_install_material`
  in the cell spec. A spec that grants it requires binary level 19, so
  apply it after the release. `status` needs any trusted signer.
- **Vault.** Publish the generation's secrets in the cell's control
  compartment. The controllers' `read secret-bundles` grant covers it.
- **Release.** Every controller runs a known-good release with this
  install. Its `selfupdate prepare` installs.

Then, for gru-1 or sjc-1:

1. **Publish** the chain and every slot's pinned config:

   ```sh
   ts-orch operator material-generation publish --config operator.json \
     --chain gru-generations-1.json \
     --controller-config controller-a=gru-1-files/controller-controller-a.json \
     --controller-config controller-b=gru-1-files/controller-controller-b.json \
     --controller-config controller-c=gru-1-files/controller-controller-c.json
   ```

   The leader refuses a chain that does not verify for the cell under its
   current roots, or that does not extend the stored one (an older chain,
   a fork). It also refuses a config unlike its pin. A new chain clears
   the stored configs and arms.
2. **Wait until every slot is staged.** `ts-orch operator
   material-generation status --config operator.json` prints the stored
   generation and fingerprint, the stored configs, the armed slots, and
   each slot's `staged`, `armed` and `installed` generation with its
   stager's error.
3. **Arm one slot:** `ts-orch operator material-generation arm --config
   operator.json --slot controller-b`. From now on any restart of that
   controller installs the generation; `disarm` undoes it before then.
4. **Verify accepted restart.** Each controller loads its root-owned v1
   accepted identity and verifies the adopted generation against that identity's
   deployment, cell, slot, broker and exact config pins. Initial manifests and
   founder selections are not restart authority. Prepare and arm the exact
   generation before rebooting; a missing, expired or inconsistent generation
   refuses admission.
5. **Reboot it:** `ts-orch node reboot --config operator.json --node <node>
   --wait 30m`.
6. **Check** that `status` shows the slot `installed`. Then do steps 3 to
   6 for the next slot.

**Rollback** is a newer generation that restates the old config and files.
A chain never moves back.

### Staging

Each controller stages the stored chain when it extends the chain the
controller has installed. It works unprivileged, every 30 seconds:

1. It verifies the chain for its manifest under the current roots.
2. It reads from Vault, with its instance principal, every file its slot
   holds: the unbound ones and its own. It never reads another slot's
   file.
3. It checks the files and its slot's config with
   `CheckGenerationFiles`.
4. It writes them owner-only to
   `/var/lib/terrascale-orchestrator-controller/material-generation/`, the
   chain last.
5. While the record arms its slot, it also writes the `armed` marker there,
   holding the newest generation's fingerprint.
6. It reports its status to the leader.

### Install at the next start

The controller cannot write its credential directory or `controller.json`.
`selfupdate prepare` runs as root before every start of the controller
unit, and does the install:

1. **Finish an interrupted install.** A committed stage in the credential
   directory is rolled forward. Any other stage is dropped.
2. **Converge the config.** If the installed generation pins a different
   `controller.json` for the slot, it moves the pending copy into place.
3. **Verify the armed stage again.** It reads the stage beneath the spool,
   following no link out and no FIFO. The stage must have:
   - a chain current under the image's roots and the adopted root chain;
   - an `armed` marker naming the chain's newest generation;
   - a chain that extends the installed one;
   - the slot's config, bound to its accepted manifest;
   - every file the slot holds, by pin and by `CheckGenerationFiles`.

   A refusal is logged as `selfupdate prepare material-generation:
   refused: ...`. The controller then starts on the installed set.
4. **Write the pending config** as
   `/etc/terrascale-orchestrator/.controller.json.generation`, synced.
5. **Adopt the files.** It writes the generation's files, owned by the
   service user with mode 0600, into a `.generation-staging`
   subdirectory, and syncs them. Then it writes the chain there, which is
   the commit record. Then it renames every file over its installed name,
   the chain last.
6. **Install the config.** It renames the pending config over
   `controller.json` (root, 0644) and syncs the directory.

**Recovery after a crash.** Each crash point converges on the next start:

- **Before the commit:** the installed set is unchanged. An armed slot
  installs again. A disarmed slot never uses the pending copy.
- **After the commit:** step 1 completes the install and step 2 moves
  `controller.json` into place.

Restart admission therefore sees either the previous set or the complete
new one.

**At boot,** bootstrap admission runs before the controller and before
`prepare`. It must run the current release too, since the image-baked binary
may refuse the new config's members: `prepare` installs that drop-in
([binary-only self-update](continuous-delivery.md#binary-only-self-update)).

## Accepted restart with a generation

Restart admission uses the explicit v1 accepted identity in
`accepted-install.json`, the baked genesis roots, and the adopted root chain.
It independently verifies the local broker/store and installed config. A
re-keyed install also requires its immutable root-signed identity journal.
It does not reload a bootstrap manifest, ledger or founder continuity proof.

The material generation must belong to the accepted deployment, cell and slot
and bind the broker account and controller config. Renewable leaves and user
credentials must be current under that verified generation; immutable material
keeps exact byte pins. An expired or mismatched generation refuses admission.
See [in-place identity re-key](identity-rekey.md) for the root-authorized
transaction that replaces retired identities without replacing the store.
