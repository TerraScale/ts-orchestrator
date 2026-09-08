# Qualification production run admission

`TS_VM_RUN_DECLARATION_FILE` names a protected JSON declaration for the
production stage. Its `version` is `1`; `hosts` contains the finite admitted
GRU/SFO/FRA inventory (at most six hosts). Each host supplies:

- `hostId` and a positive `generation` admitted for this desired operation.
- `settings`, the complete production `run --config @config` settings. OCI,
  replicas `3`, and a protected `TS_ORCH_PRODUCTION_RUNTIME_FILE` are required.
  Engine-generated database and placement callback settings are preserved;
  conflicting settings are rejected.
- `regional` and, where admitted, `global` connections. Each has `endpoint`,
  `serverName`, `account`, and the existing initialgrant `connection` vocabulary:
  `nkeySeedFile`, `publicNkey`, and TLS file paths and public file digests.
  At least one GRU host must explicitly carry global credentials; SFO/FRA
  hosts cannot receive that role. Hosts use distinct production identities.
- `files`, mapping guest paths under `/etc/terrascale/` to `{source, sha256}`.
  Sources must be protected regular files; their exact digests are checked before
  they enter the private guest sideband. Initial credential paths cannot be
  overwritten. NKeys and TLS keys must be distinct from initial-only identities.

The factory also contributes the exact orchestrator-owned engine callback and
membership files already staged for the host. Root-only observation credentials
and TerraBase-owned keys are not exposed to the orchestrator. Supported run
setting file references and JSON `File`/`Files`/`_file`/`_files` input references
must resolve within the signed inventory. JSON `host_files` contains inline
future-guest payloads and is not a local input reference. Broker configuration
is a self-contained JSON object.

The producer adds `TS_ORCH_RUN_MATERIAL_FILE`, whose content-addressed filename
commits a canonical inventory of all admitted file digests. Production
configuration loading verifies that inventory and every supplied protected file
before starting services. Changed bytes, symlinks, and unsafe file ancestry fail
admission. Material targets must lie outside the component data volume. The
production systemd unit makes all other paths read-only with
`ProtectSystem=strict`, no capabilities, and no privilege gain; service code
cannot replace checked files before later loaders consume them. Host root
administration remains trusted. Public membership pins are explicitly marked
public in the signed inventory; all other entries retain private-file checks.

The factory retains separate initial and run manifests. Initial GRU uses `initial-gru-r1`; first-candidate preparation retains its
separate typed admission. A fresh ordinary regional member receives a finite
owner bootstrap grant for the complete run manifest without inventing an initial
GRU predecessor. Staged engine callback configuration is checked against the
complete run manifest. The existing authenticated host-control command signs and
applies the run manifest against the exact initial manifest digest and the
admitted desired generation. A live election lease is resolved separately; a
configuration generation never serves as evidence of an election epoch.

Fresh ordinary members also receive independent ts-node authority reader
credentials through a separate four-file root-only sideband. The finite run
manifest pins the canonical public reader configuration with
`TS_ORCH_NODE_AUTHORITY_READER_SHA256`; image preparation checks that pin,
the host identity, credential bindings, and the exact ts-node reader configuration.
These files remain root-owned mode `0400` and are excluded from the
orchestrator inventory because only ts-node consumes them.

This declaration does not turn the initial R1 store into production R3. The
production stage requires the admitted promoted R3 endpoints and broker
configuration, scoped controller and journal permissions, and all ordinary
production dependencies. Ordinary startup retains its real topology and
credential checks. Missing declaration material remains an unpassed
qualification prerequisite. No development provider or credentials are inserted.

Initial random material is persisted under the protected per-run qualification
admission directory before any initial host grant. The record binds the run,
exact guest inventory, and every credential/configuration byte. Restart and
interrupted-publication recovery reuse those bytes. Invalid prior records or
changed inventory fail closed; they never cause a second identity to be issued.
The authority transport and finite-grant issuer share the same immutable record
store while retaining separate record names and validators.
