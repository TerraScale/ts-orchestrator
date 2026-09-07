# Qualification production run admission

`TS_VM_RUN_DECLARATION_FILE` names a protected JSON declaration for the GRU
production stage. Its `version` is `1`; `hosts` contains exactly the initial GRU
host inventory. Each host supplies:

- `hostId` and a positive `generation` admitted for this desired operation.
- `settings`, the complete production `run --config @config` settings. OCI,
  replicas `3`, and a protected `TS_ORCH_PRODUCTION_RUNTIME_FILE` are required.
  Engine-generated database and placement callback settings are preserved;
  conflicting settings are rejected.
- `regional` and, where admitted, `global` connections. Each has `endpoint`,
  `serverName`, `account`, and the existing initialgrant `connection` vocabulary:
  `nkeySeedFile`, `publicNkey`, and TLS file paths and public file digests.
  At least one GRU host must explicitly carry global credentials.
- `files`, mapping guest paths under `/etc/terrascale/` to `{source, sha256}`.
  Sources must be protected regular files; their exact digests are checked before
  they enter the private guest sideband. Initial credential paths cannot be
  overwritten. NKeys and TLS keys must be distinct from initial-only identities.

The producer adds `TS_ORCH_RUN_MATERIAL_FILE`, whose content-addressed filename
commits a canonical inventory of all admitted file digests. Production
configuration loading verifies that inventory and every supplied protected file
before starting services. Changed bytes, symlinks, and unsafe file ancestry fail
admission. Material targets must lie outside the component data volume. The
production systemd unit makes all other paths read-only with
`ProtectSystem=strict`, no capabilities, and no privilege gain; service code
cannot replace checked files before later loaders consume them. Host root
administration remains trusted. This inventory covers supplied files and does
not by itself prove closure of nested references or engine-owned callback files.

The factory retains separate initial and run manifests. The initial launch still
uses `initial-gru-r1`; staged engine callback configuration is checked against the
complete run manifest. The existing authenticated host-control command signs and
applies the run manifest against the exact initial manifest digest and the
admitted desired generation. A live election lease is resolved separately; a
configuration generation never serves as evidence of an election epoch.

This declaration does not turn the initial R1 store into production R3. The
production stage requires the admitted promoted R3 endpoints and broker
configuration, scoped controller and journal permissions, and all ordinary
production dependencies. Ordinary startup retains its real topology and
credential checks. Missing declaration material remains an unpassed
qualification prerequisite. No development provider or credentials are inserted.
