# Dependency qualification for NetBird dashboard deployment

The dependency audit for PR #193, run 40595275419, rejected the existing
`golang.org/x/net` version because GO-2026-6860 and GO-2026-6866 are fixed in
v0.62.0. The root module and each current vendored module now select v0.62.0.
SwarmKit’s required transitive Go modules moved to the versions selected by
that upgrade. No vendored runtime or task source changed.

The upstream commits and local runtime patches remain the same. These source
hashes cover the retained files plus the reviewed manifest/checksum changes:

| Replacement directory | Source SHA-256 |
|---|---|
| `third_party/swarmkit` | `c871ea3987e708cadd286421dc90be32db60357a63b88e52cfa2dcf51a0cd1b1` |
| `third_party/nats-server` | `0b6bb5e0fd6669ddda19c22fe8e209f5399b81fe227edc8b7145a0d7b8cd3027` |
| `third_party/oci-go-sdk` | `99438f31705273358cd2be7940f800de731b3275c60e7ec608169bb08bca653b` |

CI audits each module’s package/test graph and both release binaries; no
advisory exception or audit bypass was added. Local tests were not run.
