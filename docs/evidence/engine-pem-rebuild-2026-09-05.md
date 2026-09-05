# Engine PEM decoder comparison

The previously supplied static engine had SHA-256
`300d71b2c6e446555aa62eb03c04a07937a83503da1c4393da39074a19444aa7`.
A direct execution with the rendered production configuration and protected
diagnostic TLS files returned exit 1:

```text
Error: ProductionStartup(Transport("a TLS material file is unsafe or invalid"))
```

The direct configuration relocated database and TLS paths into an isolated
directory. It retained the guest QUIC address. File-system tracing showed that
the process opened the certificate successfully with `O_NOFOLLOW`; both metadata
observations reported the same regular-file size. It rejected that certificate
before opening the private key. No TLS contents were recorded in the trace.

The adjacent producer already contained commit
`926119ffc58f47b5464b921b8882a91d87a2f65e`, which replaces a hand-written PEM
base64 decoder and tests real certificates with every DER-length remainder.
The old decoder rejected valid padded certificate bodies. The supplied binary
predated this fix.

An isolated detached worktree at that commit was built with Rust 1.97.1:

```sh
cargo build --locked --release --target x86_64-unknown-linux-musl -p terrabase-server --bin terrabase-server
```

The target C compiler and Cargo linker were explicitly set to the Nix
`x86_64-unknown-linux-musl-gcc-wrapper-15.2.0` compiler at
`/nix/store/13zs1pv7x5vrzx6i425iwics4spq9a90-x86_64-unknown-linux-musl-gcc-wrapper-15.2.0/bin/x86_64-unknown-linux-musl-gcc`.
The build completed successfully. `file` identified the result as an x86-64
static PIE executable. Its SHA-256 is
`038f78bbc55e1205d117aadabe2ba243c08d26fcbdc2c2324c77d6a17d811464`.
The parser source hash still matches the orchestrator's pinned marker.

The replacement binary, against the same configuration and TLS files, returned
exit 1 at the later transport bind step:

```text
Error: ProductionStartup(Transport("QUIC bind: Bind"))
```

The guest IP does not exist on the host. This comparison establishes that the
replacement passed the TLS-material loading step. It does not establish guest
startup, membership, readiness, or a published source-to-binary attestation.

The local replacement artifact is retained at
`/var/lib/terrascale-qualification/engine-builds/038f78bbc55e1205d117aadabe2ba243c08d26fcbdc2c2324c77d6a17d811464/terrabase-server`.
It is a diagnostic build, not a production release.

Commit `ccd9201e` adds the fixed `tls-material-rejected` guest diagnostic
category. It retains no raw TLS or journal text. Verification passed:

- [Portable gate](tls-diagnostic-portable-2026-09-05.txt)
- [Tagged diagnostic and runtime race tests](tls-diagnostic-tagged-2026-09-05.txt)

## Configured Firecracker result

The full VM attempt ran from 21:39:53Z to 21:42:57Z on September 5 using a
fresh six-member diagnostic declaration bound to the replacement digest.
The [machine report](vm-test-pem-fixed-engine-2026-09-05.json) and
[sanitized service diagnostics](vm-test-pem-fixed-engine-2026-09-05.txt)
retain the result and all three component digests.

The first GRU guest booted. ts-node and orchestrator were active/running.
TerraBase exited with status 1 and reported `membership-source-missing`.
In the exact producer source built here, that error occurs after production
catalog construction, TLS loading, QUIC endpoint binding and member-runtime
construction. It then drains the member because no durable orchestrator
membership source is configured. This guest result clears the prior TLS
startup failure; it does not establish serving membership or readiness.

No guest became ready and no scenario ran. Automatic cleanup completed with
all recorded provider paths absent and fixture listeners unreachable. Explicit
`make vm-clean` subsequently exited 0. Both temporary diagnostic credential
directories were removed after use.

The next engine integration requirement is the durable membership source.
Static declaration claims and host liveness cannot substitute for that source.
The ordinary orchestrator production adapter composition, SFO/FRA admission,
full R3 recovery, provider gates and operational qualification remain open.
