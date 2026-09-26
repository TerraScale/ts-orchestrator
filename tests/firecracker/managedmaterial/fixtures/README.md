# TerraBase managed HTTPS client material fixture

This patch began as an isolated candidate for a dirty TerraBase working tree. On 2026-09-26, its ten affected paths were reconciled with the then-current `../terrabase` source and applied there after independent review. That shared worktree integration is not a TerraBase Git commit. Its current-source integration manifest and diff are in `/home/mariogk/Projects/TerraScale/.qualification/ts-orchestrator/20260926-managed-material/current-integration/`, with SHA-256 `b58672958d41008a21121282745b5177317b620fc131aa978adc1a5375d35152` and `4a91c60b0302e0dfc2fa4cce8c5e40974b0748214ec255e88e1a4943ae509479` respectively.

The original source snapshot and per-file pre/post SHA-256 inventories remain in `/home/mariogk/Projects/TerraScale/.qualification/ts-orchestrator/20260926-managed-material/`. Git HEAD alone does not identify that source: the initial inventory pins 4,421 workspace files, including in-progress changes; `inventory-revised.json` pins 4,422 files after adding the previously omitted `proto/terrabase/v1/replication.proto`. `snapshot-supplement.json` records why the build input was added. The original inventory was preserved byte-for-byte. Before replaying the patch, compare every changed file's base hash in `overlay-inventory.json` with the candidate checkout, then use `git apply --check` and apply the patch to a separate copy. Do not use hardlinks for that copy.

The paired CLI options are `--client-managed-material-manifest PATH` and `--client-managed-material-manifest-sha256 LOWER64`. Both are required and accepted only with `--client-config` in signed-v2 distributed HTTPS mode. The second value is the SHA-256 of the exact manifest bytes, carried in the orchestrator's signed desired state. The manifest is bounded to 4 KiB, strict JSON with exactly these fields:

```json
{
  "version": 1,
  "client_config_sha256": "<64 lowercase hex digits>",
  "certificate_chain_sha256": "<64 lowercase hex digits>",
  "private_key_sha256": "<64 lowercase hex digits>",
  "api_key_registry_sha256": "<64 lowercase hex digits>"
}
```

The managed loader accepts only regular root-owned files with the process's effective GID and exact mode `0440`, reached through non-symlink, root-owned directories without group or other write permission. It uses `O_NOFOLLOW`, compares path and opened-FD inode metadata, reads bounded bytes, checks the pinned SHA-256, and parses those same bytes. The manifest is verified once at startup; its four pins are immutable for the process. Client config and credential files are checked for each initial or SIGHUP generation. A rejected reload closes HTTPS admissions and readiness. The ordinary local-v1 file policy remains separate.

The Go launcher must create protected root-owned ancestor directories and the four material files, verify that the config's three absolute paths match the files in its signed desired state, pin the manifest digest in that signed state, and pass the two CLI options. The root-only process regressions in the patch's `distributed_client_process.rs` exercise startup, manifest mismatch before storage creation, valid-but-unpinned SIGHUP replacements, manifest replacement, wrong UID/GID/mode, and final symlink rejection. They skip when the fast suite runs without root; the existing local-v1 process scenarios continue to exercise ordinary `0600` material.

The isolated `nice -n 10 cargo check -j 1 -p tb-server --bin tb-server --locked --offline` and focused `cargo test -j 1 -p tb-server --test fast --no-run --locked --offline` passed with pinned Rust 1.98.1 and installed libclang. Logs are `cargo-check-proto.log` and `fast-no-run.log` in the qualification packet. Both new signed-v2 managed-material process cases and the existing fast local-v1 startup case passed as root in disposable systemd scopes with `MemoryMax=8G`, `TasksMax=256`, and a 120-second timeout; their exact logs are `test-managed-reload-scope.log`, `test-managed-rejection-scope.log`, and `test-local-v1-scope.log`. The tests exercise root:root `0440` files; a dropped workload UID and nonroot workload GID remain for the managed Firecracker runtime qualification.

The integrated source was rebuilt from a later stable snapshot that includes concurrent TerraBase storage fixes. Its full inventory of 4,452 regular files and 13 symlinks has SHA-256 `1e1617e4c4551dad034cf8b292caefcac7452d4c128f853a0f9e4fe92d26c15d`. The host binary and focused fast-suite build passed, and the same three root-scoped process cases passed against that integrated binary. A static x86-64 musl binary was built and stripped for the Noble guest; `runtime-source-identity.json` in `current-integration/storage-refresh-1/` pins its source, build, pre/post-strip hashes, and checks that the delivered ELF has no program interpreter or shared-library dependencies. The native dropped-UID/GID Firecracker run is still pending.
