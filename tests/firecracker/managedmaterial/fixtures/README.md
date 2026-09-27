# TerraBase managed HTTPS client material fixture

This patch began as an isolated candidate for a dirty TerraBase working tree. On 2026-09-26, its ten affected paths were reconciled with the then-current `../terrabase` source and applied there after independent review. That shared worktree integration is not a TerraBase Git commit.

Git HEAD alone does not identify the original source: it included in-progress workspace changes. Before replaying the patch, use `git apply --check` against the candidate checkout and apply the patch to a separate copy. Do not use hardlinks for that copy.

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

The isolated `nice -n 10 cargo check -j 1 -p tb-server --bin tb-server --locked --offline` and focused `cargo test -j 1 -p tb-server --test fast --no-run --locked --offline` passed with pinned Rust 1.98.1 and installed libclang. Both new signed-v2 managed-material process cases and the existing fast local-v1 startup case passed as root in disposable systemd scopes with `MemoryMax=8G`, `TasksMax=256`, and a 120-second timeout. The tests exercise root:root `0440` files; a dropped workload UID and nonroot workload GID remain for the managed Firecracker runtime qualification.

The integrated source was rebuilt from a later stable snapshot that includes concurrent TerraBase storage fixes. The host binary and focused fast-suite build passed, and the same three root-scoped process cases passed against that integrated binary. A static x86-64 musl binary was built and stripped for the Noble guest; the delivered ELF has no program interpreter or shared-library dependencies. The native dropped-UID/GID Firecracker run is still pending.
