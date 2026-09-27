# Historical TerraBase member-status V2 fixture

These files reproduce the Rust test binary used by the member-status Firecracker qualification. They apply to one accepted historical TerraBase source snapshot; they do not apply to the newer TerraBase source currently used elsewhere. The source is not vendored here, and the recipe builds in a separate temporary overlay so the supplied TerraBase checkout stays unchanged.

## Pinned source and overlay

Use TerraBase commit `12850214606652f036e9fde000695fe5743b374b`. Before applying any fixture, the source helper
`crates/tb-server/tests/support/server/member_control_managed.rs` must have SHA-256
`a803c675e4ed16411457d74c7be351029953f29de7a72f24d0d454e0a63c4117`.

The complete original source manifest lists 119 files and has SHA-256
`cce6767ee11aabbe2e536df2cb4c98fea3d32899ca231da74a07cc4b30252fdf`.
The overlaid manifest lists 120 files and has SHA-256
`a469bd78ee3835836c0ec37d56e25e9591a6dc49c53863cc7209d833b3f11d49`.
The rebuild recipe below regenerates both manifests and checks these digests.

The overlay changes exactly three files:

| TerraBase path | Original SHA-256 | Overlay SHA-256 |
| --- | --- | --- |
| `crates/tb-server/Cargo.toml` | `a3fc59b7ec76c52e5504ba840ae69ead21e72b50c2b48aeefb266c0eb43eaf11` | `f050490484ee0057b3c86aec57cf5cb7111371f8834234cd34387c1ab141bbd5` |
| `crates/tb-server/tests/member_control_managed.rs` | added | `0cf2a1cf354f84f4c76960494aa648cdbc41597708046333d179ccde4b44456e` |
| `crates/tb-server/tests/support/server/member_control_managed.rs` | `a803c675e4ed16411457d74c7be351029953f29de7a72f24d0d454e0a63c4117` | `83ea194d3e2c140eedd7489ad88ea628f02fb6ca6dc68dc37caa5948c0d97671` |

`registration.patch` registers the focused test target and adds its two-line wrapper. Its SHA-256 is
`ddfd15c06777872cca5d9035a057c8b2f8ac87184ff517f776ad1bd085415768`; the standalone
`registration-wrapper.rs` is the exact wrapper content and has SHA-256
`0cf2a1cf354f84f4c76960494aa648cdbc41597708046333d179ccde4b44456e`.
`authority-v2.patch` is then applied to the baseline helper; its SHA-256 is
`da5e1b0d6bb20975fd488b261ed31bc847ff551e4bc620294a7ed62c47d9d4b6`.
It changes the fixture to encode the V2 authority payload with the schema binding.

## Rebuild the binary

Run these commands from the orchestrator repository root. Set `TB_REPO` to an existing TerraBase Git checkout that contains the pinned commit. The accepted Makefile defaults to the static `x86_64-unknown-linux-musl` target and two build jobs; Rust and Cargo are 1.98.1, with `x86_64-unknown-linux-musl-gcc` available.

```sh
set -eu

fixtures="$PWD/tests/firecracker/memberstatus/fixtures"
TB_REPO=/path/to/terrabase
TB_COMMIT=12850214606652f036e9fde000695fe5743b374b
work=$(mktemp -d)
source="$work/source"
overlay="$work/overlay"
CARGO_TARGET_DIR="$work/cargo-target"

test "$(git -C "$TB_REPO" rev-parse "$TB_COMMIT^{commit}")" = "$TB_COMMIT"
mkdir -p "$source" "$overlay"
git -C "$TB_REPO" archive "$TB_COMMIT" | tar -x -C "$source"

test "$(sha256sum "$source/crates/tb-server/tests/support/server/member_control_managed.rs" | cut -d ' ' -f 1)" = \
  a803c675e4ed16411457d74c7be351029953f29de7a72f24d0d454e0a63c4117
(cd "$source" && find . -type f -printf '%P\0' | sort -z | xargs -0 sha256sum) > "$work/source.sha256"
test "$(sha256sum "$work/source.sha256" | cut -d ' ' -f 1)" = \
  cce6767ee11aabbe2e536df2cb4c98fea3d32899ca231da74a07cc4b30252fdf

cp -a "$source/." "$overlay/"
(cd "$overlay" && git apply --check "$fixtures/registration.patch" && git apply "$fixtures/registration.patch")
cmp "$fixtures/registration-wrapper.rs" "$overlay/crates/tb-server/tests/member_control_managed.rs"
(cd "$overlay" && git apply --check "$fixtures/authority-v2.patch" && git apply "$fixtures/authority-v2.patch")
(cd "$overlay" && find . -type f -printf '%P\0' | sort -z | xargs -0 sha256sum) > "$work/overlay.sha256"
test "$(sha256sum "$work/overlay.sha256" | cut -d ' ' -f 1)" = \
  a469bd78ee3835836c0ec37d56e25e9591a6dc49c53863cc7209d833b3f11d49

export CARGO_TARGET_DIR CARGO_BUILD_JOBS=2 RUSTUP_BIN="$HOME/.cargo/bin"
make -C "$overlay" test-build CARGO_ARGS="-p tb-server" CARGO_TEST_TARGETS="--test member_control_managed"
test_bin=$(find "$CARGO_TARGET_DIR/x86_64-unknown-linux-musl/debug/deps" -maxdepth 1 \
  -type f -name 'member_control_managed-*' -perm -111 -print -quit)
"$test_bin" --list
```

The accepted build produced a static x86-64 musl executable with SHA-256
`e7aa51a0ae3f57836b9b7418338c234197d650ab298b7e2e1a013e8b11da92f6`.
Its list output was exactly:

```text
member_control_managed::managed_member_status_cross_language_process_boundary: test

1 test, 0 benchmarks
```

`make test-build` passes `--no-run`; `--list` lists the test without executing its body. The test binary is used by the guest qualification. Do not use this artifact build or list output alone as evidence of a complete VM pass. In the accepted V2 `run-02`, the Rust test reported pass, but the overall driver failed while waiting for shutdown.
