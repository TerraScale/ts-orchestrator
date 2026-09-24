# Local ARM64 emulation

The [2026-09-21 receipt](../../../evidence/host-arm64-emulation-local-2026-09-21.json)
records an AArch64 application smoke test and 24 bundled signing/credential
tests executed under QEMU user-mode on an x64 workstation. The application
and test executable were checked as AArch64 ELF files. Guest loader traces
confirm initialization of extracted bundled `libsodium`; its bytes match
the pinned `libsodium` 1.0.22 ARM64 asset and both single-file executables.

This qualifies emulated startup and the selected native-library path. Native
ARM64 execution of the final TerraBase/auth images, complete host startup,
systemd/containerd, cgroups, Instance Principal and OCI networking still need
their own qualification. Guest globalization was invariant and diagnostics
disabled; neither normal globalization nor diagnostic attachment was tested.

The subsequent [credential material receipt](../../../evidence/host-credential-material-local-2026-09-21.json)
adds 67 successful emulated tests from the new source: the same 24 signing/auth
checks plus 43 protected-material tests. These exercise guest OpenSSL through
certificate creation, chain/key/usage validation, certificate/JWT expiry and
manifest/permission checks. The isolated harness retained the same publish
warnings and guest limitations described below. Its exact filter was
`/*/*/(RegionalHostCredentialMaterialTests|NatsUserSignatureTests|NatsAuthenticationFilesTests)/*`,
with `--minimum-expected-tests 67 --maximum-parallel-tests 2`.

The host recovery qualification adds 26 inventory tests under the same ARM64
emulator. Its first run found that the directory `open` flags had x64 values;
ARM64 needs different `O_DIRECTORY` and `O_NOFOLLOW` bits. After correcting the
actual architecture selection, all 26 tests passed. They exercise `statx`,
file/directory ownership checks, durable flush/rename/fsync, interruption,
corruption and exact plan roundtrips. Test helpers such as `mkfifo` and `ln`
run as host utilities; this does not qualify ARM64 workload subprocesses or
systemd/containerd. See the
[recovery receipt](../../../evidence/host-recovery-local-2026-09-21.json) for the exact
source and executable hashes. The repository dependency locks stayed unchanged.

## Reproducing the local checks

Use the receipt's Nix source identity and store paths for QEMU 10.2.4, ARM64
glibc, GCC runtime libraries and OpenSSL. The ARM64 libraries belong to the
emulated guest; do not replace the x64 loader's library environment. These
outputs can be obtained without changing system configuration:

```bash
nice -n 19 nix build --no-link --print-out-paths --max-jobs 0 \
  nixpkgs#qemu-user \
  nixpkgs#legacyPackages.aarch64-linux.glibc.out \
  nixpkgs#legacyPackages.aarch64-linux.stdenv.cc.cc.lib \
  nixpkgs#legacyPackages.aarch64-linux.openssl.out
nice -n 19 dotnet publish src/TerraScale.Orchestrator \
  -c Release -r linux-arm64 --self-contained true --no-restore \
  -p:PublishSingleFile=true -o /tmp/ts-orchestrator-arm64-app
```

Point `arm64_libraries` at the guest outputs' `lib` directories, separated by
colons. Create a private extraction directory and run the published executable
with a finite external timeout:

```bash
nice -n 19 timeout 120 "$qemu_aarch64" -L "$arm64_glibc" \
  -E "LD_LIBRARY_PATH=$arm64_libraries" \
  -E DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1 \
  -E DOTNET_EnableDiagnostics=0 \
  -E "DOTNET_BUNDLE_EXTRACT_BASE_DIR=$private_extract_dir" \
  "$published_application" runtime plan \
  --role terrabase-member --allocation arm64-smoke \
  --digest aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --architecture arm64
```

For the bundled crypto test, use an isolated source snapshot so the repository's
x64 test dependency lock stays unchanged. The initial locked publish rejects
the new RID and single-file SDK dependency with `NU1004`. Restore in that
snapshot only, compare every common resolved dependency version and content
hash with the original locks, then publish:

```bash
nice -n 19 dotnet publish tests/TerraScale.Orchestrator.Tests \
  -c Release -r linux-arm64 --self-contained true \
  -p:RestoreLockedMode=false -p:PublishSingleFile=true \
  -p:IncludeNativeLibrariesForSelfExtract=true \
  -p:WarningsNotAsErrors=IL3000 -o /tmp/ts-orchestrator-arm64-tests
```

The exception to warning promotion is limited to this isolated test harness.
`ProgramStartupTests` references `Assembly.Location`, which is empty in a
single-file app; those subprocess tests are excluded from this qualification.
`IL3000` remains visible in the publish log. `NETSDK1236` also reports exclusion
of the referenced application's runtimeconfig. Neither warning occurred in
the production application publish. The application dependency lock remained
byte-identical; the isolated test lock changed its RID, added the SDK's
`Microsoft.NET.ILLink.Tasks`, and preserved all 50 common dependency versions
and content hashes.

Copy only `TerraScale.Orchestrator.Tests` to an otherwise empty private
directory. Run it under the same guest environment, adding `-E LD_DEBUG=libs`
and a separate private extraction directory. Capture stdout and loader stderr
separately. The exact test arguments are:

```text
--treenode-filter /*/*/(NatsUserSignatureTests|NatsAuthenticationFilesTests)/*
--minimum-expected-tests 24 --maximum-parallel-tests 2
```

Require a successful `linux-arm64` test summary, zero failures/skips, a guest
loader `calling init` entry for the extracted `libsodium.so`, and matching
native/bundle hashes. A successful cross-publish without execution does not
establish these checks.
