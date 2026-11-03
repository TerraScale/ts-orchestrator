# Container runtime evaluation: keep containers, or switch to NixOS or another system?

Date: 2026-11-03. Question from the user: "Would we benefit from throwing all
Docker and containers away and just using NixOS or any other system?"

**Answer: no full switch.** Keep containerd and digest-pinned OCI images as the
production runtime. Make one partial change: stop running builds and tests
inside Docker in CI, which is where Docker costs real time today.

DECISION: keep containerd + OCI images at runtime; remove Docker from CI test
and publish paths (partial). Reason: in measured releases, image pulls take
1.8-6.4 s of a 33-49 s regional release. The 30 s bake and app startup make up
the rest, and NixOS would change neither. A switch would mean rewriting the
14k-line SwarmKit/containerd executor and reinstalling serving hosts, with no
gain in isolation. The time Docker costs is in CI: Docker-based test steps take
10-20 min, and the NuGet restore cache blob is 1.75 GB.

## 1. Where containers are used today

| Area | What runs | Evidence |
| --- | --- | --- |
| Production runtime | `ts-orch` runs under systemd with embedded SwarmKit (forked in `third_party/swarmkit`) and a containerd executor: digest pull, runc, read-only rootfs, no capabilities, default seccomp, a PID limit of 256 and host networking. | `internal/swarmruntime/controller.go:210,257`, about 14k non-test lines in `internal/swarmruntime` |
| Host runtime install | containerd 2.4.2 and runc 1.5.2 are installed from checksum-pinned upstream releases into `/usr/local` on stock Ubuntu 24.04. | `deploy/m1/host-runtime.sh`, `deploy/m1/install.sh` |
| Hosts | One A1 (arm64) host each in gru, sjc and fra, running stock Ubuntu 24.04, not a custom image. | `deploy/m1/regions.json`, `REFACTOR.md` |
| Legacy host image | A qcow2 image built on the Ubuntu noble arm64 cloud image (containerd, NetBird and units), imported as an OCI custom image. Marked "WORKS, heavy" and not needed for M1. | `deploy/image/`, `internal/image`, `internal/ociregion/imageimport` |
| App artifacts | `ghcr.io/terrascale/{terrabase,ts-auth,ts-dashboard,app-canary}@sha256`, plus third-party `docker.io/netbirdio/netbird-server`. | `deploy/m1/services/*.json` |
| Image build | `docker buildx` in GitHub Actions builds amd64 and arm64 and pushes to GHCR. The release step deploys the arm64 child digest. | terrascale `.github/workflows/ci.yml`, ts-dashboard `images-ghcr.yml`, this repo's `app-canary.yml` |
| Image contents | TerraBase and ts-auth are self-contained .NET apphosts on `runtime-deps:11.0-resolute-chiseled`; ts-dashboard is on `aspnet:10.0-noble-chiseled` and copies a prebuilt publish output. | terrascale `Dockerfile`, ts-dashboard `scripts/ci/Dockerfile.runtime` |
| CI tests | Auth Fast and every Slow area run as `docker build --target test-*` stages. libs and TerraBase Fast already run natively. Turso and router-parser native libraries are built in Rust Dockerfiles. | terrascale `Dockerfile`, `ci.yml`, `scripts/vendor/` |
| Tests in this repo | Real-containerd integration tests (`-containerd-socket`). Everything else uses fakes. | `internal/swarmruntime/*_integration_test.go` |
| Local dev | No compose files, devcontainers or Testcontainers. Podman is used only for manual import-adapter acceptance recipes and as a fallback for the Turso build. | terrascale `tools/import-adapters/*/acceptance` |
| Tenant isolation | Dedicated tenants get dedicated OCI hosts, a per-tenant NSG and a per-tenant member CA. Containers are not the tenant boundary. Functions use Wasm. | `docs/dedicated-tenants.md`, `docs/functions.md` |
| Firecracker | Used only in local four-VM qualification labs, never in production. | `internal/qualification/firecracker` |
| Nix | delta, mariogk-dev and beta run NixOS (the homelab fleet modules). The only Nix files in the repos are two pins under `ts-js/scripts/ci`. There is no flake. | `docs/netbird-m1.md`, `ts-js/scripts/ci/*.nix` |

## 2. What the measurements show

Numbers are from production releases (`docs/benchmarks/deploy-timings-20261028.md`):

| Step | Measured | Would a container-free runtime change it? |
| --- | --- | --- |
| Image pull | 1.8-2.9 s (canary, dashboard), 5.3-6.4 s (ts-auth) | Slightly. A Nix closure or tarball copy moves about the same bytes. Estimate: saves 0-3 s. |
| Ready after submit | 0.7-4.8 s on gru; 10-15 s for the dashboard on 2-CPU sjc and fra hosts; 6.6-11.8 s for ts-auth | No. This is .NET startup on small hosts. runc start overhead is estimated at under 0.2 s (not measured here). |
| Bake | 30 s | No. This is rollout policy. |
| Regional total | 33-49 s, so the 60 s target is met | Estimate: at most about 5% faster. |
| Orchestrator self-update | 7.5-20.2 s | No. It is already a plain binary under systemd. |
| Rollback leg | 30.6-31.0 s, with ready in 0.2-0.4 s | No. A digest swap is already about as fast as a Nix generation switch. |

The 60 s regional target is already met. The 10 s warm-deploy target is only
partly met, because of CPU-bound startup on 2-CPU hosts. Neither gap is caused
by containers.

Docker does cost time in CI (terrascale `benchmark/bench/2026-10-24-ci-executors.md`,
whose runs are confounded and were not taken on controlled hardware):

- The production image step took 1107 s on main.
- Docker test steps on PRs took 968-1195 s for TerraBase and 615-1048 s for auth.
- The NuGet restore cache blob in Docker is 1.75 GB and takes 76-504 s to restore from the GHA cache. A native restore takes 16-20 s.
- GHA cache usage reached 10.37 GB against the 10 GiB limit, so only the `base` stage is cached now.

## 3. Options compared with today

Ratings: `=` same as today, `+` better, `-` worse. "Est." marks estimates.

| Criterion | A. Today: containerd + OCI | B. Partial: today's runtime, no Docker in CI | C. NixOS hosts with Nix closures and systemd, no containers | D. Plain systemd units with tarballs on any distro | E. Firecracker microVMs | F. bootc/OSTree host images (still runs containers) | G. NixOS host OS that still runs containerd |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Region deploy (≤60 s) | Met, 33-49 s | `=` | Est. `=` (−0-3 s) | Est. `=` | Est. `-` (+boot about 0.2-1 s, plus rootfs build) | `=` for apps | `=` |
| Warm app deploy (≤10 s) | Partly met (CPU bound) | `=` | `=` | `=` | `-` | `=` | `=` |
| Artifact size and Arm builds | Chiseled multi-arch images, arm64 digest deployed | `+`: native publish, image is copy-only | `-`: needs `buildDotnetModule` with NuGet lock packaging, arm64 Nix builders and a binary cache (Tigris/S3 or paid Cachix) | `=`: self-contained tarball | `-`: needs rootfs and kernel images per arch | `-`: OS image per arch per change | `=` |
| Rollback | Digest swap, 0.2-0.4 s ready | `=` | `=` for apps, `+` for host OS (generations) | `=` | `=` | `+` for host OS | `+` for host OS |
| Tenant DB isolation | Dedicated OCI VM per member, NSG, member CA; runc hardening is defense in depth | `=` | `=`: systemd hardening is about equal to runc hardening | `=` | `+` only for untrusted code, which TerraBase is not | `=` | `=` |
| OCI and A1 support | Stock Ubuntu platform image, nothing to import | `=` | `-`: custom NixOS image import for A1 (UEFI, paravirtualized), still to be qualified, or kexec reinstall | `=` | `-`: no KVM on A1 VM shapes, so it needs bare-metal A1 (new paid capacity) | `-`: custom image import | `-`: same as C |
| Third-party images (NetBird server, future tenant images) | Native | `=` | `-`: repackage from nixpkgs or keep a container path anyway | `-`: same as C | `-`: convert to rootfs | `=` | `=` |
| Operational effort | `host-runtime.sh` plus apt on Ubuntu | `=` | `-`: Nix expertise needed for every service team (.NET, Node) | `=`/`-`: back to the native driver that SwarmKit replaced | `-`: networking, jailer, images | `-` | `+`/`-`: declarative host, but a custom image pipeline |
| Migration size | None | Small: about 2-4 days (est.) | Large: rewrite the executor (about 14k lines) or drop SwarmKit (its tasks are container-shaped), Nix packaging for 3 .NET/Node services, new image pipeline, host reinstall. Est. 6-10 weeks | Medium-large: new executor plus SwarmKit decoupling. Est. 3-5 weeks | Large, plus hardware | Medium: rebuild the qcow2 pipeline already judged too heavy | Medium: image plus reinstall. Est. 2-3 weeks |
| Risk to serving cells | None | None (CI only) | High: hosts must be reinstalled, and TerraBase data sits on the 100 GB boot volume (`/var/lib/ts-data`), so a reinstall needs a data move. Never re-found a serving cell. | Medium | High | High (reinstall) | High (reinstall) |
| CI and test impact | Docker builds 10-20 min per test step; cache near the 10 GiB limit | `+`: native restore 16-20 s against 76-504 s; frees the GHA cache | `-`: Nix builds in Actions need a cache, and the first builds are slow | `=` | `-` | `-` | `=` |

## 4. Why not a full switch

1. **No time to win at runtime.** Container mechanics (pull and runc start) take
   about 2-6 s of each regional release. The rest is bake and app startup,
   which NixOS leaves unchanged.
2. **Isolation already lives at the VM boundary.** Tenant DBs run on dedicated
   OCI hosts. runc and systemd sandboxing offer about the same defense in depth.
   Stronger sandboxing only matters if TerraScale starts running untrusted
   tenant code (option E), and that needs bare-metal A1 capacity.
3. **The switch would reverse a recent decision.** SwarmKit plus containerd
   replaced the native and podman drivers (`docs/generic-workloads.md`,
   `REFACTOR.md`), and the M1 milestone shipped on it. Options C and D would
   rebuild the superseded path.
4. **Serving hosts would have to be reinstalled.** OCI has no stock NixOS image
   for A1, so every serving host would need a custom image or a kexec reinstall,
   plus a move of the TerraBase data on its boot volume.
5. **Third-party software ships as images** (the NetBird server today, tenant
   images in `docs/generic-workloads.md`). Some container path would stay anyway.

## 5. Plan for the partial change (B)

All of it is in CI. Runtime and hosts are unchanged, so serving cells carry no risk.

| Step | Repo | Est. effort |
| --- | --- | --- |
| 1. Run Auth Fast and the Slow areas natively (`dotnet test` on the runner, as libs and TerraBase Fast already do). Delete the `test-*` Docker stages and the 1.75 GB restore cache blob. | terrascale | 1-2 days |
| 2. Publish TerraBase and ts-auth natively per architecture (`ubuntu-24.04-arm` for arm64, the same runner `native-build` already uses). Then build the image as a copy-only `Dockerfile.runtime` over the chiseled base, as ts-dashboard does. Keep multi-arch GHCR digests and the arm64 release step unchanged. | terrascale | 1-2 days |
| 3. Measure before and after: the main publish step (1107 s today) and PR wall time, with 3 measured repeats in `benchmark/bench/`. | terrascale | 0.5 day |
| 4. Optional: build the Turso and router-parser `.so` files natively on per-arch runners in place of the Rust Dockerfiles. Keep the reproducibility `cmp`. | terrascale | 0.5-1 day |

Expected result: tens of minutes saved per CI run (estimated from the CI
measurements above, not proven), a GHA cache back under its limit, and no change
to the runtime contract (`image@sha256`, containerd, SwarmKit).

## 6. When to revisit

- **Untrusted tenant code** (user images or functions beyond Wasm): evaluate
  Kata/Firecracker or gVisor as a containerd runtime class. This keeps the
  OCI-image contract. It needs bare-metal or nested-virtualization capacity,
  which means asking about paid capacity first.
- **Host OS drift becomes a measured problem** (packages, kernel, or
  `host-runtime.sh` diverging between regions): pilot option G (NixOS that still
  runs containerd) on a new, not-yet-serving region host. Never reinstall a
  serving host for it.
- **A1 capacity forces a different shape or architecture**
  (`docs/deployment-simplification-review.md` §7): multi-arch images already
  cover this. Nix would add nothing here.

## Limits of this evaluation

- No new benchmarks were run. Runtime numbers come from the 2026-10-28
  production release logs, and CI numbers from terrascale's confounded
  2026-10-24 executor comparison.
- Compressed image sizes could not be read: the GHCR package API needs
  `read:packages`, which the local `gh` token lacks.
- Nix packaging effort and the runc start overhead are estimates. OCI A1
  support for a custom NixOS image was not qualified.
