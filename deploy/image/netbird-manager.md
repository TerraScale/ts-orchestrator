# Dedicated NetBird manager image

Build the GRU ARM64 manager candidate from a clean checkout and retained binaries
for the same exact source revision. This is a separate recipe from
`build-image.sh`; ordinary controller and worker images keep their existing boot.

```sh
nice -n 19 deploy/image/build-netbird-manager.sh \
  --source FULL_SOURCE_SHA \
  --base /retained/base-image.qcow2 \
  --binary /retained/terrascale-orchestrator-linux-arm64 \
  --qualification /retained/qualification.json \
  --netbird-binary /retained/netbird \
  --out /new/manager-candidate
```

`TS_ORCH_BIN` selects the already retained builder executable. Both that native
builder and the guest executable must match the exact source revision, Go
toolchain and immutable CI binary qualification. No compiler runs in this recipe.
CI invokes the recipe without `nice`.

The builder verifies the existing pinned Ubuntu base, exact ELF architecture,
NetBird 0.80.0 client bytes, source tree, module digests, trust roots and time
configuration. Deployment files are copied to private staging and checked
against their immutable Git blob IDs before use. It installs containerd 2.4.2,
its runc-v2 shim and runc 1.5.2 using the existing archive digests and Go build
metadata checks. A future build downloads only those pinned runtime artifacts;
this source change performs no downloads or builds.

The image enables `netbird-foundation.service`, `containerd.service`, SSH and the
time services. Its foundation unit calls the existing
`ts-orch netbird foundation serve` dispatcher. That dispatcher discovers current
foundation authority and independently admits the exact local manager before
the supervisor touches the store, provisions Vault material or starts components.
The shared unit is embedded by the NET service and installed from the same
source file by this image builder.

The image contains `/usr/local/bin/netbird`, the identical fallback at
`/usr/local/lib/terrascale-orchestrator/netbird-client`,
`/etc/terrascale-orchestrator/netbird-pin.json`, the pinned public `netbird.json`
containing only management origin and GRU region, and the dormant
`netbird.service` unit. Its admitted foundation startup reads the client setup
key from Vault after local management has started. The recipe installs no generic
enrollment unit, controller boot or worker boot. It creates no manager store,
runtime secret configuration, baked setup key, PAT or encryption key.

The server, dashboard and ingress images use NET's shared
`foundation.PinnedComponentImages("arm64")` list. They remain immutable digest
pulls into the admitted foundation's containerd namespace with the `native`
snapshotter. These container layers are not baked into the QCOW2. Each actual
runtime image and process still needs native production qualification.

The output directory contains four files:

1. `terrascale-netbird-manager-arm64.qcow2`
2. `guest-kernel`
3. `image-qualification.json`, using the existing v2 archive convention with
   exact source, binary, kernel and image hashes, manager runtime/component pins
   and installed-file readback hashes
4. `SHA256SUMS`, binding the other three files

The builder closes its writable guest appliance, checks the standalone QCOW2,
and independently reopens it to verify kernel, executable and deployment-file
bytes before publishing the new output directory. The metadata is unsigned
build evidence. It grants no authority to launch, use an existing store, sign a
production receipt, or serve as an ordinary controller image.

The existing signed `region.NetBirdManagerIntent` remains the launch contract.
It binds `role=netbird-manager`, exact image OCID, native ARM64, complete profile
and original `storeOrigin=new|restore`. `NetBirdManagerRecipeDigest` also binds
the final image SHA-256 and `runtime=netbird-containerd`. Independent dedicated
image and retained runtime production proofs must satisfy their original
expiry caps. This recipe cannot replace those proofs or root source-role
qualification. Ordinary `image promote` has its own fixed artifact set and is
not the manager image signing path.

Required source integration: NET's admitted foundation CLI (`c321d75cf` chain),
the supervised containerd service (`1c189052` chain), and the shared
unit/component API successor `ff6230e86`. The manager unit asset is donor
`bd35cf519`. Integrators must retain the current NET successors rather than
overwrite them with these historical prerequisite tips.

Source selfchecks cover the dedicated boot path, deferred client enrollment,
fallback identity/modes, same-size artifact substitution, symlink rejection,
changed deployment source, and actual archive image/kernel checksums. Compilation,
selfcheck execution, QCOW2 construction and native acceptance require separate
QA authorization. None has run for this recipe.
