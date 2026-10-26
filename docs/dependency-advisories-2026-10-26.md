# Dependency qualification, 2026-10-26

The executable graph is selected by the root module and its local SwarmKit,
NATS and OCI replacements. The independent e2e module and all three replacement
modules also receive package/test scans. Historical manifests under `docs/`
remain immutable evidence and do not select current executable dependencies.

Run `bash scripts/ci/audit-dependencies.sh source` using Go 1.27.3. It runs
govulncheck 1.9.0 on all five package/test graphs, including locally patched
sources. An imported vulnerable package, scanner error or invalid graph fails
the existing test job. No advisory is ignored. The existing Go build/module
caches retain the scanner compilation and downloads; only one race shard scans.
The scanner binary is checksum-verified before execution and self-audited against
the current feed, including its compiler and full module graph.
Main repeats the source check before qualification and scans both actual release
binaries before publishing their bytes. Symbol tables are retained (`-w`, rather
than `-s -w`) because stripped binaries cannot reliably establish package
absence. The amd64 baseline comparison adds about 11 MB to the executable.

## Manifest and selected-version findings

The standalone SwarmKit manifest had stale indirect WebSocket and OpenTelemetry
bounds even though the application selected patched versions. Refreshing its
dependency metadata removes obsolete entries and explicitly selects patched
WebSocket 1.5.3, OTLP exporters 1.46.0 and Goldmark 1.8.6. Root selections remain
at least as new. Root also pins patched ebpf 0.22.0 and xz 0.5.17. NATS and OCI
standalone graphs now select patched x/mod 0.41.0 and x/net 0.61.0, with compatible
x/crypto 0.58.0 and x/sys 0.49.0. These changes do not replace local runtime code.

Full `go list -m -json all` graphs include upstream requirements whose packages
are absent from the build. They are retained in the audit evidence rather than
treated as a zero-match module scan. The affected unused constraints are AWS
v1.37.0, Docker distribution v2.8.3+incompatible, Prometheus
v2.5.0+incompatible and monolithic etcd/v3 v3.5.5. OpenPGP is the
maintenance record in x/crypto v0.58.0 (standalone SwarmKit: v0.57.0).
The exact selected-module reports, five test-inclusive package inventories and
complete advisory records are retained in the PR/ticket evidence index.


| Record | Disposition and verification |
| --- | --- |
| GO-2026-5932, x/crypto OpenPGP | Unmaintained package family, no fixed version. All five package/test graphs and both release binary symbol scans must show no affected package. Other x/crypto packages remain maintained dependencies. |
| GO-2022-0635 / GO-2022-0646, aws-sdk-go v1 | Affected S3 encryption packages are absent from all five package/test graphs. No AWS SDK is embedded in the release executable. |
| GO-2026-5264 / GHSA-8rm2-7qqf-34qm, old Prometheus module | Remote-read server packages are absent. The application uses separate maintained metrics/client modules. Replacing the old incompatible-major constraint with the newer v0 module forces unrelated MVS downgrades, so its unused constraint is documented. |
| etcd/v3 3.5.5: GO-2024-2528, -2529, -2530; GO-2026-4806, -4808; GHSA-6vch-q96h-7gc3, -q8m4-xhhv-38mg, -rfx7-8w68-q57q, -x35m-3gp4-4fh5, -xg4h-6gfc-h4m8 | The monolithic module's packages are absent; actual etcd packages come from the separate patched api/client/pkg/server 3.6.14 modules. |
| GHSA-685w-q87j-wqw3, docker/distribution v2 | Affected registry code is absent; the application uses separate maintained distribution/reference and containerd modules. |

These are package-absence dispositions, not advisory suppressions or claims
that every transitive module constraint has zero advisory matches. The stricter
package gate rejects a future import of an affected package. A control module
importing vulnerable x/net/html 0.48.0 failed with five package findings; a
missing-import control also failed. Scanner diagnostics never count as clean.

## Replacement provenance

Runtime source provenance remains in the existing records:

- SwarmKit 2.1.2: `docs/evidence/core-runtime-contract.md`, upstream
  `12ce3490ef26cbca6ef9b243cb013fffbfe6a6cb`.
- NATS 2.15.0: `third_party/nats-server/README.terrascale.md`, upstream
  `eb763679aa3c24a40dcd3012aa046ad1996d851c` and recorded local runtime patches.
- OCI 65.126.0: `docs/patches/oci-sdk-v65.126.0-context/provenance.json`, upstream
  `d48ee53a6d31d110dbe1316cf8762a191b916747` and recorded context patches.

This change updates their dependency metadata, not those archived provenance
snapshots. Required CI and exact merged binary evidence remain necessary before
advancement. This qualification does not establish a production exploit or
change the deployment ownership boundary.
