# TS-739 dashboard live acceptance

Verified from mariogk-dev on 2026-10-07 at 23:03 UTC. Automated acceptance
runs only on delta, beta or mariogk-dev. COS prohibits all agent activity
on mariogk-desktop; any later laptop verification is user-run.

Independent TS-672 acceptance at 23:07 UTC passed 24/24 HTTP200 requests
on delta and 24/24 on beta (both exit0), using the existing wrapper with
`NB='sudo -n netbird-wt0'`. Its isolated CLI was built from exact PR head
`a22b453a`, SHA256
`4789d0b29f372c680c85359a261aa4ff917ba347f83e1608cbb2c44a86f52934`,
and copied only to operator `/tmp/ts672-live` paths. No infrastructure or
controller mutation was made. Together with mariogk-dev this proves
72/72 IP/native-DNS healthz and authenticated topology requests.

After rebasing onto main `ea595ad9`, a mariogk-dev refresh on 2026-10-08
at 16:14 UTC again passed all 24 requests (exit0), using the rebuilt CLI
and the already-connected automation client. No controller mutation or
interactive login was needed.

## Qualified binary and in-place deployment

All six controllers prove main revision
`278e679e069ab2ca0be20d1a05f1c03aa5555e6f`, successful `ci.yml` run 1609
(native run 15144), ARM64 SHA-256
`4ebcd19ded803d774f1bac15a61fdab91aaf646b2bb1dabf4297fd71449f51cf`.
SFO completed `ts-orch release deploy`, generation 2. GRU used signed
`ts-orch selfupdate stage` and `activate --restart`, one controller at a
time with ready/version proofs and healthy three-member quorum between
steps. GRU1 and GRU3 host services were kept running; the regional API
and auth readiness checks remained HTTP 200.

The GRU root-signed dashboard amendment is cell-spec generation 12,
`requires_binary: 18`, using Vault secret `gru-1-orch-dashboard-token`.
SFO's existing generation 8 uses `sfo-1-orch-dashboard-token`.

## Private listeners and HTTP evidence

On every controller, `ss -ltnp` shows port 9463 bound to its NetBird IPv4
and IPv6, alongside the existing loopback listener. No wildcard, public
or OCI VCN listener was present. `ip -br addr show wt0` matches both
addresses, and nft's operator source-set rules mark TCP 9463 traffic
only on `iifname "wt0"`, for IPv4 and IPv6. No firewall, policy or OCI
ingress amendment was needed. TS-672's policy IDs remain
`db3a0fca0rgg00840ig0` (GRU) and `db3a0fca0rgg00840ihg` (SFO).

`scripts/check-dashboard-access.sh` through the tested TS-739 Go CLI
returned exit 0: **24/24 HTTP 200** responses for `/healthz` and
Bearer-authenticated `/topology` by IPv4 and native DNS, all six nodes.
An additional direct IPv6 curl sweep returned exit 0: **12/12 HTTP 200**
responses for those same endpoints. Curl's remote address matched the
intended peer's NetBird inventory. Tokens were read from owner-only
files and passed through curl config stdin.

| Controller | NetBird IPv4 | NetBird IPv6 |
|---|---|---|
| ts-gru-1 | 10.200.87.215 | fd9c:200:2182:65f2:40ea:3113:8dd9:d9ab |
| ts-gru-2 | 10.200.38.135 | fd9c:200:2182:65f2:60da:280d:56ec:a3ce |
| ts-gru-3 | 10.200.168.164 | fd9c:200:2182:65f2:6a3a:fdee:d2ed:27fd |
| ts-sfo-1 | 10.200.112.213 | fd9c:200:2182:65f2:1d12:72a5:647b:8225 |
| ts-sfo-2 | 10.200.122.37 | fd9c:200:2182:65f2:479d:6892:e854:c96d |
| ts-sfo-3 | 10.200.63.195 | fd9c:200:2182:65f2:baca:c386:8667:db19 |

Working IP/DNS topology links and token-fetch commands are in the
[dashboard runbook](../dashboard/README.md#netbird-access). Positive
acceptance was also posted on merged PR313, comment 20640.

## Remaining GRU recovery

At the 2026-10-07 acceptance, TS-632's earlier failed rename left GRU2
with ts-auth running but no
TerraBase desired state. The older `release-g5-controllers` rollback
is frozen, releases are paused, and the node's operation/rollout fences
remain. TS-739 did not release those fences or restart serving hosts.
The dashboard worked on all controllers despite that separate recovery.
This is the historical acceptance state; TS-632 owns subsequent recovery.

## Image failure

Image run 1573 (native run 15041, job 33690) verified its Ubuntu base,
then tried to fetch the deleted Rust TerraBase release
`ci-d2017ca9668a650ec490dff3f79bd51b75bb6466-run-11696` and old Fast run
1012. Both are absent. Production managed controllers still need that
verifier even when their TerraBase workloads use C#. The image retains the
mandatory verifier and its digest, ELF, installation and readback checks.

The recovered 46,840,040-byte verifier has the unchanged admitted SHA256
`33f316ab64ab9d83127a5921ea6b5a92304e78dfd179d3b5c0935977c7e9f33c`.
It was extracted from qualified image
`image-d30f42663eb4c5ba9e5f0917fd8bb5df98dbe309-run-13042-attempt-1`,
whose image SHA256 is
`1f563b6bd90036d54b7124cb6bb50d58a4298618badb39cf9565d852a60ae0d8`.
Its retained image qualification exactly matches the checked-in historical
evidence, SHA256
`e2d065e9b8af97adde5e50abcd0b44d5e2ab449c651fea759d1428ada0152758`,
and binds all original TerraBase source, run and qualification fields.

The verifier and that provenance are retained in ts-orchestrator release
`native-verifier-alpha-33f316ab64ab9d83127a5921ea6b5a92304e78dfd179d3b5c0935977c7e9f33c`.
Release ID 1632 holds binary asset 3613 and provenance asset 3614; both
retained downloads were read back and verified against their pins.
The build verifies both digests and the archived original pin before
installation, so it no longer depends on the deleted TerraBase run. This
archive is outside the CI release-pruning pattern. It retains previously
qualified bytes; it does not assert a new TerraBase qualification.

The named Ubuntu base release `image-base-noble-arm64-20260926` was also
missing during recovery. Its four cached assets were verified against all
existing size/SHA256 pins before retention; base signature verification
remains mandatory. No controller image was replaced during this recovery.
Release ID 1168 holds assets 3615–3618 (QCOW2, checksums, signature and
keyring). All four retained downloads passed size/SHA256 readback; the
checksum signature verified signer
`D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81`.
