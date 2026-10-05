# TS-547 browserless NetBird SSH to gru-1, 2026-10-05

mariogk-dev reaches the gru-1 servers over NetBird SSH with no browser or
human step: `ts-orch netbird ssh` (built from `ebeb19b8`) answers the embedded
IdP device login as `ssh-automation@terrascale.tech`. Server SSH JWT
authentication stays on. No secret, token, setup key or device user code
appears here. Procedure: [operator automation peer](../../deploy/netbird/README.md#operator-automation-peer).

## Manager objects

| Object | Name | ID | How |
| --- | --- | --- | --- |
| Group | `ops-automation` | `db20qtsa0rgg00dt6scg` | `ts-orch netbird sync --apply`; a second `sync` printed `no changes` |
| Policy | `ops-automation-to-gru-servers-ssh`: `ops-automation` → `gru-servers`, `netbird-ssh`, one-way, no authorized-group or user override | `db20qtsa0rgg00dt6se0` | same |
| User | `ssh-automation@terrascale.tech`, role `user`, not a service user, no auto-groups, `active` | `CiRmZjhhNzk3Yy1jMTMwLTQ4ZDAtYTZmNC0zOWU2NDVlOGU2ZTYSBWxvY2Fs` | Invite `db20rh4a0rgg00dt6sug` (1 h), accepted with the Vault password; `POST /api/users` returned 404 (inviter lookup of the account's former creator) |
| Setup key | `mariogk-dev-ops`, one-off, 1 h, auto-group `ops-automation` | `db20sgka0rgg00dt6tcg` | Used once (`state: overused`); the value lived in a `0600` tmpfs file, shredded after enrollment |
| Peer | `mariogk-dev-ops`, `10.200.35.107`, 0.79.0, groups `All`, `ops-automation`, SSH server off, no user | `db20sisa0rgg00dt6th0` | `sudo deploy/netbird/operator-peer.sh --setup-key-file …` |

## Vault (compartment `TerraScale`)

| Secret | OCID suffix | Result |
| --- | --- | --- |
| `gru-1-netbird-ssh-automation-email` | `…xo4gqe5bktkgvemh2u3fziwvavt5h4wnt4n6y37wmwoq` | `ts-orch vault put`: `created: true`, readback equal |
| `gru-1-netbird-ssh-automation-password` | `…n52u2azpqs7ftqlpm6cznp3ulq4n4h7ebewcni7oq4pq` | same; 32 random base64url bytes plus a fixed class suffix, stored before the invite was accepted, local copy shredded |

OCIDs are `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa` followed by
the suffix.

## Peer on mariogk-dev

Image `docker.io/netbirdio/netbird:0.79.0` (`sha256:3014b46532d6aa3f0512220c4dc589f757379ece0279c7bede9a8a7aad1529f0`),
loaded into root's storage from a rootless pull. Its `/usr/local/bin/netbird`
(sha256 `18db53727a3c76a845b52247c7355effe6a3210d41b4b37b0e48fe477e3bbcf9`)
is byte-identical to the binary in the release tarball pinned by
`deploy/image/image-inputs.json` (`d6f8d26f…a71efd`, checked).

`netbird status`: Management and Signal Connected, interface type Kernel,
WireGuard port 51821, SSH Server Disabled, 5 peers (the gru-1 servers).

Host state before and after enrollment (`ip rule`, `ip route`, Tailscale table
52, `nft list tables`, `/etc/resolv.conf` and `/etc/hosts` hashes,
`rp_filter`, `src_valid_mark`) differs only by:

```text
> 10.200.0.0/16 dev wt-tsops proto kernel scope link src 10.200.35.107
> table ip netbird
> table ip6 netbird
```

The container's own `resolv.conf` (a podman per-container copy) points at
NetBird and resolves `gru-1-*.nb.ts.internal`.

## Live proof

```text
$ ts-orch netbird ssh --vault-id "$VAULT" --netbird 'sudo podman exec -i ts-netbird-ops netbird' -- root@gru-1-db-1.nb.ts.internal hostname
SSH authentication required.
https://netbird.terrascale.tech/oauth2/device?user_code=<redacted>
Or visit: https://netbird.terrascale.tech/oauth2/device and enter code: <redacted>
Waiting for authentication...
gru-1-db-1                                 # 6.1 s, exit 0, 2026-10-05 before 20:56Z

$ … -- root@gru-1-ctl-1.nb.ts.internal hostname > out    # fresh login, 2026-10-05T21:34:10Z, exit 0
$ od -c out
0000000   g   r   u   -   1   -   c   t   l   -   1  \n

$ … -- root@gru-1-db-1.nb.ts.internal 'hostname; id -un'   # cached JWT, exit 0
gru-1-db-1
root

$ … -- -L 19464:127.0.0.1:9464 -L 19465:127.0.0.1:9465 root@gru-1-db-1.nb.ts.internal sleep 45 &   # 2026-10-05T21:34:28Z
$ curl http://127.0.0.1:19464/readyz
{"status":"ready","version":"0.1.0","region":"gru-1"}      # HTTP 200; /healthz 200
$ openssl s_client -connect 127.0.0.1:19465
subject=CN=gru-1-db-1
issuer=CN=TerraBase member CA gru-1
```

The runs above used `--netbird 'sudo podman exec -i ts-netbird-ops netbird'`.
Killing a backgrounded forward then left `netbird ssh` and its port running in
the container (`podman exec` relays no signals), so the runbook launches the
client with `sudo env -u SUDO_USER -u SUDO_UID nsenter -t <container PID> -m
/usr/local/bin/netbird` instead. With it, 2026-10-05T21:39Z to 21:41Z:

```text
$ … -- root@gru-1-ctl-2.nb.ts.internal hostname     # gru-1-ctl-2, exit 0
$ … -- root@gru-1-ctl-3.nb.ts.internal hostname     # fresh login, gru-1-ctl-3, exit 0
$ … -- root@gru-1-db-2.nb.ts.internal hostname      # gru-1-db-2, exit 0
$ … -- -L 19464:127.0.0.1:9464 root@gru-1-db-1.nb.ts.internal sleep 600 &
$ curl http://127.0.0.1:19464/readyz                 # {"status":"ready",...}
$ kill -TERM %1                                      # 3 s later: no listener on 19464, no netbird ssh process
```

After review, `operator-peer.sh` pins the image digest and labels its
container with a hash of its create arguments. Its first run at 22:03Z
replaced the unlabeled container (`6a847f270d4a` → `bda64e2d71cf`) with the
same identity (`mariogk-dev-ops`, `10.200.35.107`), a second run left it
unchanged, and `hostname` on gru-1-db-1 still answered `gru-1-db-1`.

With `--no-cache` the 0.79 client fails (`invalid device code or no active
auth flow`) while the daemon holds a cached token: the daemon returns the
cached token and the client then waits on an empty device code. The runbook
says not to pass it.
