# NixOS node host

Every production host runs NixOS from `flake.nix`, the same on every server;
an image is replaced, never patched. A NixOS host has `/etc/NIXOS`.

## Who owns what

Nix owns (`nix/modules/node.nix`, `nix/modules/oci.nix`):

- kernel and base OS, nixpkgs `nixos-26.05` pinned by `flake.lock`;
- containerd 2.4.2, runc 1.5.2 and the NetBird client 0.81.3 from the upstream
  archives and SHA-256 sums the Ubuntu path pins (`nix/packages/`);
- `containerd.service` (started only by ts-orch.service), `netbird.service`,
  chrony against 169.254.169.254, nftables with an empty ruleset, no firewall;
- user `terrascale` (wheel, passwordless sudo); sshd reads only
  `/var/lib/terrascale-ssh/%u`, written from IMDSv2 `ssh_authorized_keys` at
  every boot; no root login, no passwords, no `ubuntu` user, no vsock SSH;
- nixpkgs `oci-common.nix` (OCI kernel arguments, serial console, root grown
  to the boot volume) and `/dev/oracleoci/oraclevd*` volume names by LUN;
- the boot chain:
  1. `ts-node-init.service`: oneshot after `network-online.target`, runs the
     baked release's `terrascale-orchestrator node-init`. On failure it runs
     again every 10 s with no start limit (`RestartMode=direct`), because a
     pool host boots before its data volume is bound. Its start job stays
     queued until it succeeds, so `multi-user.target` waits for it.
  2. `ts-orch-units.service`: oneshot after and requiring `ts-node-init`; its
     queued start job runs once node-init succeeds:
     `/usr/local/bin/terrascale-orchestrator host-units --dir /run/systemd/system --start`.

ts-orch owns `/usr/local/bin/terrascale-orchestrator` and the
`/usr/local/bin/ts-orch` symlink (Nix only creates `/usr/local/bin`),
`/var/lib/ts-orch`, `/var/lib/ts-data` (node-init mounts the data volume at
every boot; the image has no `fileSystems` entry for it),
`/etc/terrascale-orchestrator` and every unit it writes, under
`/run/systemd/system`. On NixOS it never runs apt or dpkg, never installs
containerd, runc, chrony or NetBird, never writes `/etc/systemd/system`.

A boot reaches only IMDS and NTP at 169.254.169.254, plus node-init's
hash-pinned release download; nothing downloads packages.

## The image

`packages.aarch64-linux.oci-image` is a UEFI GPT disk from `systemd-repart`
(`image.repart`, no KVM): an ESP with systemd-boot and a unified kernel image
and an ext4 root labelled `nixos`, converted to qcow2.
`.github/workflows/nix-image.yml` builds it on `ubuntu-24.04-arm`; `ci.yml`
calls it for Nix changes and `all-green` needs it.

## Build and boot-test locally

```sh
nix flake check -L
nix build .#packages.aarch64-linux.oci-image
```

`checks.x86_64-linux.boot` boots the x86_64 build of the image under UEFI
from a 4 GiB disk with no network and asserts the pinned versions, chrony,
nftables, SSH, the user, the boot chain and node-init's restart settings and
PATH. With no IMDS, node-init fails its metadata read and retries.

## Recovery

- `ts-orch-units` failed (it does not restart itself): read
  `journalctl -u ts-orch-units`, fix, `sudo systemctl start ts-orch-units`.
- No SSH keys arrived: the serial console shows the boot log but has no
  password login, and there is no Oracle Cloud Agent. Relaunch the instance
  with `ssh_authorized_keys` in its metadata; the data volume is separate.

## Bump the baked release

`nix/release.json` names one published ts-orch release:
```sh
gh release view <tag> -R TerraScale/ts-orchestrator --json assets \
  --jq '.assets[] | select(.name | startswith("terrascale-orchestrator-linux-")) | [.name, .url, .digest] | @tsv'
```

Write the tag, URLs and digests (without `sha256:`) into `nix/release.json`,
run `nix flake check` and open a PR.
