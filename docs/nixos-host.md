# NixOS node host

Every production host runs NixOS, built from `flake.nix` at the repository
root. One flake builds the same host for every server; an image is replaced,
never patched in place. A NixOS host has `/etc/NIXOS`.

## Who owns what

Nix owns (`nix/modules/node.nix`, `nix/modules/oci.nix`):

- kernel and base OS, nixpkgs `nixos-26.05` pinned by `flake.lock`;
- containerd 2.4.2, runc 1.5.2 and the NetBird client 0.81.3, built from the
  upstream release archives with the SHA-256 sums the Ubuntu path pins
  (`nix/packages/`), not nixpkgs' packages;
- `containerd.service`, `netbird.service` (the client daemon), chrony against
  the OCI NTP server 169.254.169.254, nftables with an empty ruleset and no
  NixOS firewall;
- user `terrascale` (wheel, passwordless sudo); its SSH keys come from IMDSv2
  `ssh_authorized_keys` at every boot (`terrascale-ssh-keys.service`); there
  is no `ubuntu` user and password login is off;
- Oracle Cloud settings from nixpkgs `oci-common.nix` (OCI kernel arguments,
  serial console, root grown to the boot volume) and the
  `/dev/oracleoci/oraclevd*` names of paravirtualized volumes by LUN;
- the boot chain:
  1. `ts-node-init.service`: oneshot at every boot after
     `network-online.target`, runs the baked release's
     `terrascale-orchestrator node-init`; on failure it runs again every 10 s
     with no start limit, because a pool host boots before its data volume
     is bound;
  2. `ts-orch-units.service`: oneshot after and requiring
     `ts-node-init.service`, also pulled in by every node-init start, runs
     `/usr/local/bin/terrascale-orchestrator host-units --dir /run/systemd/system --start`.

ts-orch owns `/usr/local/bin/terrascale-orchestrator` and the
`/usr/local/bin/ts-orch` symlink (Nix only creates `/usr/local/bin`),
`/var/lib/ts-orch`, `/var/lib/ts-data` (node-init mounts the data volume at
every boot; the image has no `fileSystems` entry for it), `/etc/terrascale-orchestrator`
and every unit it writes, under `/run/systemd/system`. On a NixOS host it
never runs apt or dpkg, never installs containerd, runc, chrony or NetBird,
and never writes under `/etc/systemd/system`.

A boot reaches only IMDS and NTP at 169.254.169.254; nothing downloads
packages. The release node-init installs is hash-pinned in instance metadata.

## The image

`packages.aarch64-linux.oci-image` is a UEFI GPT disk built by
`systemd-repart` (`image.repart`, no KVM): an ESP with systemd-boot and a
unified kernel image, and an ext4 root labelled `nixos`, converted to
qcow2. `.github/workflows/nix-image.yml` builds it natively on
`ubuntu-24.04-arm` for every change under `nix/` and prints its size.

## Build and boot-test locally

```sh
nix flake check -L
nix build .#nixosConfigurations.node-arm64.config.system.build.toplevel --dry-run
nix build .#packages.aarch64-linux.oci-image
```

`checks.x86_64-linux.boot` builds the same image for x86_64, boots it in
QEMU under UEFI from a 4 GiB copy and asserts the pinned versions, chrony,
nftables, the user, the boot chain units, node-init's restart settings and
PATH, the grown root and that apt, dpkg and cloud-init are absent. It needs
KVM and no network. It cannot run node-init: the VM has no IMDS.

## Bump the baked release

`nix/release.json` names one published ts-orch release. To bump it:

```sh
gh release view <tag> -R TerraScale/ts-orchestrator --json assets \
  --jq '.assets[] | select(.name | startswith("terrascale-orchestrator-linux-")) | [.name, .url, .digest] | @tsv'
```

Write the tag, both URLs and both SHA-256 digests (without `sha256:`) into
`nix/release.json`, then run `nix flake check` and open a PR.
