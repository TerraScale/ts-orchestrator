{ pkgs, flake }:
pkgs.testers.runNixOSTest {
  name = "node-boot";

  nodes.machine =
    { lib, ... }:
    {
    imports = [ flake.nixosModules.node ];
    virtualisation = {
      directBoot.enable = false;
      mountHostNixStore = false;
      useDefaultFilesystems = false;
      useEFIBoot = true;
      fileSystems = lib.mkForce { };
    };
  };

  testScript =
    { nodes, ... }:
    let
      node = nodes.machine;
      image = "${node.system.build.image}/${node.image.filePath}";
      tools = [
        "bash"
        "python3"
        "curl"
        "lsblk"
        "blkid"
        "wipefs"
        "findmnt"
        "blockdev"
        "mountpoint"
        "mount"
        "mkfs.ext4"
        "udevadm"
        "cmp"
        "dd"
        "timeout"
        "sha256sum"
        "ip"
        "nft"
        "grep"
        "sed"
        "awk"
        "find"
      ];
    in
    ''
      import os
      import subprocess
      import tempfile

      disk = tempfile.NamedTemporaryFile(suffix=".qcow2")
      subprocess.run(["${node.virtualisation.qemu.package}/bin/qemu-img", "create", "-f", "qcow2", "-b", "${image}", "-F", "raw", disk.name, "4G"], check=True)
      os.environ["NIX_DISK_IMAGE"] = disk.name

      machine.wait_for_unit("sshd.service")

      with subtest("UEFI boot from the GPT image, root grown to the disk"):
          machine.succeed("test -d /sys/firmware/efi")
          machine.succeed("test \"$(lsblk -dno PTTYPE /dev/vda)\" = gpt")
          machine.succeed("test \"$(findmnt -no SOURCE /)\" = \"$(readlink -f /dev/disk/by-label/nixos)\"")
          machine.succeed("findmnt -no FSTYPE /boot | grep -qx vfat")
          machine.wait_until_succeeds("test $(df --output=size -B1M / | tail -1) -gt 3000")

      with subtest("pinned runtime"):
          machine.succeed("containerd --version | grep -F ' v2.4.2 '")
          machine.succeed("runc --version | grep -x 'runc version 1.5.2'")
          machine.succeed("netbird version | grep -x 0.81.3")
          machine.fail("systemctl is-active containerd.service")
          t.assertEqual(machine.succeed("systemctl show -p WantedBy -p RequiredBy --value containerd.service").split(), [])
          machine.succeed("systemctl start containerd.service")
          ctr = machine.succeed("ctr version")
          t.assertIn("Version:  v2.4.2", ctr.split("Server:", 1)[1])
          machine.wait_for_unit("netbird.service")

      with subtest("time and firewall"):
          machine.wait_for_unit("chronyd.service")
          sources = machine.succeed("chronyc -n sources | grep '^[\\^=#]' | awk '{print $2}'").split()
          t.assertEqual(sources, ["169.254.169.254"])
          config = machine.succeed("tr '\\0' '\\n' < /proc/$(pidof chronyd)/cmdline | sed -n '/^-f$/{n;p}' | xargs grep -E '^(server|pool|peer|makestep|initstepslew) '")
          t.assertEqual(config.splitlines(), ["makestep 0.100000 3", "server 169.254.169.254 iburst minpoll 4 maxpoll 6"])
          machine.wait_for_unit("nftables.service")

      with subtest("SSH listens on TCP 22 only, keys of terrascale only"):
          machine.succeed("test \"$(readlink /etc/systemd/system-generators/systemd-ssh-generator)\" = /dev/null")
          listeners = set(machine.succeed("ss -Hltn | awk '{print $4}' | grep -v -e '^127\\.' -e '^\\[::1\\]'").split())
          t.assertEqual(listeners, {"0.0.0.0:22", "[::]:22"})
          machine.succeed("test -z \"$(ss -Hl --vsock)\"")
          sshd = machine.succeed("sshd -T").lower()
          for line in ["permitrootlogin no", "passwordauthentication no", "kbdinteractiveauthentication no"]:
              t.assertIn(line, sshd.splitlines())
          keyFiles = next(line for line in sshd.splitlines() if line.startswith("authorizedkeysfile ")).split()[1:]
          t.assertEqual(set(keyFiles), {"/etc/ssh/authorized_keys.d/%u", "/var/lib/terrascale-ssh/%u"})

      with subtest("user terrascale with sudo"):
          machine.succeed("id terrascale | grep -F '(wheel)'")
          machine.succeed("su terrascale -s /bin/sh -c 'sudo -n true'")
          machine.fail("id ubuntu")

      with subtest("boot chain"):
          machine.wait_until_succeeds("journalctl -u ts-node-init.service -o cat | grep -F 'node-init: read instance metadata'")
          machine.fail("journalctl -u ts-node-init.service -o cat | grep -F 'unknown command'")
          machine.succeed("systemctl cat ts-node-init.service ts-orch-units.service")
          units = machine.succeed("cat $(systemctl show -p ExecStart --value ts-orch-units.service | grep -o '/nix/store/[^ ;]*-unit-script-ts-orch-units-start/bin/ts-orch-units-start')")
          t.assertIn("if [ -e /usr/local/bin/terrascale-orchestrator.recovery ]; then", units)
          t.assertIn("exec /usr/local/bin/terrascale-orchestrator.recovery host-units --dir /run/systemd/system --start", units)
          t.assertIn("exec /usr/local/bin/terrascale-orchestrator host-units --dir /run/systemd/system --start", units)
          machine.succeed("test -d /usr/local/bin")
          restart = machine.succeed("systemctl show -p Type -p Restart -p RestartMode -p RestartUSec -p StartLimitIntervalUSec ts-node-init.service")
          for setting in ["Type=oneshot", "Restart=on-failure", "RestartMode=direct", "RestartUSec=10s", "StartLimitIntervalUSec=0"]:
              t.assertIn(setting, restart.splitlines())
          path = machine.succeed("systemctl show -p Environment --value ts-node-init.service | tr ' ' '\\n' | sed -n 's/^PATH=//p'").strip()
          for tool in ${builtins.toJSON tools}:
              machine.succeed(f"PATH={path} command -v {tool}")
          machine.fail("grep -q /var/lib/ts- /etc/fstab")
          machine.wait_until_succeeds("test $(systemctl show -p NRestarts --value ts-node-init.service) -ge 2")
          restarts = int(machine.succeed("systemctl show -p NRestarts --value ts-node-init.service"))
          uptime = float(machine.succeed("cut -d' ' -f1 /proc/uptime"))
          t.assertLessEqual(restarts, uptime / 10 + 1)
          jobs = machine.succeed("systemctl list-jobs --no-legend")
          t.assertRegex(jobs, r"ts-orch-units\.service\s+start\s+waiting")
          t.assertRegex(jobs, r"ts-node-init\.service\s+start\s+running")

      with subtest("no Debian packaging or cloud-init"):
          for tool in ["apt", "apt-get", "dpkg", "cloud-init"]:
              machine.fail(f"command -v {tool}")
          machine.fail("systemctl cat cloud-init.service")
          machine.succeed("test -e /etc/NIXOS")
    '';
}
