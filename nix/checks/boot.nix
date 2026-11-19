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
          machine.wait_for_unit("containerd.service")
          machine.succeed("ctr version | grep -F 'Version:  v2.4.2'")
          machine.wait_for_unit("netbird.service")

      with subtest("time and firewall"):
          machine.wait_for_unit("chronyd.service")
          machine.succeed("chronyc -n sources | grep -F 169.254.169.254")
          machine.wait_for_unit("nftables.service")

      with subtest("user terrascale with sudo"):
          machine.succeed("id terrascale | grep -F '(wheel)'")
          machine.succeed("su terrascale -s /bin/sh -c 'sudo -n true'")
          machine.fail("id ubuntu")

      with subtest("boot chain"):
          machine.succeed("systemctl cat ts-node-init.service ts-orch-units.service")
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
