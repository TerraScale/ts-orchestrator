{
  config,
  lib,
  pkgs,
  modulesPath,
  ...
}:
let
  efiArch = pkgs.stdenv.hostPlatform.efiArch;
  volumeSuffixesByLun = lib.lowerChars ++ [
    "aa"
    "ab"
    "ac"
    "ad"
    "ae"
    "af"
  ];
  ociVolumeRulesByLun = lib.imap1 (
    lun: suffix: ''ENV{ID_PATH}=="pci-*-scsi-0:0:0:${toString lun}", SYMLINK+="oracleoci/oraclevd${suffix}"''
  ) volumeSuffixesByLun;
  keysDirectory = "/var/lib/terrascale-ssh";
  keysFile = "${keysDirectory}/terrascale";
in
{
  imports = [
    "${modulesPath}/virtualisation/oci-options.nix"
    "${modulesPath}/virtualisation/oci-common.nix"
    "${modulesPath}/image/repart.nix"
  ];

  boot.loader.grub.enable = false;

  services.udev.extraRules = ''
    ACTION=="remove", GOTO="terrascale_oci_device_paths_end"
    SUBSYSTEM!="block", GOTO="terrascale_oci_device_paths_end"
    ENV{DEVTYPE}!="disk", GOTO="terrascale_oci_device_paths_end"
    KERNEL!="sd*", GOTO="terrascale_oci_device_paths_end"
    SUBSYSTEMS=="scsi", ATTRS{vendor}=="ORACLE*", ATTRS{model}=="BlockVolume*", GOTO="terrascale_oci_block_volume"
    GOTO="terrascale_oci_device_paths_end"
    LABEL="terrascale_oci_block_volume"
    IMPORT{builtin}="path_id"
    ${lib.concatStringsSep "\n" ociVolumeRulesByLun}
    LABEL="terrascale_oci_device_paths_end"
  '';

  systemd.generators.systemd-ssh-generator = "/dev/null";

  services.openssh = {
    settings = {
      PasswordAuthentication = false;
      KbdInteractiveAuthentication = false;
      PermitRootLogin = "no";
    };
    authorizedKeysInHomedir = false;
    authorizedKeysFiles = [ "${keysDirectory}/%u" ];
  };

  systemd.services.terrascale-ssh-keys = {
    description = "SSH keys of user terrascale from OCI instance metadata";
    wantedBy = [ "sshd.service" ];
    before = [ "sshd.service" ];
    wants = [ "network-online.target" ];
    after = [ "network-online.target" ];
    startLimitIntervalSec = 0;
    path = [
      pkgs.coreutils
      pkgs.curl
    ];
    script = ''
      install -d -m 0755 ${keysDirectory}
      curl -fsS --max-time 10 -H "Authorization: Bearer Oracle" \
        -o ${keysFile}.new http://169.254.169.254/opc/v2/instance/metadata/ssh_authorized_keys
      chmod 0644 ${keysFile}.new
      mv ${keysFile}.new ${keysFile}
    '';
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      Restart = "on-failure";
      RestartSec = "5s";
    };
  };

  image.repart = {
    name = "terrascale-node";
    sectorSize = 512;
    partitions = {
      esp = {
        contents = {
          "/EFI/BOOT/BOOT${lib.toUpper efiArch}.EFI".source =
            "${pkgs.systemd}/lib/systemd/boot/efi/systemd-boot${efiArch}.efi";
          "/EFI/Linux/${config.system.boot.loader.ukiFile}".source =
            "${config.system.build.uki}/${config.system.boot.loader.ukiFile}";
        };
        repartConfig = {
          Type = "esp";
          Format = "vfat";
          Label = "ESP";
          SizeMinBytes = "256M";
        };
      };
      root = {
        storePaths = [ config.system.build.toplevel ];
        repartConfig = {
          Type = "root";
          Format = "ext4";
          Label = "nixos";
          Minimize = "guess";
        };
      };
    };
  };

  system.build.ociImage = pkgs.runCommand "terrascale-node-oci-image" { nativeBuildInputs = [ pkgs.qemu-utils ]; } ''
    mkdir $out
    qemu-img convert -f raw -O qcow2 ${config.system.build.image}/${config.image.filePath} $out/terrascale-node.qcow2
  '';
}
