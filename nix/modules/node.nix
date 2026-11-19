{ pkgs, ... }:
let
  containerd = pkgs.callPackage ../packages/containerd.nix { };
  runc = pkgs.callPackage ../packages/runc.nix { };
  netbird = pkgs.callPackage ../packages/netbird.nix { };
  orchestrator = pkgs.callPackage ../packages/terrascale-orchestrator.nix { };
in
{
  imports = [ ./oci.nix ];

  system.stateVersion = "26.05";

  networking.hostName = "";
  networking.firewall.enable = false;
  networking.nftables.enable = true;
  services.resolved.settings.Resolve = {
    LLMNR = false;
    MulticastDNS = false;
  };

  services.chrony = {
    enable = true;
    servers = [ ];
    extraConfig = "server 169.254.169.254 iburst minpoll 4 maxpoll 6";
    makestep = {
      enable = true;
      threshold = 0.1;
      limit = 3;
    };
  };

  boot.kernelModules = [ "overlay" ];

  environment.systemPackages = [
    containerd
    runc
    netbird
  ];

  users.mutableUsers = false;
  users.allowNoPasswordLogin = true;
  users.users.terrascale = {
    isNormalUser = true;
    extraGroups = [ "wheel" ];
  };
  security.sudo.wheelNeedsPassword = false;

  systemd.tmpfiles.rules = [ "d /usr/local/bin 0755 root root -" ];

  systemd.services.containerd = {
    description = "containerd container runtime";
    after = [ "network.target" ];
    path = [
      containerd
      runc
    ];
    serviceConfig = {
      ExecStart = "${containerd}/bin/containerd";
      Type = "notify";
      Delegate = true;
      KillMode = "process";
      Restart = "always";
      RestartSec = "5s";
      LimitNPROC = "infinity";
      LimitCORE = "infinity";
      TasksMax = "infinity";
      OOMScoreAdjust = -999;
    };
  };

  systemd.services.netbird = {
    description = "NetBird private management network and SSH";
    wantedBy = [ "multi-user.target" ];
    wants = [ "network-online.target" ];
    after = [ "network-online.target" ];
    startLimitIntervalSec = 0;
    path = [
      pkgs.iproute2
      pkgs.nftables
    ];
    environment = {
      NB_FORCE_RELAY = "true";
      NB_LAZY_CONN = "on";
    };
    serviceConfig = {
      ExecStart = "${netbird}/bin/netbird service run --config /var/lib/netbird/config.json --log-file console";
      Restart = "always";
      RestartSec = "10s";
      TimeoutStopSec = "30s";
      StateDirectory = "netbird";
      StateDirectoryMode = "0700";
      KillMode = "process";
      LimitNOFILE = 65536;
    };
  };

  systemd.services.ts-node-init = {
    description = "TerraScale node init";
    wantedBy = [ "multi-user.target" ];
    wants = [ "network-online.target" ];
    after = [ "network-online.target" ];
    startLimitIntervalSec = 0;
    path = with pkgs; [
      bash
      coreutils
      curl
      diffutils
      e2fsprogs
      findutils
      gawk
      gnugrep
      gnused
      iproute2
      nftables
      python3
      systemd
      util-linux
    ];
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      ExecStart = "${orchestrator}/bin/terrascale-orchestrator node-init";
      Restart = "on-failure";
      RestartMode = "direct";
      RestartSec = "10s";
    };
  };

  systemd.services.ts-orch-units = {
    description = "TerraScale orchestrator units";
    wantedBy = [ "multi-user.target" ];
    requires = [ "ts-node-init.service" ];
    after = [ "ts-node-init.service" ];
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
    };
    script = ''
      if [ -e /usr/local/bin/terrascale-orchestrator.recovery ]; then
        exec /usr/local/bin/terrascale-orchestrator.recovery host-units --dir /run/systemd/system --start
      fi
      exec /usr/local/bin/terrascale-orchestrator host-units --dir /run/systemd/system --start
    '';
  };
}
