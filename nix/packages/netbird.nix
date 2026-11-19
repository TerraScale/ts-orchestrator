{ callPackage }:
callPackage ./pinned-archive.nix {
  pname = "netbird";
  version = "0.81.3";
  archives = {
    arm64 = {
      url = "https://github.com/netbirdio/netbird/releases/download/v0.81.3/netbird_0.81.3_linux_arm64.tar.gz";
      sha256 = "980eef938177108bdfa7d802566b6309123592a58631349a78f11cd97c76c22d";
    };
    amd64 = {
      url = "https://github.com/netbirdio/netbird/releases/download/v0.81.3/netbird_0.81.3_linux_amd64.tar.gz";
      sha256 = "cbdea310068e35449f034544d5137fefee8f6d948fffd020883ffc8b3bab63b1";
    };
  };
  install = "install -Dm0755 netbird $out/bin/netbird";
}
