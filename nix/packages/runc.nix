{ callPackage }:
callPackage ./pinned-archive.nix {
  pname = "runc";
  version = "1.5.2";
  format = "executable";
  archives = {
    arm64 = {
      url = "https://github.com/opencontainers/runc/releases/download/v1.5.2/runc.arm64";
      sha256 = "d10ecae898361832a059be2089bab92d158aec54661b18ed7346ed79628b46b0";
    };
    amd64 = {
      url = "https://github.com/opencontainers/runc/releases/download/v1.5.2/runc.amd64";
      sha256 = "599f6f94ff8c5057241eff0d54c3c74f95c34935b6457b33fe545defc61e9488";
    };
  };
  installCommand = "install -Dm0755 runc $out/bin/runc";
}
