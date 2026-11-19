{ lib, callPackage }:
let
  release = lib.importJSON ../release.json;
in
callPackage ./pinned-archive.nix {
  pname = "terrascale-orchestrator";
  version = release.tag;
  format = "executable";
  archives = { inherit (release) arm64 amd64; };
  installCommand = "install -Dm0755 terrascale-orchestrator $out/bin/terrascale-orchestrator";
}
