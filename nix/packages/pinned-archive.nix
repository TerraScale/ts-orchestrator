{
  lib,
  stdenvNoCC,
  fetchurl,
  autoPatchelfHook,
  pname,
  version,
  archives,
  install,
}:
let
  arch =
    {
      aarch64-linux = "arm64";
      x86_64-linux = "amd64";
    }
    .${stdenvNoCC.hostPlatform.system};
  archive = archives.${arch};
in
stdenvNoCC.mkDerivation {
  inherit pname version;
  src = fetchurl {
    inherit (archive) url sha256;
  };
  sourceRoot = ".";
  unpackCmd = if lib.hasSuffix ".tar.gz" archive.url then "tar -xzf $curSrc" else "cp $curSrc ./${pname}";
  nativeBuildInputs = [ autoPatchelfHook ];
  dontConfigure = true;
  dontBuild = true;
  dontStrip = true;
  installPhase = ''
    runHook preInstall
    ${install}
    runHook postInstall
  '';
  meta.platforms = [
    "aarch64-linux"
    "x86_64-linux"
  ];
}
