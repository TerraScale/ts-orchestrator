{
  stdenvNoCC,
  fetchurl,
  autoPatchelfHook,
  pname,
  version,
  format,
  archives,
  installCommand,
}:
let
  arch =
    {
      aarch64-linux = "arm64";
      x86_64-linux = "amd64";
    }
    .${stdenvNoCC.hostPlatform.system};
  archive = archives.${arch};
  unpackCommands = {
    tarball = "tar -xzf $curSrc";
    executable = "cp $curSrc ./${pname}";
  };
in
stdenvNoCC.mkDerivation {
  inherit pname version;
  src = fetchurl {
    inherit (archive) url sha256;
  };
  sourceRoot = ".";
  unpackCmd = unpackCommands.${format};
  nativeBuildInputs = [ autoPatchelfHook ];
  dontConfigure = true;
  dontBuild = true;
  dontStrip = true;
  installPhase = ''
    runHook preInstall
    ${installCommand}
    runHook postInstall
  '';
  meta.platforms = [
    "aarch64-linux"
    "x86_64-linux"
  ];
}
