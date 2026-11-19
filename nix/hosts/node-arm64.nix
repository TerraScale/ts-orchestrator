{ flake, ... }:
{
  imports = [ flake.nixosModules.node ];
  nixpkgs.hostPlatform = "aarch64-linux";
}
