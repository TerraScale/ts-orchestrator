{
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";

  outputs =
    { self, nixpkgs }:
    let
      inherit (nixpkgs) lib;
      regularNixFiles =
        dir: lib.filterAttrs (name: type: type == "regular" && lib.hasSuffix ".nix" name) (builtins.readDir dir);
      discoverNixFiles =
        dir:
        lib.mapAttrs' (
          name: _: lib.nameValuePair (lib.removeSuffix ".nix" name) (dir + "/${name}")
        ) (regularNixFiles dir);
    in
    {
      nixosModules = discoverNixFiles ./nix/modules;

      nixosConfigurations = lib.mapAttrs (
        _: host:
        lib.nixosSystem {
          modules = [ host ];
          specialArgs.flake = self;
        }
      ) (discoverNixFiles ./nix/hosts);

      packages.aarch64-linux.oci-image = self.nixosConfigurations.node-arm64.config.system.build.ociImage;

      checks.x86_64-linux.boot = import ./nix/checks/boot.nix {
        pkgs = nixpkgs.legacyPackages.x86_64-linux;
        flake = self;
      };
    };
}
