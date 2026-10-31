{
  description = "banken: a small host EDR -- Sigma rules and IOCs over the Linux audit log, with OCSF output";

  # Used only for this flake's own packages and checks. The NixOS module builds
  # banken with the consuming system's pkgs, so importing it adds no nixpkgs.
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAll = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      nixosModules.default = import ./module.nix;
      nixosModules.banken = import ./module.nix;

      overlays.default = final: _prev: { banken = final.callPackage ./package.nix { }; };

      packages = forAll (pkgs: rec {
        banken = pkgs.callPackage ./package.nix { };
        default = banken;
      });

      # nix flake check: the end-to-end VM test (needs KVM).
      checks.x86_64-linux.vm = import ./tests/vm.nix { pkgs = nixpkgs.legacyPackages.x86_64-linux; };
    };
}
