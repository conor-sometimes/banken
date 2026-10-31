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

      # nix run .#distro-matrix: every distro in tests/distros live under KVM, no
      # manual steps (needs KVM and network for the guests' package installs).
      apps.x86_64-linux.distro-matrix = {
        type = "app";
        program = nixpkgs.lib.getExe (nixpkgs.legacyPackages.x86_64-linux.callPackage ./tests/distros {
          banken = self.packages.x86_64-linux.banken;
        });
      };

      # nix develop .#conformance -c just conformance: the tools the standards
      # gate needs, NixOS-ready. uv uses Nix's Pythons (3.13 for pySigma, 3.14
      # for the OCSF schema compiler) instead of downloading generic-Linux
      # builds NixOS cannot run, and pySigma's google-re2 wheel finds libstdc++
      # through the loader path.
      devShells.x86_64-linux.conformance = let pkgs = nixpkgs.legacyPackages.x86_64-linux; in pkgs.mkShell {
        packages = with pkgs; [ go_1_27 uv just git python3 python314 ];
        UV_PYTHON_PREFERENCE = "only-system";
        UV_PYTHON_DOWNLOADS = "never";
        LD_LIBRARY_PATH = "${pkgs.stdenv.cc.cc.lib}/lib";
      };

      # nix flake check: the end-to-end VM test (needs KVM).
      checks.x86_64-linux.vm = import ./tests/vm.nix { pkgs = nixpkgs.legacyPackages.x86_64-linux; };
    };
}
