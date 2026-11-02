{
  description = "banken: a small host EDR -- Sigma rules and IOCs over the Linux audit log, with OCSF output";

  # Used only for this flake's own packages and checks. The NixOS module builds
  # banken with the consuming system's pkgs, so importing it adds no nixpkgs.
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";

  # mimi is a TEST-ONLY input: the eBPF sensor, wired into the banken + mimi integration checks
  # (switch/floor/restart) and the live mimi distro matrix. The product stays decoupled -- the
  # package and the NixOS module never reference mimi, so importing banken drags in nothing of it.
  inputs.mimi.url = "github:conor-sometimes/mimi";

  outputs = { self, nixpkgs, mimi }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAll = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});

      # x86_64-only helpers for the KVM integration and live tests. mimi is an x86_64 eBPF sensor,
      # so its tests pin that system. The portable bundle is mimi plus the glibc loader it needs to
      # run in a vendor guest with no /nix (see tests/distros, Test B).
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
      bankenPkg = self.packages.${system}.banken;
      mimiModule = mimi.nixosModules.mimi;
      mimiBundle = pkgs.runCommand "mimi-bundle" { } ''
        mkdir -p $out
        cp ${mimi.packages.${system}.default}/bin/mimi $out/mimi
        cp ${pkgs.glibc}/lib/ld-linux-x86-64.so.2 $out/ld.so
        cp ${pkgs.glibc}/lib/libc.so.6 $out/libc.so.6
        cp ${pkgs.stdenv.cc.cc.lib}/lib/libgcc_s.so.1 $out/libgcc_s.so.1
        chmod -R u+w $out
      '';

      # A nixos test (runNixOSTest) run as a `nix run` app: its .driver executes the baked-in
      # testScript non-interactively and streams the narrated transcript to the terminal. Run in a
      # scratch dir so the driver's VM state and logs land there, not in the caller's cwd.
      demoRunner = name: test: nixpkgs.lib.getExe (pkgs.writeShellApplication {
        name = "banken-${name}";
        text = ''
          work=$(mktemp -d)
          trap 'rm -rf "$work"' EXIT
          cd "$work"
          exec ${test.driver}/bin/nixos-test-driver "$@"
        '';
      });
    in
    {
      nixosModules.default = import ./module.nix;
      nixosModules.banken = import ./module.nix;

      overlays.default = final: _prev: { banken = final.callPackage ./package.nix { }; };

      packages = forAll (pkgs: rec {
        banken = pkgs.callPackage ./package.nix { };
        default = banken;
      });

      # nix run .#distro-matrix: every distro in tests/distros live under KVM, no manual steps
      # (needs KVM and network for the guests' package installs). The -mimi variant also loads the
      # eBPF sensor on each distro's own kernel and proves banken detects off the mimi stream (Test
      # B, M1-M5); the plain one is banken on the auditd floor only.
      apps.x86_64-linux.distro-matrix = {
        type = "app";
        program = nixpkgs.lib.getExe (pkgs.callPackage ./tests/distros {
          banken = bankenPkg;
        });
      };
      apps.x86_64-linux.distro-matrix-mimi = {
        type = "app";
        program = nixpkgs.lib.getExe (pkgs.callPackage ./tests/distros {
          banken = bankenPkg;
          inherit mimiBundle;
        });
      };

      # nix run .#demo / .#demo-mimi: the repo showcase (docs/design/showcase.md, demo/demo.nix).
      # Each boots a throwaway NixOS VM, runs the repo's own benign revshell as an unprivileged
      # user, and prints a narrated transcript ending in the OCSF reverse_shell finding and the
      # measured exec->alert latency. demo = the auditd FLOOR (universal: only this repo + nixpkgs +
      # KVM); demo-mimi = the eBPF SWITCH (also needs the mimi input), the sub-second catch off the
      # mimi stream. Both REUSE tests/vm.nix / tests/switch.nix assertions, mirroring the
      # distro-matrix / distro-matrix-mimi split -- the plain one never touches mimi.
      apps.x86_64-linux.demo = {
        type = "app";
        program = demoRunner "demo" (import ./demo/demo.nix {
          inherit pkgs;
          banken = bankenPkg;
          flavour = "auditd";
        });
      };
      apps.x86_64-linux.demo-mimi = {
        type = "app";
        program = demoRunner "demo-mimi" (import ./demo/demo.nix {
          inherit pkgs mimiModule;
          banken = bankenPkg;
          flavour = "mimi";
        });
      };

      # nix develop: the full toolchain `just` needs to build and test banken, so
      # a contributor gets a reproducible dev environment without installing a
      # thing -- `nix develop` then `just` (just default = the whole gate).
      # (nix develop .#conformance adds the standards-gate tools; see below.)
      devShells = nixpkgs.lib.recursiveUpdate
        (forAll (pkgs: {
          default = pkgs.mkShell {
            packages = with pkgs; [
              go_1_26
              gofumpt
              golangci-lint
              gosec
              govulncheck
              errcheck
              go-tools # ships the `staticcheck` binary
              gotestsum # `just test` renders the suite through it
              just
              git
              hyperfine # just bench
              cyclonedx-gomod # just sbom
              delve # dlv, for debugging
            ];
            # just bench's A/B comparison also wants `benchstat` (go install
            # golang.org/x/perf/cmd/benchstat@latest); it is not packaged in nixpkgs.
            shellHook = ''echo "banken dev shell -- run 'just' for the targets (just default = the full gate)"'';
          };
        }))
        {
          # nix develop .#conformance -c just conformance: the tools the standards
          # gate needs, NixOS-ready. uv uses Nix's Pythons (3.13 for pySigma, 3.14
          # for the OCSF schema compiler) instead of downloading generic-Linux
          # builds NixOS cannot run, and pySigma's google-re2 wheel finds libstdc++
          # through the loader path.
          x86_64-linux.conformance = let pkgs = nixpkgs.legacyPackages.x86_64-linux; in pkgs.mkShell {
            packages = with pkgs; [ go_1_26 uv just git python3 python314 ];
            UV_PYTHON_PREFERENCE = "only-system";
            UV_PYTHON_DOWNLOADS = "never";
            LD_LIBRARY_PATH = "${pkgs.stdenv.cc.cc.lib}/lib";
          };
        };

      # nix flake check: the end-to-end VM tests (need KVM). vm is banken alone on the module; the
      # switch suite is the banken + mimi integration (the ONE SWITCH: services.banken.mimi.enable
      # brings up the sensor and points banken at its stream) -- switch isolates mimi (audit off),
      # switch-floor runs the live hokkaido shape (floor + mimi), switch-restart proves banken
      # re-attaches to mimi's stream across a mimi restart.
      checks.x86_64-linux = {
        vm = import ./tests/vm.nix { inherit pkgs; banken = bankenPkg; };
        switch = import ./tests/switch.nix { inherit pkgs mimiModule; banken = bankenPkg; };
        switch-floor = import ./tests/switch-floor.nix { inherit pkgs mimiModule; banken = bankenPkg; };
        switch-restart = import ./tests/switch-restart.nix { inherit pkgs mimiModule; banken = bankenPkg; };
      };
    };
}
