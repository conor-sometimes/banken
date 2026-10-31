# Non-flake entry point: the NixOS module. In a configuration.nix:
#   imports = [ "${builtins.fetchGit { url = "https://github.com/conor-sometimes/banken"; rev = "<rev>"; }}/module.nix" ];
# or import this file. The package alone: pkgs.callPackage ./package.nix { }.
import ./module.nix
