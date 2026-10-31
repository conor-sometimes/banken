# Live ATT&CK range: every Linux bash/sh atomic of a pinned Atomic Red Team
# commit runs for real inside a throwaway VM (the only place atomics may run),
# with banken deployed by its own NixOS module, and banken scores which ones it
# detects. A scorecard, not a gate: the run passes when the range completes,
# and $out holds scorecard.md, scorecard.json and results.ndjson.
#
#   nix-build tests/attackrange.nix          (needs KVM; long: ~200 atomics)
{ pkgs ? import <nixpkgs> { }, banken ? pkgs.callPackage ../package.nix { } }:

let
  # Pinned: the scorecard is only comparable run to run against the same atomics.
  art = pkgs.fetchFromGitHub {
    owner = "redcanaryco";
    repo = "atomic-red-team";
    rev = "e8cfc418a064ee50d831f41a8aeccf5b80a202f5";
    hash = "sha256-KMtcWOoBZUcwfXVG/69rWFCFQczAi0eyR792fLdN4Xk=";
  };
  python = pkgs.python3.withPackages (ps: [ ps.pyyaml ]);
  atomics = pkgs.runCommand "art-linux-atomics.ndjson" { } ''
    ${python}/bin/python3 ${../attackrange/attackrange.py} ${art}/atomics --emit > $out
  '';
in
pkgs.testers.runNixOSTest {
  name = "banken-attackrange";

  nodes.machine = { config, pkgs, lib, ... }: {
    imports = [ ../module.nix ];
    virtualisation = { memorySize = 4096; diskSize = 8192; cores = 4; };

    services.banken = { enable = true; package = banken; };
    systemd.timers.banken.wantedBy = lib.mkForce [ ]; # the range runs its own scans

    # range.py refuses to run without this: atomics execute for real.
    systemd.tmpfiles.rules = [ "f /run/banken-range-sandbox 0600 root root -" ];
    environment.etc."banken-range/audit.rules".text = lib.concatStringsSep "\n" config.security.audit.rules + "\n";

    services.cron.enable = true;
    services.atd.enable = true;
    environment.systemPackages = with pkgs; [
      curl wget python3 perl netcat-gnu socat openssl gnutar zip unzip xxd
      git gcc binutils procps psmisc lsof iproute2 nettools util-linux shadow
      file which audit
    ];

    systemd.services.banken-range = {
      description = "banken live ATT&CK range (sandbox VM only)";
      path = with pkgs; [ bash coreutils systemd audit ] ++ config.environment.systemPackages;
      serviceConfig = {
        Type = "oneshot";
        TimeoutStartSec = "infinity";
        ExecStart = "${python}/bin/python3 ${../attackrange/range.py} ${atomics} ${lib.getExe banken} /etc/banken-range/audit.rules /var/lib/banken-range";
      };
    };
  };

  testScript = ''
    machine.wait_for_unit("auditd.service")
    machine.wait_until_succeeds("auditctl -l | grep -q banken-exec")
    machine.succeed("systemctl start --no-block banken-range.service")
    machine.wait_until_succeeds("test -e /var/lib/banken-range/done", timeout=4 * 3600)
    print(machine.succeed("cat /var/lib/banken-range/scorecard.md"))
    for f in ["scorecard.md", "scorecard.json", "results.ndjson"]:
        machine.copy_from_vm(f"/var/lib/banken-range/{f}", "")
  '';
}
