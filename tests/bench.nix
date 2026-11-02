# Benchmark harness, matrix-shaped (docs/design/benchmarking.md). It boots one
# NixOS VM with banken installed by its own module, runs the banken-bench suite
# and the host-level benches inside the guest, and copies the raw JSON out to
# $out -- the same shape as tests/attackrange.nix.
#
#   nix-build tests/bench.nix            (needs KVM)
#
# ONE ROW PER PLATFORM. This file is the single-VM runner. The spec wants every
# bench run inside the live distro matrix (tests/distros/distros.json) so each
# platform gets its own row: the manager expands this by booting each distro's
# cloud image (the tests/distros payload already does the boot) and running the
# same suite with `banken-bench ... -platform <distro>`, producing one Run JSON
# per distro. The -platform field is in the schema for exactly that line-up.
#
# STATUS: harness wired, NOT YET RUN. The heavy categories below are gated on a
# scheduled run after the hokkaido rebuild (it would be killed now). None of the
# numbers in the README come from this file yet; the fast-suite numbers there
# were measured directly on the host named in the README table.
{ pkgs ? import <nixpkgs> { }
, banken ? pkgs.callPackage ../package.nix { }
}:

let
  # banken-bench and the rule tree the suite loads. Same module and vendorHash
  # as package.nix; the fileset adds bench/ (which package.nix omits) and keeps
  # internal/ + rules/ that the tool imports and loads.
  benchTools = pkgs.buildGo126Module {
    pname = "banken-bench";
    version = "dev";
    src = pkgs.lib.fileset.toSource {
      root = ../.;
      fileset = pkgs.lib.fileset.unions [
        ../go.mod ../go.sum ../internal ../rules ../bench ../embed.go
      ];
    };
    vendorHash = banken.vendorHash or "sha256-3dWz1bJjqcS+WTpQOo2F7448l9zI555jOSSWjZFVQo8=";
    subPackages = [ "bench/cmd/banken-bench" ];
    env.CGO_ENABLED = 0;
    meta.mainProgram = "banken-bench";
  };

  # The rule tree on disk for -rules (banken embeds its own copy; the tool reads
  # one from disk so the padded 2k/10k scaling rows can be built from it).
  rules = ../rules;

  # Platform label for this run's Run JSON. The per-distro loop sets this to the
  # distro name; the single VM is just "nixos-vm".
  platform = "nixos-vm";
in
pkgs.testers.runNixOSTest {
  name = "banken-bench";

  nodes.machine = { pkgs, ... }: {
    imports = [ ../module.nix ];
    virtualisation = { memorySize = 4096; diskSize = 8192; cores = 4; };

    # banken installed the way the docs say, but the periodic timer is off: the
    # bench drives banken itself so the measurement is not racing a scheduled scan.
    services.banken = { enable = true; package = banken; };
    systemd.timers.banken.wantedBy = pkgs.lib.mkForce [ ];

    environment.systemPackages = [ banken benchTools pkgs.coreutils ];
  };

  testScript = ''
    import os

    machine.wait_for_unit("multi-user.target")

    out = os.environ["out"]
    machine.succeed("mkdir -p /root/bench")

    # --- fast suite: the categories that run in the VM in minutes ---
    machine.succeed(
        "banken-bench all -rules ${rules} -bin ${banken}/bin/banken "
        "-iters 20000 -platform ${platform} -out /root/bench/all.json",
        timeout=1800,
    )

    # --- resource cost: idle RSS+CPU of the real daemon (short window here; the
    #     24h soak is the same command with -duration 86400s on a quiet box) ---
    machine.succeed("systemctl start banken.service || true")
    machine.succeed(
        "pid=$(systemctl show -p MainPID --value banken.service 2>/dev/null); "
        "if [ -n \"$pid\" ] && [ \"$pid\" != 0 ]; then "
        "banken-bench sample -pid $pid -duration 30s -interval 1s "
        "-label 'banken idle (vm)' -platform ${platform} -out /root/bench/idle.json; "
        "else echo 'banken not running; idle sample skipped' > /root/bench/idle.json; fi",
        timeout=120,
    )

    # --- sensor overhead + backpressure + kernel-build-with/without + competitor
    #     comparison + boot-to-finding: HEAVY, run by the manager after the
    #     rebuild. They need the live mimi sensor, a fork bomb, a kernel source
    #     tree, competitor installs or a reboot, so they are deliberately not run
    #     here; `bench/run.sh heavy` documents each one. ---

    for f in ["all.json", "idle.json"]:
        machine.copy_from_vm(f"/root/bench/{f}", "bench")
    print("bench JSON copied to $out/bench")
    machine.succeed(f"mkdir -p {out}")
  '';
}
