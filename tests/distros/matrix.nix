# banken's live distro matrix, as a consumer of mayfly. banken passes its own
# static binary, its units and audit rules, and its checks; the engine does the
# booting, provisioning, attribution and teardown. Nothing in the engine names
# banken.
#
# Returns the mkMatrix result (apps, checks, readme) for flake.nix to splice in.
# `distros` starts at the proven Ubuntu skeleton; the other vendor distros are
# one catalog attr each as they are signed off against the extracted engine.
{ pkgs, lib, mayfly, banken }:
mayfly.lib.mkMatrix {
  inherit pkgs;

  distros = {
    ubuntu-2404.enable = true;
  };

  installs.banken = {
    binary = lib.getExe banken;
    installPath = "/usr/bin/banken";
    units = [ ../../packaging/systemd/banken.service ../../packaging/systemd/banken.timer ];
    files = {
      "/etc/audit/rules.d/banken.rules" = ./banken.rules;
      "/etc/banken/banken.yml" = ./banken.yml;
    };
    start = false; # oneshot; installed but not auto-started, driven by `scan`
    scan = [ "systemctl" "start" "banken.service" ];
    ocsf = "/var/log/banken/alerts-*.jsonl";
    packages = [ "auditd" "auditctl" "runuser" "tar" "curl" "python3" "pkill" "bash" "sudo" ];
  };

  checks =
    (import ./checks.nix { inherit lib; emulationsDir = ../emulations; fixturesDir = ../fixtures; })
    // {
      # B2: a normal day fires nothing, scoped by its own launcher subtree.
      benign = { kind = "detect"; run = ./benign.sh; as = "user"; expect = [ ]; };
      # D1/D2: the engine built-ins, a function of the unit and the subject name.
      sandbox = { kind = "sandbox"; unit = "banken.service"; };
      lsm = { kind = "lsm"; match = "banken"; };
      # Test S: banken + Microsoft's real Sysmon-for-Linux, on the distros MS serves.
      sysmon = {
        kind = "script";
        run = ./sysmoncheck.sh;
        ids = [ "S1" "S2" "S3" "S4" "S5" ];
        tools = [ ];
        when = d: d.pm == "apt" || d.family == "rhel";
      };
    };
}
