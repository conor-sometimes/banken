# End-to-end test of the NixOS module: a VM with `services.banken.enable = true`
# (which also turns on auditd and banken's audit rules), the jsonl sink in OCSF
# format, and the benign malware look-alikes in tests/emulations. Each
# emulation runs as an ordinary user, then the banken unit runs one scan, and
# the rules that fired must be exactly the ones that family's fixtures name
# (tests/fixtures/<family>.expect-<rule>.json): a miss and a false positive
# both fail. Every alert line must be an OCSF 1.3.0 Detection Finding.
#
#   nix-build tests/vm.nix          (needs KVM; uses <nixpkgs> unless pkgs is passed)
#   nix flake check                 (the same test, as checks.x86_64-linux.vm)
{ pkgs ? import <nixpkgs> { }, banken ? pkgs.callPackage ../package.nix { } }:

let
  lib = pkgs.lib;

  # family -> expected rules, read from the fixture names so this test and the
  # fast replay test (internal/engine TestFixtures) can never disagree.
  fixtures = builtins.attrNames (builtins.readDir ./fixtures);
  parse = f: builtins.match "([^.]+)\\.expect-(.+)\\.json" f;
  families = map (f: lib.removeSuffix ".sh" f)
    (builtins.filter (lib.hasSuffix ".sh") (builtins.attrNames (builtins.readDir ./emulations)));
  expected = lib.genAttrs families (fam:
    map (f: builtins.elemAt (parse f) 1)
      (builtins.filter (f: parse f != null && builtins.elemAt (parse f) 0 == fam) fixtures));
in
pkgs.testers.runNixOSTest {
  name = "banken";

  nodes.machine = { pkgs, lib, ... }: {
    imports = [ ../module.nix ];
    services.banken = {
      enable = true;
      package = banken;
      alerts.jsonl = { enable = true; format = "ocsf"; };
    };
    # The test drives every scan itself, so a scan lands between emulations.
    systemd.timers.banken.wantedBy = lib.mkForce [ ];

    users.users.alice.isNormalUser = true;
    environment.systemPackages = with pkgs; [ curl python3 netcat-gnu procps gnutar audit ];
    environment.etc."banken-emulations".source = ./emulations;
  };

  testScript = ''
    import json

    expected = json.loads(${builtins.toJSON (builtins.toJSON expected)})

    machine.wait_for_unit("auditd.service")
    machine.wait_until_succeeds("auditctl -l | grep -q banken-exec")
    # Drain boot-time events so the first emulation is judged alone.
    machine.succeed("systemctl start banken.service")

    def lines():
        out = machine.succeed("cat /var/log/banken/alerts-*.jsonl 2>/dev/null || true")
        return [l for l in out.splitlines() if l.strip()]

    failures = []
    for family in sorted(expected):
        before = len(lines())
        # runuser, not su/sudo: those would (rightly) fire privilege_escalation_attempt.
        machine.succeed(f"runuser -u alice -- bash /etc/banken-emulations/{family}.sh")
        machine.succeed("systemctl start banken.service")
        new = [json.loads(l) for l in lines()[before:]]
        for f in new:
            assert f["class_uid"] == 2004 and f["metadata"]["version"] == "1.3.0", f
            assert f["device"]["hostname"] == "machine", f["device"]
        fired = sorted({f["finding_info"]["analytic"]["name"] for f in new})
        want = sorted(set(expected[family]))
        print(f"{family}: fired {fired}, expected {want}")
        if fired != want:
            failures.append(f"{family}: fired {fired}, expected {want}")

    assert not failures, "\n".join(failures)
  '';
}
