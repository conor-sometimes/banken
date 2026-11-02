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
  expectedAll = lib.genAttrs families (fam:
    map (f: builtins.elemAt (parse f) 1)
      (builtins.filter (f: parse f != null && builtins.elemAt (parse f) 0 == fam) fixtures));
  # Three classes of rule cannot be proven in a stock module VM (the same exclusion
  # tests/distros/matrix_test.go makes, for the same reasons): account-scoped agent rules
  # (rules/agent/, keyed on an agent login auid the emulations never carry), honeytoken_access
  # (needs decoy files and audit watches only a containment host has), and the optional rules
  # (netcat, password_cracker: off by default, so the default posture never loads them). Each is
  # proven instead by the engine golden/replay tests. Drop those families from the live expectation.
  unprovable = r: lib.hasPrefix "agent_" r || r == "honeytoken_access" || r == "netcat" || r == "password_cracker";
  expected = lib.filterAttrs (_: rules: !(lib.any unprovable rules)) expectedAll;

  # ---- module-eval proofs of the two-process split (§2.8), pure Nix, no VM ----
  # These evaluate the module directly (boot.isContainer keeps the eval light,
  # no bootloader/fileSystems) and assert, at derivation-eval time, the three
  # invariants the split rests on: the default config renders NO helper unit; the
  # daemon unit is byte-identical whether or not enforcement is armed; and a
  # misconfig trips the module's own assertions. If any fails, building this test
  # (and `nix flake check`) fails before the VM ever boots.
  pol = "mode: observe";
  evalBanken = extra: (pkgs.nixos ({ ... }: {
    imports = [ ../module.nix ];
    boot.isContainer = true;
    system.stateVersion = "26.05";
    services.banken = { enable = true; package = banken; } // extra;
  })).config;

  cfgOff = evalBanken { response = { enable = true; enforce = false; policy = pol; }; };
  cfgOn = evalBanken { response = { enable = true; enforce = true; policy = pol; }; };

  # byte-identical daemon unit regardless of enforce (the whole point of the
  # split). Reading serviceConfig forces only that unit, not the assertions.
  daemonIdentical =
    (builtins.toJSON cfgOff.systemd.services.banken.serviceConfig)
    == (builtins.toJSON cfgOn.systemd.services.banken.serviceConfig);
  # the helper exists iff response.enable && response.enforce.
  noHelperDefault = !(cfgOff.systemd.services ? banken-respond);
  helperWhenArmed = cfgOn.systemd.services ? banken-respond;

  # Does a config eval to a buildable toplevel? NixOS's assertion plumbing throws
  # (catchable by tryEval) when any assertion is false, reading the message of
  # ONLY the failing assertions -- so a misconfig that trips one of this module's
  # assertions makes this false, while a passing sibling assertion's message is
  # never forced (the reason we check toplevel, not config.assertions directly).
  toplevelSucceeds = extra:
    (builtins.tryEval (builtins.seq (evalBanken extra).system.build.toplevel.drvPath true)).success;
  # positive control: a valid armed config DOES build (so a "fires" below is our
  # assertion, not some unrelated failure in this minimal eval).
  goodBuilds = toplevelSucceeds { response = { enable = true; enforce = true; policy = pol; }; };
  # response.enforce without response.enable, and an allowPaths entry under a
  # never-touch prefix, each trip a module assertion.
  enforceAssertFires = !(toplevelSucceeds { response = { enable = false; enforce = true; }; });
  allowPathsAssertFires = !(toplevelSucceeds { response = { enable = true; policy = pol; quarantine.allowPaths = [ "/usr/bad" ]; }; });

  moduleEvalOK =
    assert daemonIdentical;
    assert noHelperDefault;
    assert helperWhenArmed;
    assert goodBuilds;
    assert enforceAssertFires;
    assert allowPathsAssertFires;
    "daemon-identical, default-has-no-helper, armed-has-helper, assertions-fire";
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
    environment.systemPackages = with pkgs; [ curl python3 netcat-gnu procps gnutar audit nmap tcpdump openssl zip ];
    environment.etc."banken-emulations".source = ./emulations;
  };

  # The "# module-eval:" line forces moduleEvalOK at derivation-eval time, so a
  # broken split invariant fails the build before the VM starts.
  testScript = ''
    # module-eval: ${moduleEvalOK}
    import json

    expected = json.loads(${builtins.toJSON (builtins.toJSON expected)})

    machine.wait_for_unit("auditd.service")
    machine.wait_until_succeeds("auditctl -l | grep -q banken-exec")

    # The default posture (response off) renders NO response helper unit, and the
    # daemon holds only CAP_DAC_READ_SEARCH (the split never grows it). Runtime
    # confirmation of the §2.8 module-eval proofs above.
    machine.fail("systemctl cat banken-respond.service")
    machine.fail("systemctl cat banken-respond.path")
    daemon_caps = machine.succeed("systemctl show -p CapabilityBoundingSet --value banken.service").strip()
    assert set(daemon_caps.split()) == {"cap_dac_read_search"}, f"daemon caps = {daemon_caps!r}"

    # Drain boot-time events so the first emulation is judged alone.
    machine.succeed("systemctl start banken.service")

    def lines():
        out = machine.succeed("cat /var/log/banken/alerts-*.jsonl 2>/dev/null || true")
        return [l for l in out.splitlines() if l.strip()]

    # A login-style PATH so the emulations find tools in the system profile and the wrappers (sudo
    # lives there); runuser's bare PATH would miss them, as it does on the real distros.
    loginpath = "/run/wrappers/bin:/run/current-system/sw/bin:/usr/bin:/bin"

    failures = []
    for family in sorted(expected):
        before = len(lines())
        # runuser, not su/sudo: those would (rightly) fire privilege_escalation_attempt.
        out = machine.succeed(f"runuser -u alice -- env PATH={loginpath} bash /etc/banken-emulations/{family}.sh")
        # An emulation whose tool is not installable on this image prints a skip marker (e.g. no
        # nmap): skip that family rather than count a miss, exactly as the distro matrix does.
        if "BANKEN-EMUL-SKIP" in out:
            print(f"{family}: skipped ({out.strip().splitlines()[-1]})")
            continue
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
