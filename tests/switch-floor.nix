# Reproduce the LIVE hokkaido config: services.banken.mimi.enable with the auditd floor left ON
# (audit.enable defaults true), unlike switch.nix which turns audit off to isolate mimi. This is a
# diagnostic harness for the deployed failure where step 4 saw no mimi-sourced reverse_shell alert:
# it dumps banken's own view of the stream (cursor, journal) and every alert for the port, so the
# break point is visible in the build log.
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
    import time
    machine.wait_for_unit("mimi.service")
    machine.wait_for_unit("banken.service")
    machine.wait_for_file("/var/log/mimi/events.jsonl")
    machine.wait_until_succeeds("test -s /var/log/mimi/events.jsonl")

    print("=== CURSOR ===\n" + machine.execute("ls -l /var/lib/banken/cursor.json.mimi 2>&1")[1])
    print("=== BANKEN.YML ===\n" + machine.execute("grep -iE 'mimi|type:|path:' /etc/banken/banken.yml 2>&1")[1])
    print("=== BANKEN JOURNAL (follow/stream/mimi/error) ===\n" +
          machine.execute("journalctl -u banken.service --no-pager | grep -iE 'follow|stream|mimi|error|scan' | tail -20")[1])

    port = "47123"
    machine.succeed(
        f"(runuser -u alice -- timeout 3 bash -c 'exec 3<>/dev/tcp/192.0.2.1/{port}' >/dev/null 2>&1 &) ; true"
    )
    time.sleep(12)

    print("=== MIMI CAPTURED THE EXEC? (port count in stream) ===\n" +
          machine.execute(f"grep -c {port} /var/log/mimi/events.jsonl")[1])
    print("=== ALERTS FOR THE PORT ===\n" +
          machine.execute(f"grep {port} /var/log/banken/alerts-*.jsonl 2>/dev/null | head -5")[1])
    print("=== BANKEN JOURNAL AFTER (capture-to-match / mimi / error) ===\n" +
          machine.execute("journalctl -u banken.service --no-pager | grep -iE 'capture to match|mimi|follow|error' | tail -20")[1])
    print("=== CURSOR AFTER ===\n" + machine.execute("cat /var/lib/banken/cursor.json.mimi 2>&1")[1])
  '';
}
