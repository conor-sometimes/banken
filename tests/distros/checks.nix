# The detect checks, derived from the fixtures - the one place a rule's expected
# firing is declared (tests/fixtures/<family>.expect-<rule>.json), exactly as
# tests/vm.nix reads them. Each emulation in tests/emulations becomes a `detect`
# check whose `expect` is the sorted rule set its fixtures name. The matrix runs
# each under its own launcher and attributes banken's findings by process
# subtree, so the fired set must equal `expect`.
#
# Three classes of rule cannot be proven on a stock cloud image, so their
# families are dropped (each stays proven by the engine golden tests):
#   - account-scoped agent rules (rules/agent/): the emulations run with no
#     agent login, so the auid never matches the User branch;
#   - honeytoken_access: needs decoy files and audit watches that live only on a
#     containment host;
#   - the opt-in rules (netcat, password_cracker): off by default, so the
#     posture under test never loads them.
{ lib, emulationsDir, fixturesDir }:
let
  entries = builtins.readDir emulationsDir;
  families = map (n: lib.removeSuffix ".sh" n)
    (lib.filter (n: lib.hasSuffix ".sh" n && entries.${n} == "regular")
      (builtins.attrNames entries));

  fixtures = builtins.attrNames (builtins.readDir fixturesDir);
  rulesFor = family:
    lib.pipe fixtures [
      (lib.filter (f: lib.hasPrefix "${family}.expect-" f))
      (map (f: lib.removeSuffix ".json" (lib.removePrefix "${family}.expect-" f)))
      (lib.filter (r: r != "none"))
      lib.naturalSort
    ];

  undroppable = r:
    lib.hasPrefix "agent_" r || r == "honeytoken_access" || r == "netcat" || r == "password_cracker";
  keep = family: !(lib.any undroppable (rulesFor family));

  # Optional emulation tools: a distro whose repos lack one skips that family.
  toolsFor = family:
    if family == "portscan" || family == "netdiscovery" then { tools = [ "nmap" ]; optional = true; }
    else if family == "sniff" then { tools = [ "tcpdump" ]; optional = true; }
    else { };

  mkCheck = family: {
    name = family;
    value = {
      kind = "detect";
      run = emulationsDir + "/${family}.sh";
      as = "user";
      expect = rulesFor family;
    } // toolsFor family;
  };
in
lib.listToAttrs (map mkCheck (lib.filter keep families))
