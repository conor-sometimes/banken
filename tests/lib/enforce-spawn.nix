# Shared spawn harness for the enforcement VM tests (response-enforce.nix,
# response-whackamole.nix). Evaluates to a Python snippet prepended to a
# runNixOSTest testScript; it assumes `machine` is in scope.
#
# It launches a LIVE, long-running victim that carries exactly one rule's
# triggering argv and then sleeps, so the exact process the rule matched is
# still alive when banken acts. Two hard lessons are baked in:
#
#  1. abe's launcher-chain caveat: the triggering marker must be in the
#     victim's argv to be detected, but if it also sits in the launcher chain's
#     argv (runuser/setsid/the bootstrap bash) each launcher becomes a SECOND
#     process carrying the marker and the scorecard is no longer one-kill-per
#     case. So the bootstrap reads the marker from a file / passes it only to
#     the final exec, and EXEC-REPLACES into the victim (setsid + exec), so no
#     launcher process ever carries the marker.
#
#  2. bash exec-optimisation: `bash -c 'A; B; sleep N'` exec-REPLACES the shell
#     with `sleep` for the last command, so the victim's live exe becomes
#     coreutils and no longer matches the rule's recorded Image (the executor
#     then refuses the kill, ErrStaleTarget). A trailing no-op builtin (`; :`)
#     keeps `sleep` from being the last command, so the victim stays the shell
#     the rule matched. (This is why the pre-redesign harness was red on
#     bash 5.3p9.)
#
# A case is {name, carrier, ...}:
#   carrier "shell": {trigger}  - bash -c "<trigger>; sleep N; :"; the victim is
#                    a shell whose CommandLine carries the trigger (CommandLine-
#                    only rules). The trigger is read from a file so the
#                    launchers carry none of it.
#   carrier "image": {image, trigger?, dir?} - a copy of bash whose exe path
#                    ends in the tool name a rule keys on (Image|endswith), run
#                    as `<dir>/<image> -c "sleep N; :" <trigger tokens>`; the
#                    tokens land in CommandLine (as unused positional params) to
#                    satisfy the rule's CommandLine selection. dir defaults to
#                    /run/enf (a non-/tmp, non-daemon path so it does not itself
#                    trip exec_from_tmp / masquerading); set dir to /tmp/enf for
#                    exec_from_tmp or /run/enf/... (a literal "..." dir) for the
#                    masquerading dotdir branch.
#   carrier "python": {trigger} - a real interpreter kept alive by time.sleep;
#                    trigger is the full `python3 -c '...'` argv.
''
    import base64

    def _b64(s):
        return base64.b64encode(s.encode()).decode()

    # The stay-alive tail. The trailing ':' (a shell builtin) is deliberate: it
    # stops bash from exec-replacing itself with `sleep` (see header), so the
    # victim keeps the exe/argv the rule matched.
    _STAY = "sleep 100000 ; :"

    def _prepare_image(image, parentdir):
        machine.succeed(f"mkdir -p '{parentdir}'")
        machine.succeed(f"cp $(command -v bash) '{parentdir}/{image}' && chmod 0755 '{parentdir}/{image}'")

    def enf_spawn(case):
        """Spawn one live victim; return its recorded pid (a string)."""
        name = case["name"]
        user = case.get("user", "alice")
        pidf = f"/tmp/enf_{name}.pid"
        machine.succeed(f"rm -f {pidf}")
        carrier = case["carrier"]

        if carrier == "shell":
            trigf = f"/tmp/enf_{name}.trig"
            body = case["trigger"] + " ; " + _STAY
            machine.succeed(f"printf %s {_b64(body)} | base64 -d > {trigf}")
            machine.succeed(f"chmod 0644 {trigf}")
            # bootstrap carries NO marker (only $(cat file)); it exec-replaces
            # into the victim, whose argv is the file's contents.
            boot = f'echo $$ > {pidf} ; exec bash -c "$(cat {trigf})"'
        elif carrier == "python":
            boot = f'echo $$ > {pidf} ; exec {case["trigger"]}'
        else:  # image
            # A unique parent dir per case so reusing a tool name across cases
            # does not hit ETXTBSY copying over a still-running victim. The path
            # still ends in the tool name the rule keys on (Image|endswith).
            parentdir = case.get("dir", "/run/enf/" + name)
            image = case["image"]
            _prepare_image(image, parentdir)
            trig = case.get("trigger", "")
            boot = f'echo $$ > {pidf} ; exec {parentdir}/{image} -c "{_STAY}"'
            if trig:
                boot += " " + trig

        pre = "" if user == "root" else f"runuser -u {user} -- "
        # setsid + exec-replace: the launcher (runuser/setsid) never lingers as a
        # second process carrying the marker; the backgrounded subshell detaches
        # the victim past this command.
        machine.succeed(
            f'( {pre}setsid bash -c "$(printf %s {_b64(boot)} | base64 -d)" >/dev/null 2>&1 & ) ; true'
        )
        machine.wait_for_file(pidf)
        pid = machine.succeed(f"cat {pidf}").strip()
        machine.succeed(f"kill -0 {pid}")  # alive before the scan
        return pid

    def enf_alive(pid):
        return machine.succeed(
            f"kill -0 {pid} 2>/dev/null && echo yes || echo no"
        ).strip() == "yes"
''
