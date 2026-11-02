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

    # --- the two-process split: the daemon writes orders, the helper drains ---
    #
    # After the split the enforcing scan is two hops: `systemctl start
    # banken.service` (the daemon, a synchronous oneshot) writes work orders to
    # /var/lib/banken/spool and exits; banken-respond.path then fires
    # banken-respond.service (the helper) on inotify, which RE-DECIDES each order
    # and acts. So a scan is not done when the daemon exits -- it is done when the
    # spool is empty AND the helper is no longer mid-run. enf_scan waits for that,
    # so the ledger reflects the completed actions before the test reads it.

    def _spool_drained():
        # spool empty (every order acted/downgraded/expired and unlinked) and the
        # helper oneshot not currently running.
        return machine.succeed(
            'if [ -z "$(ls -A /var/lib/banken/spool 2>/dev/null)" ] '
            '&& ! systemctl is-active --quiet banken-respond.service; '
            'then echo drained; else echo busy; fi'
        ).strip() == "drained"

    def enf_wait_drained():
        """Block until the spool is empty and the helper is idle."""
        machine.wait_until_succeeds(
            'test -z "$(ls -A /var/lib/banken/spool 2>/dev/null)" '
            '&& ! systemctl is-active --quiet banken-respond.service'
        )

    def enf_scan():
        """One enforcing cycle: daemon scan (writes orders) then helper drain."""
        machine.succeed("systemctl start banken.service")
        enf_wait_drained()

    _ENF_ORDER_SEQ = [0]

    def enf_order(order):
        """Write a hand-crafted work order into the spool as root (tmp + rename,
        like the daemon), returning its id. This forges the helper's one input
        directly, to exercise its own re-decision rails without needing an audit
        event (the order IS the forged input; §4.2). `order` is a dict matching
        the §2.3 shape; if it has no "id", a fresh time-ordered hex one is set."""
        import json as _json
        if not order.get("id"):
            _ENF_ORDER_SEQ[0] += 1
            # time-ordered-ish: ns timestamp + a sequence, hex, 24 chars.
            import time as _time
            order["id"] = f"{int(_time.time()*1e6):016x}{_ENF_ORDER_SEQ[0]:08x}"
        oid = order["id"]
        b64 = base64.b64encode(_json.dumps(order).encode()).decode()
        machine.succeed("mkdir -p /var/lib/banken/spool /var/lib/banken/spool.tmp")
        machine.succeed(f"printf %s {b64} | base64 -d > /var/lib/banken/spool.tmp/{oid}.json")
        machine.succeed(f"mv /var/lib/banken/spool.tmp/{oid}.json /var/lib/banken/spool/{oid}.json")
        return oid

    # ================= freeze-proof harness (docs section 4.1) =================
    # A heartbeat carrier, a process-tree victim, and the heartbeat read/stall
    # helpers that tests/response-freeze.nix needs. Appended self-contained so
    # they never touch enf_scan / enf_order / enf_spawn above (item 9 edits this
    # same file in parallel). They reuse _b64, _STAY and the launcher discipline
    # already defined above.

    # The heartbeat settle/window constants. settle_ms lets an in-flight `sleep`
    # that was mid-exit land its final append before the first size read;
    # window_ms is long enough that a running beat (every ~10 ms) grows the file
    # by many bytes, so "no growth over the window" means the tree is truly
    # stopped, not merely between ticks.
    HB_SETTLE_MS = 200
    HB_WINDOW_MS = 1000

    def _hb_file(name):
        return f"/tmp/hb_{name}"

    def hb_size(name):
        """Byte size of a victim's heartbeat file (0 if it does not exist)."""
        return int(machine.succeed(
            f"stat -c %s {_hb_file(name)} 2>/dev/null || echo 0"
        ).strip())

    def hb_stalled(name, settle_ms=HB_SETTLE_MS, window_ms=HB_WINDOW_MS):
        """True when the heartbeat file is NOT growing: let in-flight writes
        settle, read the size, wait the window, read again, compare. A frozen
        victim's file is static (-> True); a live one grows (-> False)."""
        machine.succeed(f"sleep {settle_ms / 1000.0}")
        before = hb_size(name)
        machine.succeed(f"sleep {window_ms / 1000.0}")
        after = hb_size(name)
        return after == before

    # The heartbeat stay-alive tail: append to the heartbeat file, fork a short
    # `sleep` and wait on it, forever. The file's growth is the ground truth for
    # "this process is making progress" -- frozen the instant the shell is. The
    # 10 ms sleep forks a child each tick: the fork-during-migration shape a
    # scope:tree freeze must catch.
    def _beat_tail(name):
        return f"while :; do echo . >> {_hb_file(name)}; sleep 0.01; done"

    def enf_beat(name, trigger="", user="alice"):
        """Spawn a heartbeat shell victim carrying `trigger` in its CommandLine
        (a CommandLine-only rule's marker) and then beating. Returns its pid.
        Same discipline as enf_spawn: the marker is read from a file and the
        launchers exec-replace, so no launcher process carries the marker."""
        hb = _hb_file(name)
        pidf = f"/tmp/enf_{name}.pid"
        trigf = f"/tmp/enf_{name}.trig"
        machine.succeed(f"rm -f {hb} {pidf}")
        body = (trigger + " ; " if trigger else "") + _beat_tail(name)
        machine.succeed(f"printf %s {_b64(body)} | base64 -d > {trigf}")
        machine.succeed(f"chmod 0644 {trigf}")
        boot = f'echo $$ > {pidf} ; exec bash -c "$(cat {trigf})"'
        pre = "" if user == "root" else f"runuser -u {user} -- "
        machine.succeed(
            f'( {pre}setsid bash -c "$(printf %s {_b64(boot)} | base64 -d)" >/dev/null 2>&1 & ) ; true'
        )
        machine.wait_for_file(pidf)
        pid = machine.succeed(f"cat {pidf}").strip()
        machine.succeed(f"kill -0 {pid}")
        machine.wait_until_succeeds(f"test -s {hb}")  # it is beating
        return pid

    def enf_tree(name, trigger="", beat=False, user="alice"):
        """Spawn a process-tree victim: a bash shell that first backgrounds a
        long-lived `sleep` child (recorded) and then either beats (beat=True) or
        sleeps. Returns (shell_pid, child_pid). The child's ppid is the shell, so
        targetSet(scope:tree) enumerates both and they share the shell's cgroup,
        so the cgroup freezer/kill catches the whole tree. The child is spawned
        BEFORE the trigger so a slow trigger cannot keep the child from being
        recorded."""
        hb = _hb_file(name)
        pidf = f"/tmp/enf_{name}.pid"
        childf = f"/tmp/enf_{name}.child"
        trigf = f"/tmp/enf_{name}.trig"
        machine.succeed(f"rm -f {hb} {pidf} {childf}")
        tail = _beat_tail(name) if beat else _STAY
        body = (f"sleep 1000000 & echo $! > {childf} ; "
                + (trigger + " ; " if trigger else "") + tail)
        machine.succeed(f"printf %s {_b64(body)} | base64 -d > {trigf}")
        machine.succeed(f"chmod 0644 {trigf}")
        boot = f'echo $$ > {pidf} ; exec bash -c "$(cat {trigf})"'
        pre = "" if user == "root" else f"runuser -u {user} -- "
        machine.succeed(
            f'( {pre}setsid bash -c "$(printf %s {_b64(boot)} | base64 -d)" >/dev/null 2>&1 & ) ; true'
        )
        machine.wait_for_file(pidf)
        machine.wait_for_file(childf)
        shell_pid = machine.succeed(f"cat {pidf}").strip()
        child_pid = machine.succeed(f"cat {childf}").strip()
        machine.succeed(f"kill -0 {shell_pid}")
        machine.succeed(f"kill -0 {child_pid}")
        if beat:
            machine.wait_until_succeeds(f"test -s {hb}")
        return shell_pid, child_pid
''
