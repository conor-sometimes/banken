# Scenario: New threat detected

> You read about a new attack on a security blog this morning. By lunch you want every host in the
> fleet detecting it -- without shipping a new banken binary.

This page walks an operator through that, command by command. It is the practical, user-facing twin of
the design in [docs/design/rule-refresh.md](design/rule-refresh.md); read that for how and why it works.

This is the first page under `docs/scenarios/`. banken had no scenario convention before, so this
directory is the home for task-shaped "I need to do X" walkthroughs; add siblings here as they come up.

Status note: runtime rule refresh is **implemented** -- `refreshDirs`, `banken reload`, `banken
status`, the resource guard and the NixOS puller (`services.banken.refresh`) all exist. The one piece
still landing is recording the pulled commit SHA in the status file and a scrapeable metrics endpoint;
those are called out inline where they appear.

## What you need once (setup)

- A git repo your team pushes rules to (the "fleet rules repo"). Lay it out like banken's own tree:
  one subdir per ATT&CK tactic (`credential-access/`, `persistence/`, ...), `malware/<family>/` for
  family signatures, `ioc/*.txt` for bulk indicators. See [writing rules](writing-rules.md).
- Each host clones that repo to `/var/lib/banken-rules` and lists it under `refreshDirs:` in
  `/etc/banken/banken.yml`, with a timer that pulls and reloads. On NixOS this is
  `services.banken.refresh.enable = true` with the repo URL; on other distros it is the packaged
  `banken-rules-pull.timer`. (Setup is covered in [deployment](deployment.md); here we assume it is
  already in place and focus on the daily loop.)

## The loop

### 1. Write the rule (on your laptop)

Clone of the fleet rules repo. The threat: a credential-dumping tool stages itself in shared memory
and reads `/etc/shadow`.

```sh
cat > credential-access/shadow_read_from_shm.yml <<'YAML'
title: Shadow read by a binary staged in shared memory
level: high
tags: [attack.credential-access, attack.t1003.008]
detection:
  stage:
    Image|startswith: /dev/shm/
  shadow:
    CommandLine|contains: /etc/shadow
  condition: stage and shadow
YAML
```

It is standard Sigma (banken's supported subset); [writing rules](writing-rules.md) has the exact
modifiers and worked examples.

### 2. Validate it compiles (exists today: `banken check`)

```sh
banken check .
```

This compiles every rule in the tree and reports any that fail, so a typo is caught now, on your
laptop, not on 500 hosts. A clean tree exits 0; a bad rule exits non-zero and names the file.

### 3. Prove it fires on the threat and stays quiet on benign activity (exists today)

```sh
banken check -image /dev/shm/.cache 'cat /etc/shadow'
#   -> [high]  shadow_read_from_shm  Shadow read by a binary staged in shared memory

banken check 'cat /etc/passwd'
#   -> no rules matched
```

`banken check` describes one event and prints which rules fire -- your fast feedback loop before you
commit. Tune the rule until the first command fires and the second does not.

### 4. Push it (signed)

```sh
git add credential-access/shadow_read_from_shm.yml
git commit -S -m "cred-access: detect /etc/shadow read by a /dev/shm staged binary"
git push
```

Sign the commit: on the fleet, write access to this repo means the power to change what every host
detects, so pushes are signed and reviewed like production code.

### 5. The fleet pulls and refreshes

Normally you do nothing here -- each host's timer pulls the repo and reloads banken within its interval
(a minute or a few). To push it out immediately, run the pull+reload across the fleet with your config
management, for example:

```sh
clush -g prod 'systemctl start banken-rules-pull.service'
```

What that unit does on each host (you can run the steps by hand on one host to understand it):

```sh
# pull the new rules into the host's checkout (this half has git + network;
# the banken daemon itself has neither, by design)
git -C /var/lib/banken-rules pull --ff-only
git -C /var/lib/banken-rules verify-commit HEAD      # reject an unsigned/untrusted HEAD

# preflight on the host, then refresh the RUNNING daemon -- no restart, no redeploy
banken check /var/lib/banken-rules && systemctl reload banken
#   (systemctl reload sends the daemon a refresh signal; it validates the whole
#    tree and swaps the rule set atomically. One bad rule is reported and skipped;
#    the daemon never drops its working rules and never goes ruleless.)
```

### 6. Confirm it is live on a host

```sh
banken status
#   last refresh: 2026-11-02T11:48:03Z  outcome: swapped  loaded: 214  failed: 0  indicators: 37
#   dirs: [/etc/banken/rules /var/lib/banken-rules]
#   (recording the pulled commit SHA here is the next addition)

banken check -image /dev/shm/.cache 'cat /etc/shadow'
#   -> the rule fires, compiled from the exact on-disk tree the daemon just loaded
```

Two confirmations: `banken status` shows the refresh swapped in and your rule is not in the failed
list; `banken check` against the host's tree proves the rule compiles and fires there. When the real
activity happens, the alert reaches your configured sink (journal / webhook / jsonl / OTLP) like any
other detection.

A fleet-wide dashboard of every host's loaded commit and last-refresh age is the planned next step,
once banken records the pulled commit and exposes a scrapeable metrics endpoint.

## If the rule turns out wrong

Revert it the same way it went out:

```sh
git revert 4f1c2ab && git push
```

Every host pulls the revert on its next tick and refreshes back to the good set. If a host's preflight
had caught a breakage, that host never swapped in the first place -- it kept its previous working rules
and logged the error (`journalctl -u banken -p err`).

## What this is not

- You are **not** rebuilding or redeploying the banken binary. The binary ships a baseline embedded;
  your fleet rules load on top of it at runtime.
- You are **not** editing rules on each host by hand. The git repo is the single source of truth; hosts
  pull it. Edit on your laptop, push, done.
- Changing *sources or sinks* (not rules) still needs a config change and a restart; only rules
  refresh live.
