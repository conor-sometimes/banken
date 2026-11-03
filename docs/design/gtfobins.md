# GTFOBins as a Linux LOLBin detection source for banken

Status: research scope (2026-11-01). Decision doc for project:banken.coverage.attack.
Owner lane: banken.research. Feeds the Fable rule grind under the GTFOBins umbrella task
(c055d242). Docs only; no code in this PR.

GTFOBins is the de-facto Linux "living off the land binaries" (LOLBin) catalogue. A LOLBin is a
trusted system binary abused to do an attacker's work. It is the Unix analog of the Windows LOLBAS
project. This doc scopes it as an input to banken's Sigma rules:

- what the data looks like
- whether anything more authoritative exists
- what banken already detects
- whether to hand-write rules or generate them from GTFOBins data

The verdict up front. Hand-write a small set of high-value Sigma rules keyed on the *abuse shape*:

- a trusted binary spawning a shell
- a sudo breakout
- a pager/editor escape
- a file-write to a sensitive sink

Do not auto-generate rules or import GTFOBins as an IOC list. The entries are exploitation recipes
for legitimate binaries, so a name-match list would be almost pure false positives. Use GTFOBins as
a *checklist of abuse classes and a corpus of binary names*, not as a feed.

## 1. What GTFOBins is and its data shape

GTFOBins (https://gtfobins.github.io, repo GTFOBins/GTFOBins.github.io) is a curated list of Unix
binaries that can be abused to bypass local security restrictions. Each can do one or more of these:

- spawn shells
- read or write files outside the caller's rights
- transfer files
- load libraries
- escalate via SUID / sudo / capabilities

It is a Jekyll site, and the data is the repo.

The data shape, verified against master, 2026-11-01:

- **Per-binary entries** live in `_gtfobins/<name>`, one file per binary, named after the executable
  with **no extension** (e.g. `_gtfobins/find`, `_gtfobins/tar`). There are 478 binary entries at
  time of writing. The site's Markdown pages are generated from these. Do not scrape the rendered
  HTML; read the entries.
- Each entry is a **single pure-YAML document** (Jekyll front matter, delimited `---` ... `...`)
  with a top-level `functions:` map. Example, `_gtfobins/find`:

  ```yaml
  functions:
    file-read:
    - code: find /path/to/input-file -exec cat {} \;
      comment: ...
      contexts:
        sudo:
        suid:
        unprivileged:
    shell:
    - code: find . -exec /bin/sh \; -quit
      contexts:
        sudo:
        suid:
          code: find . -exec /bin/sh -p \; -quit
          shell: false
        unprivileged:
  ```

  So it is cleanly machine-consumable. `functions[<fn>]` is a list of examples, each with `code`, an
  optional `comment`, and a `contexts` map. Optional per-example fields include `version` (OS/binary
  requirement) and `description`.

- **Function vocabulary** is not free-form. It is registered in `_data/functions.yml`, which is also
  the authoritative abuse-class list and already carries a MITRE mapping per function:

  | function | meaning | GTFOBins `mitre:` |
  | --- | --- | --- |
  | `shell` | spawn an interactive system shell | T1059 |
  | `command` | run a non-interactive system command | T1059 |
  | `reverse-shell` | connect a shell back to a listener | T1059, T1071 |
  | `bind-shell` | bind a shell to a local port | T1059, T1071 |
  | `file-read` | read arbitrary local files | T1005 |
  | `file-write` | write arbitrary local files | T1565 |
  | `upload` | send local data out | T1041 |
  | `download` | pull remote data in | T1105 |
  | `library-load` | load a shared library (arbitrary code in-process) | T1574 |
  | `privilege-escalation` | set SUID / chown another executable | T1548 |
  | `inherit` | meta: inherit functions from another entry | - |

- **Contexts** are registered in `_data/contexts.yml`: `unprivileged`, `sudo`, `suid`,
  `capabilities`. A context on an example says *how* the abuse gains privilege:
  - via `sudo` (privileges not dropped)
  - via the SUID bit (effective privileges not dropped)
  - via file capabilities (kernel permission checks bypassed)

  The old flat tags people remember as "suid / sudo / capabilities functions" are now modelled as
  contexts under the real function.

- **License: GPL-3.0** (repo `license` = GPL-3.0). This matters for banken. We may *read* the
  catalogue to decide what to detect, and borrow binary names and abuse recipes as facts. But we do
  not vendor GTFOBins content verbatim into banken's MIT/own-license rule tree. Our rules are
  original Sigma we author. GTFOBins is the reference, not a bundled dependency. No copy of the repo
  ships in banken.

In summary: ~478 binaries, ~9 real abuse functions (+2 meta) and 4 contexts, cleanly structured
YAML, GPL-3.0. It is trivially parseable. The hard part is turning recipes into low-FP detections.

## 2. Is anything "more official" for Linux LOLBins?

No. There is no vendor-canonical Linux LOLBin list the way LOLBAS is the semi-canonical Windows one
(LOLBAS is directly referenced by CISA). The living-off-the-land family splits by platform, and each
platform has one community project that everyone cites:

- **Windows binaries/scripts/libraries:** LOLBAS (lolbas-project.github.io). Semi-canonical,
  CISA-referenced.
- **Linux / Unix binaries:** GTFOBins. This is the one. Treated as the Linux counterpart to
  LOLBAS across the literature; there is no competing authoritative set.
- **macOS:** LOOBins (not relevant to banken, Linux host EDR).
- **Drivers (kernel, mostly Windows):** LOLDrivers (magicsword.io). Driver hashes for vulnerable
  / malicious drivers. Windows-centric; **not relevant** to a Linux host EDR today (banken has
  no Windows driver surface). A distant future analog would be malicious-LKM hashes, but banken
  already has `kernel_module_load` for the behaviour, so a hash feed is not worth it now.
- **WADComs:** Windows/AD offensive command reference. **Not relevant** (no AD surface).
- **LOTS (Living Off Trusted Sites), lots-project.com:** legitimate domains abused for C2 /
  exfil / phishing (github.io, pastebin, discord CDN, etc.). This is a *network/domain* set, not
  a binary set. Marginally relevant to banken's command-and-control and collection lanes if we
  ever enrich on destination domains, but banken's process-telemetry core keys on binaries and
  argv, not domains, so LOTS is out of scope for this work.

So GTFOBins is the right and only authoritative Linux source. Its own `functions.yml` MITRE hints
are a useful starting point, but they are coarse, since everything shell-ish is T1059. banken should
map more precisely:

- **T1059 Command and Scripting Interpreter** (+ .004 Unix Shell, .006 Python, .007 JS). Covers
  `shell`, `command`, `reverse-shell` and `bind-shell` when a binary runs an interpreter / shell.
- **T1202 Indirect Command Execution.** The signature GTFOBins move: a trusted *non-shell* utility
  runs a command without the user invoking a shell directly (find `-exec`, awk `system()`, a pager
  `!cmd`, an editor `:!`). This is the technique that makes GTFOBins distinct from "someone ran
  bash", and banken has no rule framed this way yet.
- **T1218 System Binary Proxy Execution.** The Windows-canonical technique for LOLBAS. Its defined
  sub-techniques are Windows-specific (rundll32, mshta, regsvr32, msiexec, ...), so for Linux there
  is no clean sub-technique. We tag the parent **T1218** on "trusted binary proxies execution of a
  shell" to express the analogy, alongside T1059 / T1202.
- **T1548 Abuse Elevation Control Mechanism** (.001 SUID/SGID, .003 Sudo and Sudo Caching). Covers
  the `sudo` / `suid` / `capabilities` contexts. This is privilege escalation *through* a GTFOBin.
- **T1005 / T1565 / T1041 / T1105 / T1574.** file-read / file-write / upload / download /
  library-load, mapped as in the table above.

## 3. Overlap with what banken already detects

banken loads SigmaHQ Linux rules plus its own `rules/` tree. Several GTFOBins abuse classes are
already covered. New rules must add coverage, not duplicate. The current state, for banken's own
rules:

| GTFOBins abuse class | banken coverage today | status |
| --- | --- | --- |
| `reverse-shell` | `command-and-control/reverse_shell.yml` - bash `/dev/tcp`, python/perl/ruby/php sockets, `nc -e`, `socat EXEC/SYSTEM`, `mkfifo|nc` | COVERED (strong) |
| `bind-shell` | partly via `reverse_shell.yml` (`nc -e`, `socat ...EXEC`) and `optional/netcat.yml` | MOSTLY covered; pure bind without `-e` is a minor gap, low value |
| `download` + shell | `execution/pipe_to_shell.yml` (`curl|sh`, `base64 -d|sh`, proc-subst, eval) | COVERED |
| `download` / `upload` | `command-and-control/remote_file_copy.yml` (scp/rsync/sftp), `download_ip_to_tmp.yml` (HTTP fetch of IP to /tmp) | COVERED for the common transports |
| `file-read` (of secrets) | `credential-access/credential_file_read.yml` - reader list + **binary-agnostic** `TargetFilename` on shadow/ssh-keys/cloud creds | COVERED for sensitive paths (incl. GTFOBin readers like dd/base64 via file-access branch) |
| `library-load` | `privilege-escalation/ld_preload_hijack.yml` (LD_PRELOAD / LD_LIBRARY_PATH) | COVERED for the preload vector |
| `privilege-escalation` context (create SUID) | `privilege-escalation/setuid_bit_set.yml` (chmod u+s / 4xxx) | COVERED (creating the mechanism) |
| `sudo` context (policy) | `privilege-escalation/sudoers_modification.yml` (/etc/sudoers edits) | COVERED (rewriting the policy) |
| running sudo/su/pkexec | `privilege-escalation/privilege_escalation_attempt.yml` | COVERED (the escalation attempt itself) |
| kernel module (LKM) | `persistence/kernel_module_load.yml` | COVERED (adjacent to library-load) |

The gaps are the GTFOBins-signature classes with no banken rule keyed on the abuse shape:

- **`shell` / `command` via a trusted non-shell binary** (find/tar/awk/vim/less/zip/openssl/...
  spawning `/bin/sh`). This is *the* GTFOBins move and the core of the T1202/T1218 analogy.
  Nothing in `rules/` keys on "a trusted utility forked a shell". **Highest value.**
- **`sudo` + a GTFOBin breakout** (`sudo find ... -exec /bin/sh`, `sudo awk 'BEGIN{system(...)}'`).
  `privilege_escalation_attempt` sees `sudo` ran, but not the *shape* that `sudo <gtfobin>` with
  a shell-escape token is a root breakout. A targeted rule is higher-signal and lower-FP than
  flagging every sudo.
- **Pager / editor shell escape** (`less`/`more`/`man`/`vi`/`vim`/`ed` with `!cmd`, `:!`,
  `-c '!...'`, or `VISUAL`/`EDITOR` abuse). This is T1202 indirect execution, and it is not covered.
- **`command` via interpreter one-liner** run non-interactively (awk `system()/BEGIN`, perl `-e`,
  find `-exec <cmd>`) where the intent is to run a command, not a reverse shell (which
  `reverse_shell.yml` already catches). This partly overlaps, so scope carefully to avoid
  duplicating.
- **`file-write` to a sensitive sink via a GTFOBin** (find `-fprintf`, `dd of=`, `tee`, `vim -c w`
  writing authorized_keys / cron / a trusted binary / PAM). `sudoers_modification` covers the
  sudoers sink only. The general "trusted tool wrote a persistence/escalation sink" is a gap.

## 4. Recommendation: hand-write, do not generate

Hand-write a small, prioritized set of Sigma rules. Do not auto-generate from GTFOBins, and do not
import GTFOBins as an IOC / binary-name list.

Why not generate or IOC-list:

- Every GTFOBins binary is a *legitimate* tool. `tar`, `find`, `awk`, `vim`, `less`, `openssl`,
  `git`, `scp` and `python` run thousands of times a day on a normal host. A rule that fires on the
  binary name, or on the exact GTFOBins `code` string, is one of two things. It is either near-100%
  false positive, or so literal it is trivially evaded by reordering flags. GTFOBins `code` fields
  are teaching examples, not signatures.
- The detectable signal is the **abuse shape**, not the invocation:
  - a trusted binary *spawning a shell* (parent/child)
  - a *sudo* context wrapping a breakout token
  - a pager *escaping* to a command
  - a file-write landing in a *sensitive sink*

  These are a handful of patterns that cover most of the 478 binaries at once, because the binaries
  differ only in which flag triggers the same escape.
- So the leverage is two things GTFOBins gives us. One is the abuse-class checklist, which we already
  have from `functions.yml`. The other is the *list of binary names* per class, which we fold into
  allow/deny sets inside a few hand-written rules. That is a far smaller, more maintainable, lower-FP
  artifact than one rule per binary.

Here is how banken's event fields express each detection. The fields are `Image`, `CommandLine`,
`ParentImage` and `TargetFilename`, plus user/uid from the schema.

- **Trusted binary spawns a shell (flagship).** Key on the **parent/child** relationship, the one
  unambiguous signal. Fire when `ParentImage|endswith` is in a curated GTFOBins `shell`/`command`
  set (/find, /tar, /zip, /awk, /gawk, /vim, /nmap, /openssl, /git, /env, /nice, /tee-less tools,
  ...) AND `Image|endswith` one of /sh /bash /dash /zsh /ksh. This is low-FP because these utilities
  do not legitimately fork an interactive shell. Tag T1059.004 + T1202 + T1218.
- **Sudo GTFOBin breakout.** Fire when `CommandLine` starts with `sudo ` (or `Image|endswith:
  /sudo`) AND the argv names a GTFOBin AND carries an escape token (`-exec`, `!`, `:!`, `BEGIN{`,
  `system(`, `-c`). A cleaner alternative is to combine with the flagship by also firing when
  `ParentImage` is `sudo`'s child chain, but the argv form is directly expressible. Tag T1548.003.
- **Pager / editor escape.** Fire when `Image|endswith` /less /more /man /vi /vim /view /ed AND
  `CommandLine|re` matches an escape (`!`, `:!`, `:shell`, `-c ...!`). The parent/child form
  (ParentImage a pager, Image a shell) is already caught by the flagship. So this rule leans on argv
  for the cases launched non-interactively (`vim -c ':!/bin/sh'`). Tag T1059 + T1202.
- **Command via interpreter one-liner.** Fire when `Image|endswith` /awk /gawk /perl /python* AND
  `CommandLine|contains` the command-exec idiom (`BEGIN{system`, `system(`, `-e 'exec`, `-exec`),
  but **excluding** the reverse-shell idioms `reverse_shell.yml` owns (socket/connect). Scope it to
  avoid duplication and mark `level: medium`. Tag T1059 + T1202.
- **File-write to a sensitive sink.** Fire when `Image|endswith` a GTFOBins file-write tool (/dd
  /tee /find(-fprintf) /cp /vim) AND (`CommandLine|contains` OR `TargetFilename|contains`) a
  sensitive sink: `~/.ssh/authorized_keys`, `/etc/cron`, `/etc/pam.d/`, `/etc/ld.so.preload`, or a
  path under a trusted bin dir. Reuse the binary-agnostic `TargetFilename` pattern already proven in
  `credential_file_read` / `sudoers_modification`. Tag T1565.001 (+ the persistence technique of
  the sink). Keep it tightly scoped. This is the highest-FP class.

FP control is the whole game:

- anchor allow-lists to real system paths (as `credential_file_read` does with `/nix/store/*/bin`)
- prefer the parent/child signal over argv where possible
- set levels honestly (shell-spawn = high/critical, interpreter-command = medium)

Each rule carries a `falsepositives:` note naming the legitimate case (a build that runs
`find -exec`, an installer).

Cross-check every new rule against the pinned SigmaHQ Linux set before writing, so we add rather
than shadow an upstream rule. Note any upstream equivalent in `references:`.

## 5. Seeded rule tasks

Seeded into project:banken.coverage.attack, tag +research-seed. Each depends on the GTFOBins
umbrella (c055d242) for the Fable grind. There is one task per gap abuse class worth a rule. The
UUIDs are listed in the handback report. The classes already covered are intentionally not
re-seeded: reverse-shell, download-to-shell, remote copy, credential file-read, LD_PRELOAD,
setuid-bit, sudoers edit, sudo-attempt.
