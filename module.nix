# NixOS module: banken, a small host EDR. A systemd timer runs the one-shot
# scan every `interval`; each run reads the audit log since its saved cursor,
# matches the Sigma rules and IOC lists, and alerts.
#
#   imports = [ banken.nixosModules.default ];   # flake
#   imports = [ "${banken}/module.nix" ];        # or a pinned checkout
#   services.banken.enable = true;
#
# Every option maps onto banken's own YAML config (docs/deployment.md); the
# module writes that file to /etc/banken/banken.yml. The unit mirrors the
# portable packaging/systemd/banken.service (its hardening is canonical), plus
# no network at all unless the webhook is on. By default the module also turns
# on auditd with the rules banken needs, so `enable = true` is the whole setup.
{ config, options, lib, pkgs, ... }:

let
  cfg = config.services.banken;
  yaml = pkgs.formats.yaml { };

  # A live sensor (mimi or Sysmon-for-Linux) turns banken into a long-running daemon (--watch) that
  # follows the sensor's stream continuously instead of the one-shot timer; the floor logic below
  # keys off this.
  streamEnabled = cfg.mimi.enable || cfg.sysmon.enable;

  # The file banken tails for the sysmon source. On a journald-only host (no /var/log/syslog, the
  # NixOS default and RHEL/Fedora/Amazon) banken tails the journal->file bridge below; otherwise it
  # tails the syslog file Sysmon's events land in directly.
  sysmonSourcePath = if cfg.sysmon.fromJournal then cfg.sysmon.bridgePath else cfg.sysmon.logPath;

  # The fleet rules checkout is in refreshDirs when the puller is on, so the
  # daemon reads it live; it is a plain runtime path (a string), never a store
  # input, which is the whole point -- a rule change costs a git pull, not a
  # rebuild. Operator-supplied refreshDirs come first, the puller's dir last.
  refreshDirs = cfg.refreshDirs ++ lib.optional cfg.refresh.enable cfg.refresh.dir;

  # The response policy banken reads: the operator's own file if given, else the
  # inline policy rendered to /etc/banken/response-policy.yml, else none.
  responsePolicyPath =
    if cfg.response.policyFile != null then toString cfg.response.policyFile
    else if cfg.response.policy != "" then "/etc/banken/response-policy.yml"
    else "";

  settings = {
    rules = [ "/etc/banken/rules" ] ++ map (p: "${p}") cfg.extraRules; # interpolation copies the tree to the store
    inherit refreshDirs;
    optionalRules = cfg.optionalRules;
    observeRules = cfg.observeRules;
    statePath = "/var/lib/banken/cursor.json";
    # Refresh governance (the resource guard + baseline protection). These are
    # daemon-side knobs, independent of whether the puller is enabled; they also
    # apply to a one-shot run that reads a manually-managed refreshDir.
    refresh = {
      protectBaseline = cfg.refresh.protectBaseline;
      maxRules = cfg.refresh.maxRules;
      maxPatternBytes = cfg.refresh.maxPatternBytes;
    };
    # With a live sensor on, banken follows its stream as a source (added here so it needs no manual
    # sources entry): mimi's OCSF stream as a `mimi` source, and/or Sysmon-for-Linux as a `sysmon`
    # source tailing the syslog file or the journal bridge. The sensors themselves are brought up below.
    #
    # banken auto-detects the audit log only when `sources` is empty. Naming a sensor stream makes
    # the list non-empty, which would suppress that auto-detect and silently leave banken with no
    # auditd floor -- the opposite of the soft-dependency intent (a sensor adds to the floor, never
    # replaces it). So when a sensor is on and the operator gave no sources of their own, name the
    # audit log explicitly alongside the stream, keeping the floor.
    sources =
      cfg.sources
      ++ lib.optionals (streamEnabled && cfg.sources == [ ] && cfg.audit.enable) [
        { type = "auditd"; path = "/var/log/audit/audit.log"; }
      ]
      ++ lib.optional cfg.mimi.enable { type = "mimi"; path = cfg.mimi.streamPath; }
      ++ lib.optional cfg.sysmon.enable { type = "sysmon"; path = sysmonSourcePath; };
    alerts = {
      journal.enable = cfg.alerts.journal.enable;
      jsonl = {
        inherit (cfg.alerts.jsonl) enable dir retentionDays format;
      };
      webhook = {
        inherit (cfg.alerts.webhook) enable style url;
        urlFile = if cfg.alerts.webhook.urlFile == null then "" else toString cfg.alerts.webhook.urlFile;
      };
      otlp = {
        inherit (cfg.alerts.otlp) enable endpoint headers;
      };
    };
    # The response layer. enable off (the default) makes this inert: banken is
    # alert-only. enforce off (also the default, and kept off on every real
    # host) means the executor is a dry-run even when a policy decides an action.
    response = {
      inherit (cfg.response) enable enforce ledgerDir;
      policyFile = responsePolicyPath;
      spool.maxAge = cfg.response.spool.maxAge;
      # The sandbox the helper unit's ReadWritePaths is bounded to, rendered here
      # too so the drain can refuse at startup a policy whose quarantine.allowPaths
      # lies outside it (§2.4 -- the sandbox and the policy must agree). With
      # fileActions off this is the empty list, so the drain refuses ANY quarantine
      # entry at startup: a kill-only host never carries the file capabilities.
      quarantineAllowPaths = lib.optionals cfg.response.fileActions cfg.response.quarantine.allowPaths;
    };
  };

  # The helper (banken-respond) exists only when response enforcement is armed.
  # It is the ONLY unit holding the act capabilities (§2.1); the daemon holds
  # none after the split. Gating the units (and the cgroup-root tmpfiles rule)
  # on this one predicate keeps "armed" a single source of truth.
  responseHelper = cfg.response.enable && cfg.response.enforce;

  # The cgroup v2 root under which a freeze/tree-kill gets its own child cgroup
  # (the executor default; §2.1). The helper's ReadWritePaths carves it out of
  # the otherwise read-only /sys (ProtectSystem=strict), and a tmpfiles rule
  # pre-creates it so the carve-out resolves.
  responseCgroupRoot = "/sys/fs/cgroup/banken.quarantine";

  # The helper's capability set (§2.1). CAP_DAC_READ_SEARCH reads the policy and
  # ledger whatever their mode; CAP_KILL signals another uid's process via
  # pidfd; CAP_SYS_PTRACE reads /proc/<pid>/exe of another uid for the identity
  # rail. The three FILE capabilities (write a 0700 home on the rename path,
  # rename/fchmod another uid's file in a sticky dir, set/clear the immutable
  # bit) are dropped when response.fileActions is off, leaving a kill-only host
  # no immutable cap it never uses.
  responseFileCaps = [ "CAP_DAC_OVERRIDE" "CAP_FOWNER" "CAP_LINUX_IMMUTABLE" ];
  responseHelperCaps = [ "CAP_KILL" "CAP_SYS_PTRACE" "CAP_DAC_READ_SEARCH" ]
    ++ lib.optionals cfg.response.fileActions responseFileCaps;

  # Mirror of internal/response/policy.go's never-touch check, so a bad
  # quarantine.allowPaths fails at nixos-rebuild rather than at the helper's
  # first alert (the same prefixes, the same path-component match). item 3 adds
  # /dev with a /dev/shm carve-out to both sides at once.
  neverTouchPrefixes = [ "/nix/store" "/usr" "/bin" "/sbin" "/lib" "/lib64" "/etc" "/boot" "/proc" "/sys" "/run" ];
  underNeverTouch = p: lib.any (pfx: p == pfx || lib.hasPrefix "${pfx}/" p) neverTouchPrefixes;
  badAllowPaths = lib.filter (p: !(lib.hasPrefix "/" p) || underNeverTouch p) cfg.response.quarantine.allowPaths;

  # The fleet rules puller: the ONLY piece with git and the network. It pulls the
  # rules repo into the runtime checkout, optionally verifies the signed HEAD,
  # preflights the tree with `banken check` (non-zero on any bad rule), and --
  # only on success -- lets the reload unit SIGHUP the daemon. On any failure it
  # rolls the checkout back to the previous commit and exits non-zero, so a
  # broken or unverified push never reaches the running daemon. banken itself
  # stays network-free and git-free in its strict sandbox; this is deliberately a
  # separate, unprivileged identity (docs/design/rule-refresh.md sections 7, 8).
  pullScript = pkgs.writeShellScript "banken-rules-pull" ''
    set -euo pipefail
    dir=${lib.escapeShellArg cfg.refresh.dir}
    repo=${lib.escapeShellArg cfg.refresh.repo}
    git=${pkgs.git}/bin/git
    banken=${lib.getExe cfg.package}

    if [ -d "$dir/.git" ]; then
      old="$("$git" -C "$dir" rev-parse HEAD 2>/dev/null || true)"
      "$git" -C "$dir" fetch --prune --depth 1 origin
      "$git" -C "$dir" reset --hard FETCH_HEAD
    else
      old=""
      "$git" clone --depth 1 "$repo" "$dir"
    fi

    rollback() {
      if [ -n "$old" ]; then
        echo "banken-rules-pull: rolling back to $old" >&2
        "$git" -C "$dir" reset --hard "$old"
      fi
    }

    ${lib.optionalString cfg.refresh.verify ''
      if ! "$git" -C "$dir" verify-commit HEAD; then
        echo "banken-rules-pull: HEAD is not a verified signed commit; refusing refresh" >&2
        rollback
        exit 1
      fi
    ''}

    if ! "$banken" check "$dir"; then
      echo "banken-rules-pull: preflight failed; keeping the previous rules" >&2
      rollback
      exit 1
    fi
    echo "banken-rules-pull: refreshed $dir to $("$git" -C "$dir" rev-parse --short HEAD)"
  '';
in
{
  options.services.banken = {
    enable = lib.mkEnableOption "banken, a host EDR over the audit log";

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.callPackage ./package.nix { };
      defaultText = lib.literalExpression "pkgs.callPackage ./package.nix { }";
      description = "The banken package (the baseline rules are embedded in the binary).";
    };

    interval = lib.mkOption {
      type = lib.types.str;
      default = "2min";
      example = "30s";
      description = "How often the timer runs a scan (systemd time span).";
    };

    sources = lib.mkOption {
      type = lib.types.listOf (lib.types.submodule {
        options = {
          type = lib.mkOption {
            type = lib.types.enum [ "laurel" "auditd" "generic" "mimi" "sysmon" ];
            description = "Parser for this log.";
          };
          path = lib.mkOption {
            type = lib.types.str;
            description = "The log file to read.";
          };
        };
      });
      default = [ ];
      example = [{ type = "auditd"; path = "/var/log/audit/audit.log"; }];
      description = ''
        Logs to scan. Empty means auto-detect: Laurel's JSON log if present,
        else the raw audit log.
      '';
    };

    extraRules = lib.mkOption {
      type = lib.types.listOf lib.types.path;
      default = [ ];
      example = lib.literalExpression "[ ./rules ]";
      description = ''
        Extra rule trees (Sigma .yml and ioc/ lists), loaded after the
        embedded baseline and /etc/banken/rules. Each path is a directory
        copied into the Nix store; point it at your own rules dir.
      '';
    };

    refreshDirs = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "/var/lib/banken-rules" ];
      description = ''
        Runtime-refreshable rule directories. Unlike extraRules these are plain
        on-disk paths (strings), NOT copied into the Nix store, so a rule change
        there needs no rebuild: the daemon re-reads them on a reload (SIGHUP /
        `banken reload`), and a one-shot run reads them on its next scan. They
        load at the highest precedence (above the baseline and extraRules). Point
        this at an externally-managed or cloned rules dir; set
        services.banken.refresh to have the module clone and pull one for you.
      '';
    };

    refresh = {
      enable = lib.mkEnableOption ''
        the fleet rules puller: a separate, unprivileged systemd timer that git-pulls a rules repo
        into `dir` (a runtime path, never the store), verifies and preflights it, and reloads the
        running daemon with no binary redeploy. `dir` is added to refreshDirs automatically. The
        puller is the ONLY component with git and the network; the banken daemon stays network-free
        in its sandbox and only reads the checkout
      '';
      repo = lib.mkOption {
        type = lib.types.str;
        default = "";
        example = "https://github.com/your-org/banken-rules.git";
        description = ''
          Git URL of the fleet rules repo the puller clones and pulls. A private repo needs
          credentials the operator provides to the banken-rules-pull.service (e.g. a deploy key via
          a systemd credential and GIT_SSH_COMMAND); the module does not embed secrets.
        '';
      };
      dir = lib.mkOption {
        type = lib.types.str;
        default = "/var/lib/banken-rules";
        description = ''
          The on-disk checkout path. Owned by the dedicated `banken-rules` puller user and
          world-readable; the banken daemon (root) only reads it. Added to refreshDirs when
          refresh.enable is set. NOT copied into the Nix store.
        '';
      };
      interval = lib.mkOption {
        type = lib.types.str;
        default = "5min";
        example = "1min";
        description = "How often the puller pulls + preflights + reloads (systemd time span).";
      };
      verify = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = ''
          Require a verified signed HEAD (`git verify-commit HEAD`) before accepting a refresh; a
          failed verification rolls the checkout back and refuses the reload. The design's fleet
          default is on, but it needs git commit signing and an allowed-signers / GPG keyring set up
          for the puller user, so it defaults OFF here -- turn it on once provenance keys are wired,
          and treat the rules repo's push access as production access regardless (section 8).
        '';
      };
      protectBaseline = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = ''
          Forbid an on-disk rule from overriding an embedded-baseline rule by filename: the override
          is refused (baseline kept) and logged, so a pushed rule cannot silently shadow and weaken a
          baseline detection. Overrides are always audited to the journal and the refresh status file
          whether or not this is set; this makes them a hard error. Applies to every refreshDir, not
          only the puller's.
        '';
      };
      maxRules = lib.mkOption {
        type = lib.types.ints.unsigned;
        default = 50000;
        description = ''
          Resource guard: the maximum rules a refresh may load. A tree over the cap is a whole-set
          failure (the old set is kept), so a pathological or hostile push cannot exhaust memory or
          blind the host. Generous by default.
        '';
      };
      maxPatternBytes = lib.mkOption {
        type = lib.types.ints.unsigned;
        default = 8388608; # 8 MiB
        description = ''
          Resource guard: the maximum total bytes of literal match patterns across a refresh, with
          the same whole-set-failure semantics as maxRules. Bounds the matcher build a refresh does.
        '';
      };
    };

    optionalRules = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "netcat" "password_cracker" ];
      description = ''
        Opt-in (optional) rules to activate, by rule name, or "*" for all of
        them. Optional rules ship in the binary but are held back by default
        because they are noisy or environment-specific (netcat use, a password
        cracker); name here the ones this host wants. A name that matches no
        optional rule is warned about at startup (a mis-typed enable is a
        detection that silently is not running).
      '';
    };

    observeRules = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "netcat" ];
      description = ''
        Optional rules to run in observe mode, by rule name, or "*" for all.
        They evaluate and their hits are recorded (jsonl, run summary) but
        marked "observed" so the paging sinks (journal, webhook) skip them --
        a way to measure how noisy a rule would be on this host before letting
        it page. A rule named in both optionalRules and observeRules pages (the
        explicit enable wins).
      '';
    };

    mimi = {
      enable = lib.mkEnableOption ''
        the mimi eBPF sensor as a live telemetry source. A SOFT dependency: it brings up
        services.mimi (so mimi's NixOS module must be imported too), points banken at mimi's OCSF
        event stream, and orders banken after it -- but Wants, not Requires, so if mimi dies banken
        keeps running on the auditd floor. banken alone (this off) stays the floor: mimi adds richer
        exec telemetry (the executable path, uid/gid, the full ancestry), it does not replace auditd
      '';
      streamPath = lib.mkOption {
        type = lib.types.str;
        default = "/var/log/mimi/events.jsonl";
        description = ''
          Where mimi writes its OCSF event stream and banken tails it (a `mimi` source). A durable
          file, so a banken restart never loses events; banken's cursor resumes. With the sensor on,
          banken runs as a daemon (--watch) and follows this file continuously (inotify), so an
          event reaches the rules as it lands rather than on the next timer tick.
        '';
      };
    };

    sysmon = {
      enable = lib.mkEnableOption ''
        Microsoft Sysmon-for-Linux as a live telemetry source. Like mimi it is additive: banken
        follows Sysmon's event stream as a `sysmon` source and keeps the auditd floor underneath, so
        Sysmon dying never takes banken down. Sysmon maps its ProcessCreate/network/file events onto
        the SAME field names the large body of Windows Sysmon Sigma rules already key on, so enabling
        it lights up those rules on Linux.

        This module does NOT install Sysmon: Microsoft's sysmonforlinux is an EULA binary, not in
        nixpkgs, and needs root + eBPF + kernel BTF. The operator installs and configures it (with a
        Sysmon config that logs at least ProcessCreate); this switch only points banken at the events
        it produces and, on a journald-only host, bridges them to a file banken can tail
      '';
      fromJournal = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = ''
          Read Sysmon's events from the systemd journal rather than a syslog file. This is the right
          setting on a journald-only host -- the NixOS default, and RHEL/Rocky/Alma/Fedora/Amazon
          Linux -- where there is no /var/log/syslog and Sysmon logs to the journal under the syslog
          identifier `journalIdentifier`. A tiny `journalctl -f -o cat -t <identifier>` service
          (banken-sysmon-journal, below) appends those entries to `bridgePath`, which banken tails
          with its normal file path (cursor, rotation, inotify follow) -- no journal client or cgo in
          banken itself. Set false on Debian/Ubuntu/openSUSE, where Sysmon's events already land in
          `logPath` (/var/log/syslog) and banken tails that file directly, skipping the other lines
          sharing it.
        '';
      };
      journalIdentifier = lib.mkOption {
        type = lib.types.str;
        default = "sysmon";
        description = ''
          The journal SYSLOG_IDENTIFIER Sysmon-for-Linux logs under (used only when fromJournal).
          journalctl filters to this identifier so the bridge file carries Sysmon events only.
        '';
      };
      bridgePath = lib.mkOption {
        type = lib.types.str;
        default = "/var/log/banken-sysmon/sysmon.log";
        description = ''
          Where the journal bridge writes Sysmon events and banken tails them (a `sysmon` source),
          used only when fromJournal. The bridge owns this file; banken (root) reads it.
        '';
      };
      logPath = lib.mkOption {
        type = lib.types.str;
        default = "/var/log/syslog";
        description = ''
          The syslog file Sysmon's events land in, tailed directly when fromJournal is false
          (Debian/Ubuntu/openSUSE). banken skips the non-Sysmon lines sharing the file.
        '';
      };
    };

    audit = {
      enable = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = ''
          Turn on auditd and the audit rules banken reads: every execve (64-
          and 32-bit) and a read/write watch on each of audit.watchPaths. Off
          if the host's audit rules are managed elsewhere.
        '';
      };
      watchPaths = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [ "/etc/shadow" "/etc/gshadow" ];
        description = ''
          Files whose access is audited, so a credential read shows up whatever
          program does it (the binary-agnostic branch of credential_file_read).
          Keep it to files: a watch on a busy directory such as /home floods
          the log. Each path's parent directory must exist when the audit
          rules load: NixOS loads them in one go (auditctl -R), and a single
          failing watch leaves the host with no audit rules at all. A missing
          file is fine; a missing directory is not.
        '';
      };
    };

    alerts = {
      journal.enable = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = "Log high and critical alerts to the journal.";
      };

      jsonl = {
        enable = lib.mkEnableOption "the jsonl sink (one file of alerts per day)";
        dir = lib.mkOption {
          type = lib.types.str;
          default = "/var/log/banken";
          description = "Directory for alerts-YYYY-MM-DD.jsonl.";
        };
        retentionDays = lib.mkOption {
          type = lib.types.ints.unsigned;
          default = 30;
          description = "Days of alert files to keep (0 = forever).";
        };
        format = lib.mkOption {
          type = lib.types.enum [ "banken" "ocsf" "ecs" ];
          default = "banken";
          example = "ocsf";
          description = ''
            Encoding for each line: "banken" (the native JSON shape), "ocsf"
            (OCSF 1.3.0 Detection Findings, for an OCSF-aware SIEM such as
            Security Lake, Splunk or Datadog), or "ecs" (Elastic Common Schema,
            for Elasticsearch/Kibana). One finding per line either way; this
            only changes the field names, not the file or retention.
          '';
        };
      };

      webhook = {
        enable = lib.mkEnableOption "the webhook sink";
        urlFile = lib.mkOption {
          type = lib.types.nullOr lib.types.path;
          default = null;
          example = "/run/secrets/banken-webhook";
          description = ''
            File holding the webhook URL (a secret: sops-nix, agenix or a
            systemd credential). Never put the URL itself in the Nix store.
          '';
        };
        url = lib.mkOption {
          type = lib.types.str;
          default = "";
          example = "https://example.com/ingest";
          description = ''
            The webhook URL inline, used only when urlFile is unset. Most webhook URLs embed a secret
            token (Slack, Discord) and MUST use urlFile instead -- a URL set here lands in the
            world-readable Nix store. Use this only for a genuinely non-secret receiver.
          '';
        };
        style = lib.mkOption {
          type = lib.types.enum [ "generic" "slack" "discord" "ntfy" "ocsf" ];
          default = "generic";
          description = "Body shape for the receiver.";
        };
      };

      otlp = {
        enable = lib.mkEnableOption "the OTLP/HTTP log exporter (findings to an OpenTelemetry collector)";
        endpoint = lib.mkOption {
          type = lib.types.str;
          default = "";
          example = "http://collector:4318/v1/logs";
          description = ''
            The collector's OTLP/HTTP logs URL. OCSF is banken's schema, OTLP the pipe: any OTel
            backend (Grafana, Datadog, Splunk, Elastic) then ingests the findings with no glue.
          '';
        };
        headers = lib.mkOption {
          type = lib.types.attrsOf lib.types.str;
          default = { };
          example = {
            Authorization = "Bearer REDACTED";
          };
          description = ''
            Optional request headers, such as auth for a hosted collector. A real secret belongs in a
            systemd credential the operator wires in, not in the Nix store.
          '';
        };
      };
    };

    response = {
      enable = lib.mkEnableOption ''
        the response-action layer: banken decides an action (freeze/kill/quarantine/collect) per the
        policy for each alert and records it to an append-only ledger. Enabling this alone changes
        NOTHING destructive -- the executor stays a dry-run (it records what it WOULD do and touches
        no process or file) until `response.enforce` is also set. See docs/design/response-actions.md
      '';

      enforce = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = ''
          ARM REAL ENFORCEMENT. When true, banken's executor performs real actions -- it sends a real
          SIGKILL, freezes a real cgroup, renames a real file -- for any action the policy decides in
          enforce mode. This is OFF BY DEFAULT and MUST stay off on any host you are not willing to
          have banken kill processes on: it is a live response weapon, gated behind this one switch
          plus the policy's own `mode: enforce` and its safety rails (minLevel, enforceSources, the
          built-in denylist, the kill-switch file, rate limits). It exists so a throwaway KVM VM test
          can prove enforcement end to end; the hokkaido host and every real deployment leave it false
          and run observe/dry-run. Turning it on also relaxes the scan unit's sandbox exactly as much
          as the executor needs (CAP_KILL and process visibility), which is itself a reason to keep it
          off unless you mean it.
        '';
      };

      policyFile = lib.mkOption {
        type = lib.types.nullOr lib.types.path;
        default = null;
        description = ''
          Path to the response policy YAML (the `response:` block shape in docs/design/response-actions.md:
          mode, minLevel, enforceSources, denylist, rateLimit, and the ordered `actions:` mapping of
          rule/tag to action). Used when set; otherwise `response.policy` (inline) is rendered to
          /etc/banken/response-policy.yml. One of the two is required when `response.enable` is set.
        '';
      };

      policy = lib.mkOption {
        type = lib.types.lines;
        default = "";
        example = ''
          mode: observe
          minLevel: high
          enforceSources: [auditd, laurel]
          actions:
            - name: freeze-reverse-shell
              rules: [reverse_shell]
              action: freeze
              scope: tree
        '';
        description = ''
          The response policy YAML inline, rendered to /etc/banken/response-policy.yml. Used only when
          `response.policyFile` is unset. Default mode in the policy is observe, so even with
          `response.enforce` armed nothing acts until the policy itself opts a rule into an action in
          enforce mode.
        '';
      };

      ledgerDir = lib.mkOption {
        type = lib.types.str;
        default = "/var/lib/banken/response";
        description = ''
          Where the append-only decision/action ledger is written (one decisions-<day>.jsonl and, when
          an action is taken, one actions-<day>.jsonl per day). Kept forever by default: these lines
          are the chain of custody for "why did banken touch this process".
        '';
      };

      fileActions = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = ''
          Let an armed host quarantine files (the doc's default behaviour). When false, the helper unit
          drops the three file capabilities (CAP_DAC_OVERRIDE, CAP_FOWNER, CAP_LINUX_IMMUTABLE) and the
          quarantine.allowPaths ReadWritePaths, and quarantineAllowPaths is rendered empty so the drain
          refuses a quarantine entry at startup -- a kill-only host never carries the immutable cap it
          would never use. Has no effect unless response.enforce is also set.
        '';
      };

      spool.maxAge = lib.mkOption {
        type = lib.types.str;
        default = "10m";
        example = "5m";
        description = ''
          How long a work order may sit in the spool before the drain expires it unacted (a kill
          landing later than this is one the operator did not expect). A systemd/Go duration string.
          Five default 2 min scans by default. Rendered to banken.yml response.spool.maxAge.
        '';
      };

      quarantine.allowPaths = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [ "/tmp" "/var/tmp" "/dev/shm" "/home" "/root" "/opt" ];
        description = ''
          The directories a quarantine action may move or neuter a file in. Rendered BOTH into the
          helper unit's ReadWritePaths (the sandbox) AND into banken.yml response.quarantineAllowPaths,
          so the drain refuses at startup a policy whose allowPaths lie outside this list rather than
          failing with EROFS at the first alert (the silent-disarm failure, §2.4). Every entry must be
          absolute and not under a never-touch prefix (/etc, /usr, /bin, /sbin, /lib, /boot, /sys,
          /proc, /dev except /dev/shm). Ignored when response.fileActions is off.
        '';
      };
    };
  };

  config = lib.mkIf cfg.enable (
    {
    assertions = [{
      assertion = cfg.alerts.webhook.enable -> (cfg.alerts.webhook.urlFile != null || cfg.alerts.webhook.url != "");
      message = "services.banken.alerts.webhook.enable needs alerts.webhook.urlFile (a secret URL) or alerts.webhook.url (a non-secret one).";
    } {
      assertion = cfg.alerts.otlp.enable -> cfg.alerts.otlp.endpoint != "";
      message = "services.banken.alerts.otlp.enable needs alerts.otlp.endpoint.";
    } {
      assertion = cfg.refresh.enable -> cfg.refresh.repo != "";
      message = "services.banken.refresh.enable needs refresh.repo (the fleet rules repo URL to pull).";
    } {
      assertion = cfg.response.enable -> (cfg.response.policyFile != null || cfg.response.policy != "");
      message = "services.banken.response.enable needs response.policyFile or response.policy (the response policy YAML).";
    } {
      assertion = cfg.response.enforce -> cfg.response.enable;
      message = "services.banken.response.enforce needs response.enable: the banken-respond helper only exists when the responder does.";
    } {
      assertion = !(cfg.response.enable && cfg.response.fileActions) || badAllowPaths == [ ];
      message = "services.banken.response.quarantine.allowPaths has entries that are not absolute or lie under a never-touch prefix (/etc, /usr, /sys, /nix/store, ...): ${toString badAllowPaths}. The drain refuses such a policy at startup, so the module refuses it here.";
    }];

    environment.systemPackages = [ cfg.package ];
    environment.etc."banken/banken.yml".source = yaml.generate "banken.yml" settings;
    # Render the inline response policy when one is given and no file was named.
    environment.etc."banken/response-policy.yml" = lib.mkIf
      (cfg.response.enable && cfg.response.policyFile == null && cfg.response.policy != "")
      { text = cfg.response.policy; };

    security.auditd.enable = lib.mkIf cfg.audit.enable true;
    security.audit = lib.mkIf cfg.audit.enable {
      enable = lib.mkDefault true;
      rules = [
        "-a always,exit -F arch=b64 -S execve,execveat -k banken-exec"
        "-a always,exit -F arch=b32 -S execve -k banken-exec"
      ] ++ map (p: "-w ${p} -p rwa -k banken-watch") cfg.audit.watchPaths;
    };

    # The one switch (services.banken.mimi.enable) brings up services.mimi; its definition lives in
    # the conditional merge at the END of config, not here. When the sensor is off, banken is used
    # standalone WITHOUT mimi's module imported, so the `services.mimi` option does not exist -- and a
    # bare `services.mimi = ...`, even under mkIf-false, still references that absent option and fails
    # to evaluate. A separate `mkIf cfg.mimi.enable { ... }` module is dropped whole when off, so
    # banken alone never touches it. (With the sensor on, the operator imports mimi's module.)

    systemd.services.banken = {
      description = "banken host EDR scan";
      documentation = [ "https://github.com/conor-sometimes/banken" ];
      # Soft dependency on each sensor when it is on: order after it and want it, never require it,
      # so a sensor failure degrades banken to the auditd floor rather than taking it down. Sysmon is
      # operator-installed and not managed here, so banken only ORDERS after sysmon.service (harmless
      # if that unit is absent) and never Wants it; the journal bridge, which banken does own on a
      # journald-only host, it both wants and orders after (banken needs the bridge file being fed).
      after = [ "auditd.service" ]
        ++ lib.optional cfg.mimi.enable "mimi.service"
        ++ lib.optional cfg.sysmon.enable "sysmon.service"
        ++ lib.optional (cfg.sysmon.enable && cfg.sysmon.fromJournal) "banken-sysmon-journal.service";
      wants = [ "auditd.service" ]
        ++ lib.optional cfg.mimi.enable "mimi.service"
        ++ lib.optional (cfg.sysmon.enable && cfg.sysmon.fromJournal) "banken-sysmon-journal.service";
      # The daemon (a sensor on) starts at boot; the one-shot (no sensor) is started by the timer.
      wantedBy = lib.mkIf streamEnabled [ "multi-user.target" ];
      serviceConfig = {
        # With a sensor on, banken runs as a long-running daemon (--watch): it follows each sensor
        # stream (mimi, sysmon) continuously and scans the auditd floor on banken's own interval, one
        # process, one alert path. Without it, the one-shot + timer below is the floor. Only the
        # daemon restarts on failure (the one-shot is driven by the timer). (--watch uses banken's
        # built-in scan interval for the floor; services.banken.interval drives the timer, no-sensor.)
        Type = if streamEnabled then "exec" else "oneshot";
        ExecStart = "${lib.getExe cfg.package}${lib.optionalString streamEnabled " --watch"} -config /etc/banken/banken.yml";
        # `systemctl reload banken` refreshes the rule set live (validate-all-then-swap in the
        # daemon). Only the long-running daemon can be reloaded; the one-shot timer model has nothing
        # to SIGHUP, so a refresh there is just the next scan reading the new dir (no reload unit).
        ExecReload = lib.mkIf streamEnabled "${pkgs.coreutils}/bin/kill -HUP $MAINPID";
        Restart = lib.mkIf streamEnabled "on-failure";
        RestartSec = lib.mkIf streamEnabled 2;
        StateDirectory = "banken";
        StateDirectoryMode = "0700";
        LogsDirectory = lib.mkIf (cfg.alerts.jsonl.enable && cfg.alerts.jsonl.dir == "/var/log/banken") "banken";

        # An attacker who floods the box to trip the OOM killer must not reap
        # the watchdog (see the portable unit for why there is no MemoryMax).
        OOMScoreAdjust = -900;

        # Root, because the audit log is root's; every other power is taken
        # away. CAP_DAC_READ_SEARCH reads a log another user owns (Laurel's is
        # _laurel:_laurel 0640). After the two-process split the daemon NEVER
        # grows this set: it only decides and writes a work order, and the act
        # capabilities (CAP_KILL, CAP_SYS_PTRACE and the file caps) live solely
        # in banken-respond.service. So this unit is byte-identical whether or
        # not enforcement is armed -- the point of the split, asserted by the
        # module-eval check in tests/vm.nix. See docs/design/response-architecture.md §2.1.
        CapabilityBoundingSet = [ "CAP_DAC_READ_SEARCH" ];
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        # The response ledger defaults to <StateDirectory>/response, which is
        # already writable; a ledgerDir set OUTSIDE /var/lib/banken is added to
        # the writable set (StateDirectory covers the default, so this is empty
        # in the common case).
        ReadWritePaths = (lib.optional cfg.alerts.jsonl.enable cfg.alerts.jsonl.dir)
          ++ lib.optional
            (cfg.response.enable && !(lib.hasPrefix "/var/lib/banken" cfg.response.ledgerDir))
            cfg.response.ledgerDir;
        ProtectHome = true;
        PrivateTmp = true;
        PrivateDevices = true;
        # The webhook and OTLP sinks are the only egress; without them banken needs no network.
        PrivateNetwork = !(cfg.alerts.webhook.enable || cfg.alerts.otlp.enable);
        RestrictAddressFamilies = [ "AF_UNIX" ] ++ lib.optionals (cfg.alerts.webhook.enable || cfg.alerts.otlp.enable) [ "AF_INET" "AF_INET6" ];
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectKernelLogs = true;
        ProtectControlGroups = true;
        ProtectClock = true;
        ProtectHostname = true;
        # invisible hides other users' processes from the daemon. Before the split
        # an armed in-process executor had to flip this to "default" to read its
        # target's /proc; after the split the daemon never reads another process's
        # /proc (the helper does), so it stays invisible unconditionally.
        ProtectProc = "invisible";
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        SystemCallArchitectures = "native";
        # The daemon never signals or pins a process after the split, so it no
        # longer needs the pidfd syscalls; they moved to the helper's filter. This
        # list is now the same whether or not enforcement is armed.
        SystemCallFilter = [ "@system-service" ];
        SystemCallErrorNumber = "EPERM";
        UMask = "0077";
      };
    };

    # --- the response helper: banken-respond.{service,path} (the two-process split) ---
    #
    # The ONLY unit that holds the act capabilities (§2.1). It runs `banken
    # respond drain`: it reads work orders the daemon wrote to the spool,
    # RE-DECIDES each from its own copy of the policy on disk, re-checks the live
    # target, and acts -- so a compromised daemon's only lever is a JSON file
    # that is re-judged under rails it does not control. Exists only when
    # enforcement is armed (responseHelper); a non-armed host has neither unit.
    #
    # The path unit fires the oneshot on inotify when an order lands
    # (DirectoryNotEmpty), MakeDirectory pre-creates the 0700 spool dir. No
    # ordering between the two units is needed: the daemon writes orders whether
    # or not the helper is up, and the path unit catches up when it is.
    systemd.paths.banken-respond = lib.mkIf responseHelper {
      description = "Fire banken-respond when a response work order lands in the spool";
      documentation = [ "https://github.com/conor-sometimes/banken" ];
      wantedBy = [ "multi-user.target" ];
      pathConfig = {
        DirectoryNotEmpty = "/var/lib/banken/spool";
        MakeDirectory = true;
        DirectoryMode = "0700";
      };
    };

    systemd.services.banken-respond = lib.mkIf responseHelper {
      description = "banken response helper (re-decides and executes work orders)";
      documentation = [ "https://github.com/conor-sometimes/banken" ];
      # Ordering only (the helper has no sensor dependency): a drain reads the
      # audit log's /proc targets, not the log, so it needs auditd present but
      # does not wait on events. Never wantedBy: the path unit starts it.
      after = [ "auditd.service" ];
      # A drain that fails five times in a minute (unreadable policy, an order it
      # cannot unlink) stops being retried until an operator looks; the number is
      # the systemd default shape, in the unit so the journal names the limit.
      unitConfig = {
        StartLimitIntervalSec = 60;
        StartLimitBurst = 5;
      };
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${lib.getExe cfg.package} respond drain -config /etc/banken/banken.yml";
        StateDirectory = "banken";
        StateDirectoryMode = "0700";

        OOMScoreAdjust = -900;

        # The act capability set (§2.1). This unit is the sole holder; the daemon
        # holds CAP_DAC_READ_SEARCH only. fileActions off drops the file caps.
        CapabilityBoundingSet = responseHelperCaps;
        # pidfd_open/_send_signal pin and signal a target race-free; pidfd_getfd
        # grabs the target's fds for a collect; renameat2 (not on the generic
        # syscall-table group on every systemd) is the quarantine rename. Named so
        # the filter is correct regardless of the host's @system-service group.
        SystemCallFilter = [ "@system-service" "pidfd_open" "pidfd_send_signal" "pidfd_getfd" "renameat2" ];

        # It must see and act on other users' processes and files, so the three
        # daemon shields are OFF here -- the write set is bounded by ReadWritePaths
        # instead, and the sandbox below is otherwise the daemon's.
        ProtectProc = "default";
        ProtectControlGroups = false;
        PrivateTmp = false;
        ProtectHome = false;
        # The cgroup root (freeze/tree-kill writes child cgroups there; '-' so a
        # kill-only host where it was never created still starts), the quarantine
        # allowPaths (fileActions only), and a ledgerDir outside the state dir.
        ReadWritePaths = [ "-${responseCgroupRoot}" ]
          ++ lib.optionals cfg.response.fileActions cfg.response.quarantine.allowPaths
          ++ lib.optional
            (!(lib.hasPrefix "/var/lib/banken" cfg.response.ledgerDir))
            cfg.response.ledgerDir;

        # It has no reason to speak to the network at all.
        PrivateNetwork = true;
        RestrictAddressFamilies = [ "AF_UNIX" ];

        NoNewPrivileges = true;
        ProtectSystem = "strict";
        PrivateDevices = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectKernelLogs = true;
        ProtectClock = true;
        ProtectHostname = true;
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        SystemCallArchitectures = "native";
        SystemCallErrorNumber = "EPERM";
        UMask = "0077";
      };
    };

    # The periodic timer drives the one-shot floor. With a sensor on, banken is a long-running
    # daemon instead (it scans on its own interval), so the timer is not used.
    systemd.timers.banken = lib.mkIf (!streamEnabled) {
      description = "Run a banken scan every ${cfg.interval}";
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnBootSec = "1min";
        OnUnitActiveSec = cfg.interval;
        AccuracySec = "5s";
      };
    };

    # --- fleet rule refresh: the puller (git + network), its timer, and the reload step ---
    #
    # The checkout dir is owned by a dedicated, unprivileged `banken-rules` user: it is the only
    # identity with git and network, and it never touches the audit log, the cursor, or the detection
    # daemon. banken (root) merely reads the dir. See docs/design/rule-refresh.md sections 7-8.
    users.users.banken-rules = lib.mkIf cfg.refresh.enable {
      isSystemUser = true;
      group = "banken-rules";
      description = "banken fleet rules puller";
      home = cfg.refresh.dir;
    };
    users.groups.banken-rules = lib.mkIf cfg.refresh.enable { };
    # The puller's checkout dir (when on) and the response helper's cgroup-v2
    # root (when armed): the latter pre-created so the helper's ReadWritePaths
    # carve-out of the otherwise read-only /sys resolves. One rules list, since a
    # nested attrpath may be assigned only once in this attrset.
    systemd.tmpfiles.rules =
      lib.optionals cfg.refresh.enable [ "d ${cfg.refresh.dir} 0755 banken-rules banken-rules -" ]
      ++ lib.optionals responseHelper [ "d ${responseCgroupRoot} 0700 root root -" ];

    # The puller: pull -> (verify) -> preflight -> (on success) reload. Unprivileged, network-facing,
    # hardened as far as a git+network job allows. A failure rolls the checkout back and exits
    # non-zero, so the running daemon never sees a broken or unverified tree.
    systemd.services.banken-rules-pull = lib.mkIf cfg.refresh.enable {
      description = "Pull the fleet rules repo and refresh banken";
      documentation = [ "https://github.com/conor-sometimes/banken" ];
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      # Only reload when there is a long-running daemon to SIGHUP (a sensor is on). On the one-shot
      # timer model the next scan picks up the new dir, so no reload step is wired.
      unitConfig = lib.mkIf streamEnabled { OnSuccess = "banken-rules-reload.service"; };
      serviceConfig = {
        Type = "oneshot";
        User = "banken-rules";
        Group = "banken-rules";
        ExecStart = pullScript;
        OOMScoreAdjust = -900;
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ReadWritePaths = [ cfg.refresh.dir ];
        ProtectHome = true;
        PrivateTmp = true;
        PrivateDevices = true;
        RestrictAddressFamilies = [ "AF_UNIX" "AF_INET" "AF_INET6" ];
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectKernelLogs = true;
        ProtectControlGroups = true;
        ProtectClock = true;
        ProtectHostname = true;
        ProtectProc = "invisible";
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        LockPersonality = true;
        SystemCallArchitectures = "native";
        SystemCallFilter = [ "@system-service" ];
        SystemCallErrorNumber = "EPERM";
        UMask = "0022"; # the checkout is world-readable (0755 dir); banken reads it
      };
      environment = { HOME = cfg.refresh.dir; };
    };

    systemd.timers.banken-rules-pull = lib.mkIf cfg.refresh.enable {
      description = "Pull the fleet rules repo every ${cfg.refresh.interval}";
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnBootSec = "2min";
        OnUnitActiveSec = cfg.refresh.interval;
        AccuracySec = "10s";
        Persistent = true;
      };
    };

    # The reload step: a tiny root one-shot that SIGHUPs the daemon via its ExecReload. Kept separate
    # from the puller so the network/git half stays unprivileged; this half has no network and no git,
    # only the privilege to reload one unit. Wired only when a daemon exists to reload.
    systemd.services.banken-rules-reload = lib.mkIf (cfg.refresh.enable && streamEnabled) {
      description = "Reload banken after a successful rules pull";
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${config.systemd.package}/bin/systemctl reload banken.service";
      };
    };

    # The journal->file bridge for the sysmon source on a journald-only host (no /var/log/syslog):
    # `journalctl -f -o cat -t <identifier>` follows the journal and emits just the MESSAGE field
    # (the raw Sysmon <Event> XML, no syslog prefix), appended to bridgePath, which banken tails as a
    # normal file source. This is the whole of "banken reads the journal there": a thin, supported
    # journalctl pipe rather than a journal client or cgo in banken itself, so banken keeps its single
    # file+cursor+inotify reading path. The bridge runs unprivileged (DynamicUser) with only
    # journal-read access. Note: a bridge restart resumes at the journal tail (-n0), so events during
    # its sub-second downtime are not bridged; the auditd floor still records process exec meanwhile.
    systemd.services.banken-sysmon-journal = lib.mkIf (cfg.sysmon.enable && cfg.sysmon.fromJournal) {
      description = "Bridge the systemd journal '${cfg.sysmon.journalIdentifier}' identifier to a file banken tails";
      documentation = [ "https://github.com/conor-sometimes/banken" ];
      wantedBy = [ "multi-user.target" ];
      serviceConfig = {
        Type = "exec";
        ExecStart = "${config.systemd.package}/bin/journalctl -f -n0 -o cat -t ${cfg.sysmon.journalIdentifier}";
        StandardOutput = "append:${cfg.sysmon.bridgePath}";
        Restart = "on-failure";
        RestartSec = 2;
        # Unprivileged: a dynamic user that can only read the journal and write its own LogsDirectory.
        DynamicUser = true;
        SupplementaryGroups = [ "systemd-journal" ];
        LogsDirectory = lib.mkIf (lib.hasPrefix "/var/log/banken-sysmon/" cfg.sysmon.bridgePath) "banken-sysmon";
        OOMScoreAdjust = -900;
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        PrivateDevices = true;
        PrivateNetwork = true;
        RestrictAddressFamilies = [ "AF_UNIX" ];
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectKernelLogs = true;
        ProtectControlGroups = true;
        ProtectClock = true;
        ProtectHostname = true;
        ProtectProc = "invisible";
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        SystemCallArchitectures = "native";
        SystemCallFilter = [ "@system-service" ];
        SystemCallErrorNumber = "EPERM";
        UMask = "0077";
      };
    };
    }
    # The `services.mimi` wiring is included ONLY when that option is actually declared, i.e. when
    # mimi's NixOS module is imported alongside banken's. Gating on `options ? services.mimi` (the
    # declared-option tree, not a config value) keeps banken evaluable standalone -- the floor-only
    # deployment, and every banken-only test -- where mimi's module is absent and the option does not
    # exist. (Gating on cfg.mimi.enable instead would make config's shape depend on its own values:
    # infinite recursion. A bare mkIf-false definition would reference the absent option and fail.)
    // lib.optionalAttrs (options ? services.mimi) {
      services.mimi = lib.mkIf cfg.mimi.enable {
        enable = true;
        sink = cfg.mimi.streamPath;
      };
    }
  );
}
