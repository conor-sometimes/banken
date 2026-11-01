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
{ config, lib, pkgs, ... }:

let
  cfg = config.services.banken;
  yaml = pkgs.formats.yaml { };

  settings = {
    rules = [ "/etc/banken/rules" ] ++ map (p: "${p}") cfg.extraRules; # interpolation copies the tree to the store
    optionalRules = cfg.optionalRules;
    observeRules = cfg.observeRules;
    statePath = "/var/lib/banken/cursor.json";
    # With the mimi sensor on, banken follows its OCSF event stream as a `mimi` source (added here so
    # it needs no manual sources entry); the sensor itself is brought up below.
    #
    # banken auto-detects the audit log only when `sources` is empty. Naming the mimi stream makes
    # the list non-empty, which would suppress that auto-detect and silently leave banken with no
    # auditd floor -- the opposite of the soft-dependency intent (mimi adds to the floor, never
    # replaces it). So when the sensor is on and the operator gave no sources of their own, name the
    # audit log explicitly alongside the stream, keeping the floor.
    sources =
      cfg.sources
      ++ lib.optionals (cfg.mimi.enable && cfg.sources == [ ] && cfg.audit.enable) [
        { type = "auditd"; path = "/var/log/audit/audit.log"; }
      ]
      ++ lib.optional cfg.mimi.enable { type = "mimi"; path = cfg.mimi.streamPath; };
    alerts = {
      journal.enable = cfg.alerts.journal.enable;
      jsonl = {
        inherit (cfg.alerts.jsonl) enable dir retentionDays format;
      };
      webhook = {
        inherit (cfg.alerts.webhook) enable style;
        urlFile = if cfg.alerts.webhook.urlFile == null then "" else toString cfg.alerts.webhook.urlFile;
      };
      otlp = {
        inherit (cfg.alerts.otlp) enable endpoint headers;
      };
    };
  };
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
            type = lib.types.enum [ "laurel" "auditd" "generic" "mimi" ];
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
      description = ''
        Extra rule trees (Sigma .yml and ioc/ lists), loaded after the
        embedded baseline and /etc/banken/rules.
      '';
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
          file, so a banken restart never loses events; banken's cursor resumes. banken polls it on
          the timer today; the continuous low-latency push path is a planned refinement.
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
          type = lib.types.enum [ "banken" "ocsf" ];
          default = "banken";
          description = ''
            Encoding: banken's native JSON, or OCSF 1.3.0 Detection Findings
            for an OCSF-aware SIEM (Security Lake, Splunk, Datadog, ...).
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
  };

  config = lib.mkIf cfg.enable {
    assertions = [{
      assertion = cfg.alerts.webhook.enable -> cfg.alerts.webhook.urlFile != null;
      message = "services.banken.alerts.webhook.enable needs alerts.webhook.urlFile.";
    } {
      assertion = cfg.alerts.otlp.enable -> cfg.alerts.otlp.endpoint != "";
      message = "services.banken.alerts.otlp.enable needs alerts.otlp.endpoint.";
    }];

    environment.systemPackages = [ cfg.package ];
    environment.etc."banken/banken.yml".source = yaml.generate "banken.yml" settings;

    security.auditd.enable = lib.mkIf cfg.audit.enable true;
    security.audit = lib.mkIf cfg.audit.enable {
      enable = lib.mkDefault true;
      rules = [
        "-a always,exit -F arch=b64 -S execve,execveat -k banken-exec"
        "-a always,exit -F arch=b32 -S execve -k banken-exec"
      ] ++ map (p: "-w ${p} -p rwa -k banken-watch") cfg.audit.watchPaths;
    };

    # The one switch: enabling the mimi sensor brings up services.mimi (mimi's own module must be
    # imported) pointed at the same stream file banken tails. Soft-wired above; banken stays the
    # auditd floor on its own.
    services.mimi = lib.mkIf cfg.mimi.enable {
      enable = true;
      sink = cfg.mimi.streamPath;
    };

    systemd.services.banken = {
      description = "banken host EDR scan";
      documentation = [ "https://github.com/conor-sometimes/banken" ];
      # Soft dependency on the sensor when it is on: order after it and want it, never require it,
      # so a mimi failure degrades banken to the auditd floor rather than taking it down.
      after = [ "auditd.service" ] ++ lib.optional cfg.mimi.enable "mimi.service";
      wants = [ "auditd.service" ] ++ lib.optional cfg.mimi.enable "mimi.service";
      # The daemon (sensor on) starts at boot; the one-shot (sensor off) is started by the timer.
      wantedBy = lib.mkIf cfg.mimi.enable [ "multi-user.target" ];
      serviceConfig = {
        # With the sensor on, banken runs as a long-running daemon (--watch): it follows the mimi
        # stream continuously and scans the auditd floor on banken's own interval, one process, one
        # alert path. Without it, the one-shot + timer below is the floor. Only the daemon restarts
        # on failure (the one-shot is driven by the timer). (--watch uses banken's built-in scan
        # interval for the floor; services.banken.interval drives the timer, the no-sensor path.)
        Type = if cfg.mimi.enable then "exec" else "oneshot";
        ExecStart = "${lib.getExe cfg.package}${lib.optionalString cfg.mimi.enable " --watch"} -config /etc/banken/banken.yml";
        Restart = lib.mkIf cfg.mimi.enable "on-failure";
        RestartSec = lib.mkIf cfg.mimi.enable 2;
        StateDirectory = "banken";
        StateDirectoryMode = "0700";
        LogsDirectory = lib.mkIf (cfg.alerts.jsonl.enable && cfg.alerts.jsonl.dir == "/var/log/banken") "banken";

        # An attacker who floods the box to trip the OOM killer must not reap
        # the watchdog (see the portable unit for why there is no MemoryMax).
        OOMScoreAdjust = -900;

        # Root, because the audit log is root's; every other power is taken
        # away. CAP_DAC_READ_SEARCH reads a log another user owns (Laurel's
        # is _laurel:_laurel 0640).
        CapabilityBoundingSet = [ "CAP_DAC_READ_SEARCH" ];
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ReadWritePaths = lib.optional cfg.alerts.jsonl.enable cfg.alerts.jsonl.dir;
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

    # The periodic timer drives the one-shot floor. With the sensor on, banken is a long-running
    # daemon instead (it scans on its own interval), so the timer is not used.
    systemd.timers.banken = lib.mkIf (!cfg.mimi.enable) {
      description = "Run a banken scan every ${cfg.interval}";
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnBootSec = "1min";
        OnUnitActiveSec = cfg.interval;
        AccuracySec = "5s";
      };
    };
  };
}
