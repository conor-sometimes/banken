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
    sources = cfg.sources;
    alerts = {
      journal.enable = cfg.alerts.journal.enable;
      jsonl = {
        inherit (cfg.alerts.jsonl) enable dir retentionDays format;
        groupReadable = cfg.alerts.jsonl.readableByGroup != "";
      };
      webhook = {
        inherit (cfg.alerts.webhook) enable style;
        urlFile = if cfg.alerts.webhook.urlFile == null then "" else toString cfg.alerts.webhook.urlFile;
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
            type = lib.types.enum [ "laurel" "auditd" "generic" ];
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
        readableByGroup = lib.mkOption {
          type = lib.types.str;
          default = "";
          example = "banken-observers";
          description = ''
            Make the alert log readable by this group (default: owner-only).
            banken writes the per-day files 0640, and sets its log directory
            setgid-owned by this group so new files inherit it -- banken never
            chowns (it runs with CAP_DAC_READ_SEARCH only, no CAP_CHOWN).

            You declare the group and its members yourself -- the module sets
            the group of its own log directory, it does not create or manage
            system users or groups. A group named here that does not exist is a
            deploy-time tmpfiles error, not banken's to paper over.

            Every alert, host-wide, becomes readable to the group, so point it
            at a trusted log-reader account, not a sandboxed one.
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
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [{
      assertion = cfg.alerts.webhook.enable -> cfg.alerts.webhook.urlFile != null;
      message = "services.banken.alerts.webhook.enable needs alerts.webhook.urlFile.";
    }];

    environment.systemPackages = [ cfg.package ];
    environment.etc."banken/banken.yml".source = yaml.generate "banken.yml" settings;

    # Own banken's OWN log directory setgid to the reader group, so its 0640
    # files inherit that group (banken cannot chown them -- no CAP_CHOWN). The
    # group itself, and who is in it, are the operator's to declare: the module
    # sets the group of its data dir, it does not manage the system's users.
    systemd.tmpfiles.rules = lib.mkIf (cfg.alerts.jsonl.enable && cfg.alerts.jsonl.readableByGroup != "") [
      "d ${cfg.alerts.jsonl.dir} 2750 root ${cfg.alerts.jsonl.readableByGroup} - -"
    ];

    security.auditd.enable = lib.mkIf cfg.audit.enable true;
    security.audit = lib.mkIf cfg.audit.enable {
      enable = lib.mkDefault true;
      rules = [
        "-a always,exit -F arch=b64 -S execve,execveat -k banken-exec"
        "-a always,exit -F arch=b32 -S execve -k banken-exec"
      ] ++ map (p: "-w ${p} -p rwa -k banken-watch") cfg.audit.watchPaths;
    };

    systemd.services.banken = {
      description = "banken host EDR scan";
      documentation = [ "https://github.com/conor-sometimes/banken" ];
      after = [ "auditd.service" ];
      wants = [ "auditd.service" ];
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${lib.getExe cfg.package} -config /etc/banken/banken.yml";
        StateDirectory = "banken";
        StateDirectoryMode = "0700";
        # systemd owns /var/log/banken as root:root -- except when a reader
        # group is configured, where a tmpfiles rule (below) owns it setgid to
        # that group instead, so LogsDirectory must not fight it.
        LogsDirectory = lib.mkIf (cfg.alerts.jsonl.enable && cfg.alerts.jsonl.dir == "/var/log/banken" && cfg.alerts.jsonl.readableByGroup == "") "banken";

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
        PrivateNetwork = !cfg.alerts.webhook.enable;
        RestrictAddressFamilies = [ "AF_UNIX" ] ++ lib.optionals cfg.alerts.webhook.enable [ "AF_INET" "AF_INET6" ];
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

    systemd.timers.banken = {
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
