# services.banken.honeytokens - plant decoy credential files and alert the moment
# one is touched. A honeytoken is a credential-shaped file no real task refers to,
# placed where an intruder looks and nothing legitimate reads, so ANY access is a
# hit with no false-positive story. The detection side is banken's honeytoken_access
# rule; this module is the deployment: it seeds the decoys and the audit watches.
#
# Safety, by design:
#  - It NEVER overwrites an existing file. A real ~/.aws/credentials is never
#    clobbered; the module only ever ADDS bait.
#  - Watches are scoped to the decoy paths by key (-k banken-honeytoken), so a real
#    credential's legitimate reads are never watched and never alert.
#  - Decoys default to a locked, no-login decoy user whose files nothing legitimate
#    ever reads -- the highest-signal trap, zero false positives, no collision with
#    any real user's secrets.
{ config, lib, pkgs, ... }:

let
  cfg = config.services.banken.honeytokens;

  # The decoy catalog. Each entry: the relative path under the owner's home, the
  # file mode, and inert-but-plausible content (valid-looking, authenticates to
  # nothing). The AWS pair is AWS's own documented EXAMPLE key, universally known
  # to be dead. None of these grant access to anything.
  catalog = {
    aws = {
      rel = ".aws/credentials";
      mode = "0600";
      text = ''
        [default]
        aws_access_key_id = AKIAIOSFODNN7EXAMPLE
        aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
        region = us-east-1
      '';
    };
    ssh = {
      rel = ".ssh/id_rsa";
      mode = "0600";
      # A plausible OpenSSH private-key shape with inert body: looks like a key to
      # a hunter, is not a usable key.
      text = ''
        -----BEGIN OPENSSH PRIVATE KEY-----
        b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
        REDACTED0000000000000000000000000000000000000000000000000000000000000
        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
        -----END OPENSSH PRIVATE KEY-----
      '';
    };
    npm = {
      rel = ".npmrc";
      mode = "0600";
      text = "//registry.npmjs.org/:_authToken=npm_0000000000000000000000000000000000000000\n";
    };
    env = {
      rel = ".env";
      mode = "0600";
      text = ''
        DATABASE_URL=postgres://admin:S3cr3tP4ss@db.internal:5432/prod
        STRIPE_SECRET_KEY=sk_live_0000000000000000000000000000
        JWT_SECRET=change-me-0000000000000000000000000000
      '';
    };
    kube = {
      rel = ".kube/config";
      mode = "0600";
      text = ''
        apiVersion: v1
        kind: Config
        clusters:
        - cluster: {server: https://10.0.0.1:6443}
          name: prod
        users:
        - name: admin
          user: {token: eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.0000000000.0000000000}
        contexts:
        - context: {cluster: prod, user: admin}
          name: prod
        current-context: prod
      '';
    };
    git = {
      rel = ".git-credentials";
      mode = "0600";
      text = "https://ci-bot:ghp_0000000000000000000000000000000000000000@github.com\n";
    };
    docker = {
      rel = ".docker/config.json";
      mode = "0600";
      text = ''{"auths":{"registry.internal":{"auth":"Y2ktYm90OjAwMDAwMDAwMDAwMDAwMDA="}}}'';
    };
    netrc = {
      rel = ".netrc";
      mode = "0600";
      text = "machine ftp.internal login admin password hunter2000\n";
    };
  };

  # The types the operator turned on.
  enabledTypes = lib.filter (t: cfg.${t}.enable) (lib.attrNames catalog);

  home = cfg.home;
  # Each enabled decoy's absolute path + source file + mode.
  decoys = map
    (t: {
      name = t;
      path = "${home}/${catalog.${t}.rel}";
      src = pkgs.writeText "banken-honeytoken-${t}" catalog.${t}.text;
      mode = catalog.${t}.mode;
    })
    enabledTypes;

  decoyPaths = map (d: d.path) decoys;

  # The detection rule, generated from exactly the decoy paths planted. Reuses the
  # proven TargetFilename match (same shape as rules/agent/honeytoken_access.yml),
  # so no new engine behaviour is needed: any read of a decoy fires critical.
  honeytokenRule = pkgs.writeText "banken-honeytoken.yml" ''
    title: Honeytoken decoy credential accessed
    id: 6f3a2b1c-9d4e-4a5b-8c7d-0e1f2a3b4c5d
    status: stable
    description: >
      A banken-planted decoy credential file was opened. No real task refers to these
      files, so any open is an intruder (a credential hunt or an injected instruction),
      caught before the attacker uses anything. Seeded by services.banken.honeytokens.
    references:
      - https://attack.mitre.org/techniques/T1552/001/
      - https://d3fend.mitre.org/technique/d3f:DecoyFile/
    author: banken
    logsource:
      product: linux
      category: process_creation
    detection:
      honeytoken:
        TargetFilename:
    ${lib.concatMapStringsSep "\n" (p: "      - ${p}") decoyPaths}
      condition: honeytoken
    falsepositives:
      - A backup or locate/updatedb job reading a decoy. The watch is read-only (-p r)
        so a plain ls (which stats, not opens) stays quiet; exclude such Image values.
    level: critical
    tags:
      - attack.credential-access
      - attack.t1552.001
  '';

  # Ransomware canaries. Decoy DOCUMENTS watched for MODIFICATION, not reads. No
  # real task edits these files, so a write to one is a process encrypting user
  # files (ransomware). Same subsystem as the credential decoys above, with a
  # write/attribute watch (-p wa) and its own key instead of a read watch.
  canaryNames = [
    "000-IMPORTANT-do-not-delete.docx"
    "budget-2026.xlsx"
    "passwords.kdbx"
    "family-photos.zip"
  ];
  canarySrc = pkgs.writeText "banken-canary.txt"
    "banken ransomware canary. A decoy document that nothing legitimate edits. If this file was modified or renamed, a process is encrypting user files.\n";
  canaryDecoys = lib.optionals cfg.canary.enable
    (lib.concatMap (dir: map (n: "${dir}/${n}") canaryNames) cfg.canary.dirs);

  # The ransomware rule, generated from exactly the canary paths planted. Same
  # TargetFilename shape as the honeytoken rule, so no new engine behaviour: any
  # write to a canary fires critical.
  ransomwareRule = pkgs.writeText "banken-ransomware-canary.yml" ''
    title: Ransomware canary file modified
    id: 7a4b3c2d-0e1f-4a5b-9c8d-1e2f3a4b5c6d
    status: stable
    description: >
      A banken-planted canary document was modified or renamed. No real task edits
      these files, so a write is a process encrypting user files (ransomware), caught
      as it starts sweeping a directory. Seeded by services.banken.honeytokens.canary.
    references:
      - https://attack.mitre.org/techniques/T1486/
      - https://d3fend.mitre.org/technique/d3f:DecoyFile/
    author: banken
    logsource:
      product: linux
      category: process_creation
    detection:
      canary:
        TargetFilename:
    ${lib.concatMapStringsSep "\n" (p: "      - ${p}") canaryDecoys}
      condition: canary
    falsepositives:
      - A backup job rewriting a canary. The watch is write/attribute only (-p wa).
    level: critical
    tags:
      - attack.impact
      - attack.t1486
  '';

in
{
  options.services.banken.honeytokens = {
    enable = lib.mkEnableOption ''
      banken honeytokens: plant decoy credential files and alert on any access.
      Pairs with the honeytoken_access detection rule
    '';

    user = lib.mkOption {
      type = lib.types.str;
      default = "banken-decoy";
      description = ''
        The account that owns the decoys. The default is a dedicated locked,
        no-login service user created by this module; nothing legitimate ever logs
        in as it or reads its files, so any access is an intruder. Point it at a
        real user only to plant bait in that user's home (then the never-clobber
        guard applies).
      '';
    };

    group = lib.mkOption {
      type = lib.types.str;
      default = "banken-decoy";
      description = "The group that owns the decoys.";
    };

    home = lib.mkOption {
      type = lib.types.path;
      default = "/var/lib/banken-decoy";
      description = "The home directory the decoys are planted under.";
    };

    createUser = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Create the decoy user/group as a locked, no-login system account. Turn off
        when user points at an existing real account.
      '';
    };

    canary = {
      enable = lib.mkEnableOption ''
        ransomware canaries: plant decoy documents and alert on any WRITE to them.
        Nothing legitimate edits these files, so a write is a process encrypting
        user files. Pairs with the generated ransomware-canary detection rule
      '';

      dirs = lib.mkOption {
        type = lib.types.listOf lib.types.path;
        default = [ cfg.home ];
        defaultText = lib.literalExpression "[ config.services.banken.honeytokens.home ]";
        example = lib.literalExpression ''[ "/home/alice/Documents" "/srv/share" ]'';
        description = ''
          Directories to plant canary documents in and watch for writes. The default
          is the decoy user's home. Point it at real document directories (a user's
          Documents, a file share) to catch an encryptor the moment it sweeps one;
          the canaries are owned by the honeytoken user and the never-clobber guard
          still applies, so no real file is touched.
        '';
      };
    };

  } // lib.mapAttrs
    (t: _: {
      enable = lib.mkEnableOption "the ${t} honeytoken decoy (${catalog.${t}.rel}), planted under the honeytoken home and watched for reads";
    })
    catalog;

  config = lib.mkIf (cfg.enable && config.services.banken.enable) {
    assertions = [{
      assertion = enabledTypes != [ ] || cfg.canary.enable;
      message = "services.banken.honeytokens.enable is on but nothing is planted: enable a credential decoy (e.g. services.banken.honeytokens.aws.enable = true) or the ransomware canary (services.banken.honeytokens.canary.enable = true).";
    }];

    # The locked decoy account: no login, no password, a home for the bait.
    users.users = lib.mkIf (cfg.createUser) {
      ${cfg.user} = {
        isSystemUser = true;
        group = cfg.group;
        home = cfg.home;
        createHome = true;
        shell = "${pkgs.shadow}/bin/nologin";
        description = "banken honeytoken decoy account (no real use; any access is an alert)";
      };
    };
    users.groups = lib.mkIf (cfg.createUser) { ${cfg.group} = { }; };

    # Plant the decoys EARLY via tmpfiles, before auditd loads its rules, so the
    # read-watch attaches to a file that exists. tmpfiles `C` copies the decoy
    # from its store source ONLY if the target does not exist yet -- that is the
    # never-clobber guard, as a documented systemd guarantee: a real credential is
    # never overwritten. `d` ensures each decoy's parent directory exists.
    systemd.tmpfiles.rules =
      (map (d: "d ${builtins.dirOf d.path} 0700 ${cfg.user} ${cfg.group} -") decoys)
      ++ (map (d: "C ${d.path} ${d.mode} ${cfg.user} ${cfg.group} - ${d.src}") decoys)
      # Canary documents: a 0755 parent (a user's Documents dir is browsable) and a
      # 0644 decoy copied only if absent (never-clobber). Watched for writes below.
      ++ (map (p: "d ${builtins.dirOf p} 0755 ${cfg.user} ${cfg.group} -") canaryDecoys)
      ++ (map (p: "C ${p} 0644 ${cfg.user} ${cfg.group} - ${canarySrc}") canaryDecoys);

    # Load the read-watch for each decoy AFTER auditd is up and the decoys exist,
    # via auditctl directly. The declarative security.audit.rules load at auditd
    # start, which races the decoy planting: a -w on a not-yet-existing file is
    # dropped. Adding the watches here guarantees they attach to files that exist.
    # Keyed so banken sees them and real credentials (no key) are never watched.
    systemd.services.banken-honeytoken-watch = {
      description = "Load banken honeytoken + ransomware-canary audit watches";
      wantedBy = [ "multi-user.target" ];
      after = [ "auditd.service" "systemd-tmpfiles-setup.service" ];
      requires = [ "auditd.service" ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
      };
      # Read-watch (-p r) on each credential decoy; write/attribute-watch (-p wa) on
      # each canary document. Separate keys so banken tells the two apart.
      script = lib.concatStringsSep "\n" (
        (map (p: "${pkgs.audit}/bin/auditctl -w ${p} -p r -k banken-honeytoken") decoyPaths)
        ++ (map (p: "${pkgs.audit}/bin/auditctl -w ${p} -p wa -k banken-canary") canaryDecoys)
      );
    };

    # Ship the generated detection rules to banken as an extra rule dir. Each rule
    # is written only when it has decoys, so a canary-only (or decoy-only) config
    # never ships a rule with an empty TargetFilename list.
    services.banken.extraRules = [ (pkgs.runCommand "banken-honeytoken-rules" { } ''
      mkdir -p $out
      ${lib.optionalString (enabledTypes != [ ]) "cp ${honeytokenRule} $out/honeytoken-decoy.yml"}
      ${lib.optionalString cfg.canary.enable "cp ${ransomwareRule} $out/ransomware-canary.yml"}
    '') ];
  };
}
