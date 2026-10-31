# banken as a Nix package: one CGO-free static binary with the baseline rules
# embedded (embed.go), so the package is the whole product.
#
#   pkgs.callPackage ./package.nix { }
{ lib, buildGo127Module }:

let
  # What the binary is built from: the root package's non-test Go files (by
  # pattern, so a new file is never silently left out), the internal packages
  # and the embedded rules. A docs or test-data edit does not change the hash.
  rootGo = map (n: ./. + "/${n}") (builtins.filter
    (n: lib.hasSuffix ".go" n && !lib.hasSuffix "_test.go" n)
    (builtins.attrNames (builtins.readDir ./.)));
  fileset = lib.fileset.unions ([ ./go.mod ./go.sum ./internal ./rules ] ++ rootGo);
in
buildGo127Module (finalAttrs: {
  pname = "banken";
  version = "dev";

  src = lib.fileset.toSource { root = ./.; inherit fileset; };

  # The Go module set (yaml.v3; rapid is test-only but in the module graph),
  # pinned by go.sum and this hash.
  vendorHash = "sha256-3dWz1bJjqcS+WTpQOo2F7448l9zI555jOSSWjZFVQo8=";

  subPackages = [ "." ];
  env.CGO_ENABLED = 0;
  ldflags = [ "-s" "-w" "-X main.version=${finalAttrs.version}" ];

  # For builds of other packages in this module (the distro matrix harness).
  passthru.fileset = fileset;

  meta = {
    description = "Small host EDR: Sigma rules and IOCs over the audit log, with OCSF output";
    homepage = "https://github.com/conor-sometimes/banken";
    mainProgram = "banken";
    platforms = lib.platforms.linux;
  };
})
