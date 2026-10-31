# banken as a Nix package: one CGO-free static binary with the baseline rules
# embedded (embed.go), so the package is the whole product.
#
#   pkgs.callPackage ./package.nix { }
{ lib, buildGo127Module }:

buildGo127Module (finalAttrs: {
  pname = "banken";
  version = "dev";

  # Only what the binary is built from: a docs or test-data edit does not
  # change the package hash.
  src = lib.fileset.toSource {
    root = ./.;
    fileset = lib.fileset.unions [
      ./go.mod
      ./go.sum
      ./main.go
      ./check.go
      ./embed.go
      ./internal
      ./rules
    ];
  };

  # The Go module set (yaml.v3; rapid is test-only but in the module graph),
  # pinned by go.sum and this hash.
  vendorHash = "sha256-3dWz1bJjqcS+WTpQOo2F7448l9zI555jOSSWjZFVQo8=";

  subPackages = [ "." ];
  env.CGO_ENABLED = 0;
  ldflags = [ "-s" "-w" "-X main.version=${finalAttrs.version}" ];

  meta = {
    description = "Small host EDR: Sigma rules and IOCs over the audit log, with OCSF output";
    homepage = "https://github.com/conor-sometimes/banken";
    mainProgram = "banken";
    platforms = lib.platforms.linux;
  };
})
