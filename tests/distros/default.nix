# The live distro matrix as one program: `nix run .#distro-matrix`.
#
# Builds banken's distro test (matrix_test.go, compiled with `go test -c`) and
# the in-guest checker (distrocheck), fetches every image in distros.json by
# the vendor checksum pinned there, and runs the test with QEMU and xorriso on
# PATH. Each distro is a subtest; arguments pass through to the test binary:
#
#   nix run .#distro-matrix -- -test.run 'TestMatrix/rocky-9'
#
# An app, not a `nix flake check`: the guests install auditd from their
# distros' own repos -- the install path under test -- and the check sandbox
# has no network. Everything Nix builds here is pure; only the VM run is not.
{ lib, buildGo127Module, fetchurl, runCommand, writeText, writeShellApplication, qemu, xorriso, banken }:

let
  distros = builtins.fromJSON (builtins.readFile ./distros.json);
  image = d: fetchurl ({ inherit (d) url; } // (if d ? sha512 then { inherit (d) sha512; } else { inherit (d) sha256; }));
  images = writeText "banken-distro-images.json"
    (builtins.toJSON (lib.listToAttrs (map (d: lib.nameValuePair d.name "${image d}") distros)));

  # The test binary and distrocheck, from the same module as banken (so the
  # same pinned Go modules, the same vendorHash).
  harness = buildGo127Module {
    pname = "banken-distro-matrix";
    inherit (banken) version vendorHash;
    src = lib.fileset.toSource {
      root = ../..;
      fileset = lib.fileset.unions [ banken.fileset (lib.fileset.fileFilter (f: f.hasExt "go") ./.) ];
    };
    env.CGO_ENABLED = 0;
    buildPhase = ''
      runHook preBuild
      go build -trimpath -o distrocheck ./tests/distros/distrocheck
      go test -c -trimpath -tags distros -o distro-matrix.test ./tests/distros
      runHook postBuild
    '';
    doCheck = false;
    installPhase = ''
      install -Dm755 distrocheck $out/bin/distrocheck
      install -Dm755 distro-matrix.test $out/bin/distro-matrix.test
    '';
  };

  # What every guest gets: banken, the checker, the canonical units, the
  # emulations, and the fixtures that say what each emulation must fire.
  payload = runCommand "banken-distro-payload" { } ''
    mkdir -p $out/emulations $out/fixtures
    cp ${./distros.json} $out/distros.json
    cp ${../emulations}/*.sh $out/emulations/
    cp ${../fixtures}/*.json $out/fixtures/
    cp ${../../packaging/systemd/banken.service} $out/banken.service
    cp ${../../packaging/systemd/banken.timer} $out/banken.timer
    cp ${lib.getExe banken} $out/banken
    cp ${harness}/bin/distrocheck $out/distrocheck
  '';
in
writeShellApplication {
  name = "banken-distro-matrix";
  runtimeInputs = [ qemu xorriso ];
  text = ''
    exec ${harness}/bin/distro-matrix.test -test.v -test.timeout 4h -test.parallel 3 \
      -payload ${payload} -images ${images} "$@"
  '';
}
