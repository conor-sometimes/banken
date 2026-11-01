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
# mimiBundle (optional) is a directory holding the portable mimi sensor and the three shared objects
# it needs to run with no /nix in a guest (mimi, ld.so, libc.so.6, libgcc_s.so.1). Supplied, the
# payload carries it plus mimicheck.sh and distrocheck runs the banken + mimi objectives (M1-M5) on
# every distro; omitted (banken's own `nix run .#distro-matrix`), the matrix is banken-raw only.
{ lib, buildGo127Module, fetchurl, runCommand, writeText, writeShellApplication, qemu, xorriso, banken, mimiBundle ? null }:

let
  distros = builtins.fromJSON (builtins.readFile ./distros.json);
  image = d: fetchurl ({ inherit (d) url; } // (if d ? sha512 then { inherit (d) sha512; } else { inherit (d) sha256; }));
  images = writeText "banken-distro-images.json"
    (builtins.toJSON (lib.listToAttrs (map (d: lib.nameValuePair d.name "${image d}") distros)));

  # The whole repository's source (its Go code with every test, fixture and
  # golden), so banken's own test suite can run inside each guest (E1).
  src = lib.fileset.toSource {
    root = ../..;
    fileset = lib.fileset.unions [
      banken.fileset ../../examples ../../tests ../../tools
      (lib.fileset.fileFilter (f: lib.hasSuffix "_test.go" f.name) ../..)
    ];
  };

  # The matrix test, distrocheck, and a test binary per package, from the same
  # module as banken (so the same pinned Go modules, the same vendorHash).
  harness = buildGo127Module {
    pname = "banken-distro-matrix";
    inherit (banken) version vendorHash;
    inherit src;
    env.CGO_ENABLED = 0;
    buildPhase = ''
      runHook preBuild
      go build -trimpath -o distrocheck ./tests/distros/distrocheck
      go test -c -trimpath -tags distros -o distro-matrix.test ./tests/distros
      # One binary per package with tests, named for its directory
      # (internal/sigma -> internal_sigma.test; the root package -> banken.test).
      mkdir suite
      for pkg in $(go list ./...); do
        dir=''${pkg#github.com/conor-sometimes/banken}; dir=''${dir#/}
        name=$(echo "''${dir:-banken}" | tr / _)
        go test -c -trimpath -o "suite/$name.test" "$pkg"
      done
      runHook postBuild
    '';
    doCheck = false;
    installPhase = ''
      install -Dm755 distrocheck $out/bin/distrocheck
      install -Dm755 distro-matrix.test $out/bin/distro-matrix.test
      mkdir -p $out/suite && cp suite/*.test $out/suite/
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
    cp -r ${harness}/suite $out/suite
    tar -C ${src} -cf $out/src.tar .
    ${lib.optionalString (mimiBundle != null) ''
      cp ${./mimicheck.sh} $out/mimicheck.sh
      mkdir -p $out/mimi-bundle
      cp ${mimiBundle}/mimi ${mimiBundle}/ld.so ${mimiBundle}/libc.so.6 ${mimiBundle}/libgcc_s.so.1 $out/mimi-bundle/
    ''}
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
