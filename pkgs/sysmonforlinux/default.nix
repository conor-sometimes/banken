# Microsoft Sysmon-for-Linux, packaged for NixOS so banken's live sysmon test can run the REAL
# binary (not an injected record). This is the artifact deliverable 1 of the "PROVE Sysmon-for-Linux
# end-to-end" task.
#
#   pkgs.callPackage ./pkgs/sysmonforlinux { }   ->  $out/bin/sysmon + $out/opt/sysinternalsEBPF
#
# ----------------------------------------------------------------------------------------------
# PACKAGING PATH: Microsoft .deb (fetchurl + dpkg-deb + autoPatchelfHook).
#
# Why the .deb and not a source build (the task's stated preference):
#   * SysmonForLinux's CMake build MANDATORILY runs the dotnet-t4 (`t4`) template tool to transform
#     sysmonCommon/manifest.tt into sysmonevents.h / the message catalog. `t4` is distributed only as
#     a .NET global tool from api.nuget.org, and nixpkgs ships no equivalent (mono 6.14 has no
#     TextTransform). On hokkaido's egress wall api.nuget.org returns "403 Filtered", so the source
#     build cannot even configure. Pre-generating the manifest files would itself need `t4` once.
#   * The .deb is the complete, officially supported runtime: the `sysmon` binary, the compiled eBPF
#     objects AND the kernel-offsets database under /opt/sysinternalsEBPF, and libsysinternalsEBPF.so
#     -- exactly what sysmon loads at runtime. No build toolchain, no .NET.
#
# ----------------------------------------------------------------------------------------------
# !! UNVERIFIED / BLOCKED ON EGRESS !!  (Taskwarrior 1188, +conor)
#
# packages.microsoft.com is ALSO walled on hokkaido ("403 Filtered"), so these two .debs cannot be
# fetched here and the sha256 values below cannot be realised. They are lib.fakeHash on purpose: this
# derivation is structurally complete and ready, but it has NOT been built and MUST NOT be presented
# as proven. To finalise once Conor opens egress to packages.microsoft.com:
#   1. Confirm the current versions in the pool index (versions move; the ones below are the last
#      publicly known and MUST be re-checked, do not trust them blind):
#        curl -s https://packages.microsoft.com/ubuntu/22.04/prod/pool/main/s/sysmonforlinux/
#        curl -s https://packages.microsoft.com/ubuntu/22.04/prod/pool/main/s/sysinternalsebpf/
#      and set `sysmonVersion` / `ebpfVersion` to match the .deb filenames.
#   2. `nix-build` -- it fails and prints the real `got: sha256-...` for each fetch; paste those in.
#   3. Run tests/sysmon-live.nix; only a live PASS justifies the README support line.
# ----------------------------------------------------------------------------------------------
{ lib
, stdenv
, fetchurl
, dpkg
, autoPatchelfHook
, zlib
, libxml2
, elfutils      # libelf, for libsysinternalsEBPF.so
, glib
, json-glib     # SysinternalsEBPF links json-glib
}:

let
  # TODO(egress 1188): re-confirm against the pool index before the first real build (see header).
  sysmonVersion = "1.3.5.0";
  ebpfVersion = "1.5.0";
  base = "https://packages.microsoft.com/ubuntu/22.04/prod/pool/main/s";
in
stdenv.mkDerivation (finalAttrs: {
  pname = "sysmonforlinux";
  version = sysmonVersion;

  # Two .debs: the eBPF runtime library + offsets DB, and sysmon itself. amd64 only (the VM test and
  # hokkaido are x86_64; sysmon upstream also ships arm64 if a host ever needs it).
  srcs = [
    (fetchurl {
      url = "${base}/sysinternalsebpf/sysinternalsebpf_${ebpfVersion}_amd64.deb";
      hash = lib.fakeHash; # TODO(egress 1188): nix-build prints the real hash.
    })
    (fetchurl {
      url = "${base}/sysmonforlinux/sysmonforlinux_${sysmonVersion}_amd64.deb";
      hash = lib.fakeHash; # TODO(egress 1188): nix-build prints the real hash.
    })
  ];

  nativeBuildInputs = [ dpkg autoPatchelfHook ];

  # Shared libraries the prebuilt ELFs need; autoPatchelfHook rewrites the interpreter + rpath to
  # these store paths.
  buildInputs = [ (lib.getLib stdenv.cc.cc) zlib libxml2 elfutils glib json-glib ];

  unpackPhase = ''
    runHook preUnpack
    for deb in $srcs; do
      dpkg-deb -x "$deb" ./extracted
    done
    runHook postUnpack
  '';

  dontConfigure = true;
  dontBuild = true;

  # The sysmon binary and libsysinternalsEBPF.so hard-code /opt/sysinternalsEBPF for their eBPF
  # objects and offsets DB. We ship that tree verbatim in $out/opt/sysinternalsEBPF; the NixOS module
  # / the live test binds or symlinks it to /opt so the binary finds it. We do NOT move or rename
  # those resources (the loader does a fixed-path lookup -- no rough-edge path rewriting).
  installPhase = ''
    runHook preInstall

    mkdir -p "$out/bin" "$out/lib" "$out/opt"

    install -Dm755 ./extracted/usr/bin/sysmon "$out/bin/sysmon"
    if [ -e ./extracted/usr/bin/sysmonLogView ]; then
      install -Dm755 ./extracted/usr/bin/sysmonLogView "$out/bin/sysmonLogView"
    fi

    # libsysinternalsEBPF.so* lands in a multiarch libdir in the .deb.
    find ./extracted -name 'libsysinternalsEBPF.so*' -exec cp -a {} "$out/lib/" \;

    # The eBPF objects + offsets DB + installer helper live under /opt/sysinternalsEBPF.
    cp -a ./extracted/opt/sysinternalsEBPF "$out/opt/sysinternalsEBPF"

    runHook postInstall
  '';

  # sysmon dlopen()s libsysinternalsEBPF.so by soname at runtime; keep $out/lib on its rpath.
  appendRunpaths = [ "${placeholder "out"}/lib" ];

  passthru = {
    # Absolute resource dir the loader expects at /opt/sysinternalsEBPF; the module/test binds it.
    ebpfResourceDir = "${placeholder "out"}/opt/sysinternalsEBPF";
  };

  meta = {
    description = "Microsoft Sysmon for Linux: system activity monitor emitting Sysmon-schema events via eBPF";
    homepage = "https://github.com/Sysinternals/SysmonForLinux";
    # SysmonForLinux userspace is MIT; its eBPF programs are GPL-2.0; SysinternalsEBPF is LGPL-2.1
    # with its eBPF library GPL-2.0. All redistributable. (The task assumed all-MIT; corrected here.)
    license = with lib.licenses; [ mit gpl2Only lgpl21Only ];
    mainProgram = "sysmon";
    platforms = [ "x86_64-linux" ];
    sourceProvenance = [ lib.sourceTypes.binaryNativeCode ];
  };
})
