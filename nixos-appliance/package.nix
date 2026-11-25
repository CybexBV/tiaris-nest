# `journeySystemRoots`: only the install journey's build sets it (Cargo.toml,
# feature `journey-system-roots`); a release build trusts public roots only.
{ pkgs, repoRoot ? ../., manageOrigin, journeySystemRoots ? false }:
let
  repo = builtins.toPath repoRoot;
  source = pkgs.lib.cleanSourceWith {
    src = repo;
    filter = path: type:
      let relative = pkgs.lib.removePrefix (toString repo + "/") (toString path);
          top = builtins.head (pkgs.lib.splitString "/" relative);
          handoff = "assets/autoexec.ipxe";
      in builtins.elem top [ "Cargo.toml" "Cargo.lock" "build.rs" "src" "migrations" "protocol" "release" "assets" "LICENSE" "NOTICE" ]
        || relative == handoff || (type == "directory" && pkgs.lib.hasPrefix (relative + "/") handoff);
  };
in pkgs.rustPlatform.buildRustPackage {
  pname = "tiaris-nest";
  version = (builtins.fromTOML (builtins.readFile (repo + "/Cargo.toml"))).package.version;
  src = source;
  cargoLock.lockFile = source + "/Cargo.lock";
  TIARIS_NEST_BUILD_MANAGE_ORIGIN = manageOrigin;
  buildFeatures = pkgs.lib.optional journeySystemRoots "journey-system-roots";
  # Build only the daemon and bootstrap binaries (omit qualification helpers).
  cargoBuildFlags = [ "--bin" "tiaris-nest" "--bin" "tiaris-nest-bootstrap" ];
  # Split bootstrap into its own output so the setup ISO does not carry the
  # 25 MiB tiaris-nest daemon binary.
  outputs = [ "out" "bootstrap" ];
  doCheck = false; # Locked Rust tests are a separate release gate.
  postInstall = ''
    mkdir -p "$bootstrap/bin"
    mv "$out/bin/tiaris-nest-bootstrap" "$bootstrap/bin/tiaris-nest-bootstrap"
    install -Dm0444 ${source}/assets/pxe-menu.png $out/share/tiaris-nest/assets/pxe-menu.png
    install -Dm0444 -t $out/share/doc/tiaris-nest ${source}/LICENSE ${source}/NOTICE
  '';
  meta = { license = pkgs.lib.licenses.asl20; platforms = [ "x86_64-linux" ]; };
}
