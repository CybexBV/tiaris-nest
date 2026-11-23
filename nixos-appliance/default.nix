{ manageRepo, manageSourceArchive, manageSourceRevision, sourceRevision
, releasePublicKey, provisioningPublicKeys, manageOrigin, sourceDateEpoch
, system ? "x86_64-linux"
  # Only the install journey sets this (Tiaris docs/checks.md, "The install
  # journey"): the public certificate of its test CA. The Nest then also trusts
  # the system store, which holds it. A release build has none.
, journeyCaCertificate ? null
}:
let
  pin = import ../release/nixpkgs.nix;
  nixpkgs = builtins.fetchTarball { inherit (pin) url sha256; };
  pkgs = import nixpkgs { inherit system; };
  lib = pkgs.lib;
  publicKeys = if builtins.isString provisioningPublicKeys then builtins.fromJSON provisioningPublicKeys else provisioningPublicKeys;
  archiveInput = builtins.path { path = manageSourceArchive; name = "tiaris-manage-${manageSourceRevision}.tar"; };
  journeyCa = if journeyCaCertificate == null then null else
    let text = builtins.readFile (builtins.toPath journeyCaCertificate); in
    assert builtins.stringLength text <= 16384;
    assert lib.hasPrefix "-----BEGIN CERTIFICATE-----\n" text;
    assert !lib.hasInfix "PRIVATE KEY" text;
    builtins.path { path = builtins.toPath journeyCaCertificate; name = "tiaris-journey-ca.crt"; };
  journeyTrust = lib.optional (journeyCa != null) {
    security.pki.certificateFiles = [ journeyCa ];
    # The journey keeps each machine's serial log as evidence: the ISO and the
    # installed Nest write their journal there (nobody can sign in to look).
    boot.kernelParams = [ "console=ttyS0,115200" "console=tty0" ];
    services.journald.extraConfig = ''
      ForwardToConsole=yes
      TTYPath=/dev/ttyS0
      MaxLevelConsole=info
    '';
  };
  package = import ./package.nix { inherit pkgs manageOrigin; journeySystemRoots = journeyCa != null; };
  migrations = pkgs.runCommand "tiaris-nest-sqlite-migrations" { nativeBuildInputs = [ pkgs.python3 ]; } ''
    mkdir -p $out
    python3 ${./metadata.py} migrations ${../migrations} $out/sqlite-migrations.json
  '';
  # The source's metadata beside a link to the one embedded source archive
  # (`archiveInput`, the manifest's `manage_source`): a copy would ship the
  # same 72 MiB twice in every release. First boot copies both into
  # /usr/share/tiaris-nest/manage-source (runtime/source-copy.py).
  sourceArchive = pkgs.runCommand "tiaris-nest-manage-source-${manageSourceRevision}" {
    nativeBuildInputs = [ pkgs.python3 ];
  } ''
    mkdir -p $out
    ln -s ${archiveInput} $out/${manageSourceRevision}.tar
    python3 ${./metadata.py} source $out/${manageSourceRevision}.tar ${manageSourceRevision} $out/${manageSourceRevision}.json
    chmod 0444 $out/${manageSourceRevision}.json
  '';
  # The offline production fixture builds the workstation target from this
  # exact Manage revision. Seed its agent output in the signed appliance cache
  # so the target build never needs to fetch Cargo crates from the Internet.
  workstationAgent = import (builtins.toPath manageRepo + "/deploy/nixos/tiaris-agent-package.nix") {
    inherit pkgs;
    repoRoot = builtins.toPath manageRepo;
  };
  workstationCacheSeeds = import ./workstation-cache-seeds.nix {
    inherit nixpkgs pkgs manageRepo workstationAgent system;
  };
  # The Canopy tty1 screens: `--nest-setup` on the setup ISO and
  # `--appliance` on the installed Nest. Both read bounded JSON projections
  # written by tiaris-nest-bootstrap and the tiaris-nest daemon.
  installerKiosk = import (builtins.toPath manageRepo + "/deploy/nixos/tiaris-installer-kiosk-package.nix") {
    inherit pkgs;
    repoRoot = builtins.toPath manageRepo;
  };
  # The generic USB installer stick for computers that cannot network-boot
  # (Tiaris docs/design/usb-installer.md), built from the same pinned Tiaris
  # source. Every release publishes it beside the template ISO and names it
  # in its signed manifest; the Nest itself does not carry or serve it.
  # The stick checks the runtime's signature with this release's key and
  # installs only for this release's Manage. Tiaris sources from before the
  # stick took them do not accept the two arguments, so pass only what the
  # pinned source's function names.
  usbInstaller =
    let
      build = import (builtins.toPath manageRepo + "/deploy/nixos/tiaris-usb-installer.nix");
    in
    build (builtins.intersectAttrs (builtins.functionArgs build) {
      inherit nixpkgs pkgs system releasePublicKey manageOrigin;
      repoRoot = builtins.toPath manageRepo;
      sourceRevision = manageSourceRevision;
    });
  common = {
    inherit package sourceArchive migrations workstationAgent workstationCacheSeeds installerKiosk sourceRevision manageSourceRevision manageOrigin sourceDateEpoch releasePublicKey;
    sourceArchiveFile = archiveInput;
    provisioningPublicKeys = publicKeys;
    nixpkgsRevision = pin.revision;
    nixpkgsPath = nixpkgs;
    # Presentation-only GRUB theme directory (theme.txt, images, .pf2 fonts).
    grubTheme = import (builtins.toPath manageRepo + "/deploy/nixos/tiaris-grub-theme.nix") {
      inherit pkgs;
      repoRoot = builtins.toPath manageRepo;
      variant = "nest-installer";
      footerLeft = "NIXOS 26.05 · UEFI";
    };
  };
  installed = import (nixpkgs + "/nixos/lib/eval-config.nix") {
    inherit system;
    specialArgs.appliance = common;
    modules = [ ./system.nix ] ++ journeyTrust;
  };
  live = import (nixpkgs + "/nixos/lib/eval-config.nix") {
    inherit system;
    specialArgs.appliance = common;
    modules = [ ./iso.nix ] ++ journeyTrust;
  };
  metadataBase = {
    schema = "tiaris.nest.appliance-closure-build.v1";
    release_id = package.version;
    base_os = "nixos";
    base_os_version = "26.05";
    source_revision = sourceRevision;
    manage_source_revision = manageSourceRevision;
    nixpkgs_revision = pin.revision;
    system_toplevel = toString installed.config.system.build.toplevel;
    required_system_versions = {
      kernel = installed.config.boot.kernelPackages.kernel.version;
      linux-firmware = pkgs.linux-firmware.version;
      nix = installed.config.nix.package.version;
      tiaris-nest = package.version;
      systemd-boot = pkgs.systemd.version;
    };
    nix_signing_public_key = "tiaris-nest-appliance-1:${releasePublicKey}";
    manage_origin = manageOrigin;
    manage_source = {
      revision = manageSourceRevision;
      sha256 = builtins.hashFile "sha256" (builtins.toPath manageSourceArchive);
      store_path = toString archiveInput;
    };
    microcode_versions = { intel = pkgs.microcode-intel.version; amd = pkgs.microcode-amd.version; };
  };
  buildMetadata = pkgs.runCommand "tiaris-nest-system-build.json" { nativeBuildInputs = [ pkgs.python3 ]; } ''
    python3 ${./metadata.py} build ${pkgs.writeText "metadata.json" (builtins.toJSON metadataBase)} ${migrations}/sqlite-migrations.json ${sourceArchive}/${manageSourceRevision}.tar $out
  '';
  unsignedCache = import ./closure.nix { inherit pkgs buildMetadata sourceDateEpoch; toplevel = installed.config.system.build.toplevel; };
in
assert system == "x86_64-linux";
assert builtins.match "[0-9a-f]{40}" sourceRevision != null;
assert builtins.match "[0-9a-f]{40}" manageSourceRevision != null;
assert builtins.length publicKeys >= 1 && builtins.length publicKeys <= 8;
assert publicKeys == lib.sort builtins.lessThan (lib.unique publicKeys);
{
  inherit package unsignedCache buildMetadata workstationAgent workstationCacheSeeds installerKiosk;
  # The stick image, exported beside the template ISO (RELEASES.md).
  inherit usbInstaller;
  workstationCacheSeedPaths = map toString workstationCacheSeeds.packages;
  system = installed.config.system.build.toplevel;
  iso = live.config.system.build.isoImage;
  inherit (installed) config;
  tests = import ./tests { inherit nixpkgs pkgs common; };
}
