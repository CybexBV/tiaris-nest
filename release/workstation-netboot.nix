{ manageRepo
, system ? "x86_64-linux"
, sourceDateEpoch
}:

let
  sourcePin = builtins.fromJSON (builtins.readFile ./workstation-netboot-source.json);
  # Every name of the Tiaris repository; see tools/github_repositories.py.
  tiarisNames = (builtins.fromJSON (builtins.readFile ./github-repositories.json)).tiaris.names;
  nixpkgsPin = import ./nixpkgs.nix;
  nixpkgs = builtins.fetchTarball {
    inherit (nixpkgsPin) url sha256;
  };
  installer = import (manageRepo + "/deploy/nixos/tiaris-installer-netboot.nix");
  # Tiaris assigns runtime versions in its release tools (deploy/manage/runtime_versions.py,
  # 17 November 2026): its installer takes the pinned version as runtimeVersion. An older
  # Tiaris source reads its own deploy/nixos/workstation-netboot-version, which must match.
  takesVersion = (builtins.functionArgs installer) ? runtimeVersion;
  fileVersion = builtins.replaceStrings [ "\n" ] [ "" ]
    (builtins.readFile (manageRepo + "/deploy/nixos/workstation-netboot-version"));
  sourceRevisionMatches = builtins.match "[0-9a-f]{40}" sourcePin.revision != null;
  nixpkgsRevisionMatches = builtins.match "[0-9a-f]{40}" nixpkgsPin.revision != null;
in
assert builtins.elem sourcePin.repository tiarisNames;
assert sourceRevisionMatches;
assert nixpkgsRevisionMatches;
assert takesVersion || fileVersion == sourcePin.runtime_version;
installer ({
  inherit nixpkgs system sourceDateEpoch;
  repoRoot = manageRepo;
  manageSourceRevision = sourcePin.revision;
  nixpkgsRevision = nixpkgsPin.revision;
} // (if takesVersion then { runtimeVersion = sourcePin.runtime_version; } else { }))
