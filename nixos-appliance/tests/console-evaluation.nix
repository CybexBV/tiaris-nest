{ nixpkgs ? builtins.fetchTarball (let pin = import ../../release/nixpkgs.nix; in { inherit (pin) url sha256; }) }:
let
  configurations = import ./console-config.nix { inherit nixpkgs; };
  inherit (configurations) appliance;
  setup = configurations.setup;
  installed = configurations.installed;
  setupConsole = setup.systemd.services.tiaris-nest-setup-console;
  installedConsole = installed.systemd.services.tiaris-nest-console;
  bootstrap = setup.systemd.services.tiaris-nest-bootstrap.serviceConfig;
  bootstrapPackage = appliance.bootstrap or (appliance.package.bootstrap or appliance.package);
  daemon = installed.systemd.services.tiaris-nest.serviceConfig;
  kiosk = "${appliance.installerKiosk}/bin/tiaris-installer-kiosk";
  noAutomaticLogin = config: !(config.systemd.services."autovt@tty1".enable or true);
  ownsTty1 = unit: unit.serviceConfig.TTYPath == "/dev/tty1"
    && unit.serviceConfig.TTYReset && unit.serviceConfig.TTYVHangup && unit.serviceConfig.TTYVTDisallocate
    # The kiosk's no-DRM text feed is stdout; it must reach tty1.
    && unit.serviceConfig.StandardOutput == "tty" && unit.serviceConfig.StandardInput == "tty"
    && unit.serviceConfig.Restart == "always" && unit.serviceConfig.PAMName == "login"
    && unit.environment.FONTCONFIG_FILE != "";
  menuLabel = setup.isoImage.prependToMenuLabel + setup.system.nixos.distroName + " "
    + setup.system.nixos.label + setup.isoImage.appendToMenuLabel;
  checks = {
    setupMasksAutomaticTty1 = noAutomaticLogin setup;
    installedMasksAutomaticTty1 = noAutomaticLogin installed;
    installedMasksDirectTty1 = !installed.systemd.services."getty@tty1".enable;
    setupMasksDirectTty1 = !setup.systemd.services."getty@tty1".enable;
    # First generic ISO install, 2026-11-18: ttyS0 offered a root login
    # without a password.
    setupHasNoSerialLogin = !setup.systemd.services."serial-getty@ttyS0".enable;
    setupLocksEveryAccount = setup.users.users.root.initialHashedPassword == "!"
      && setup.users.users.nixos.initialHashedPassword == "!"
      && setup.services.getty.autologinUser == null
      && setup.security.sudo.wheelNeedsPassword;
    setupHasVisibleConsole = ownsTty1 setupConsole;
    installedHasVisibleConsole = ownsTty1 installedConsole;
    setupRunsSetupKiosk = setupConsole.serviceConfig.ExecStart == "${kiosk} --nest-setup"
      && setupConsole.environment.TIARIS_NEST_SETUP_STATUS == "/run/tiaris-nest-setup/status.json";
    installedRunsApplianceKiosk = installedConsole.serviceConfig.ExecStart == "${kiosk} --appliance"
      && installedConsole.environment.TIARIS_NEST_CONSOLE_STATUS == "/run/tiaris-nest/console-status.json";
    installedConsoleKeepsGettyOrdering = builtins.elem "getty.target" installedConsole.wantedBy
      && builtins.elem "rescue.service" installedConsole.conflicts
      && installedConsole.serviceConfig.Type == "idle";
    bootstrapPublishesSetupStatus = bootstrap.RuntimeDirectory == "tiaris-nest-setup"
      && bootstrap.RuntimeDirectoryMode == "0755" && bootstrap.RuntimeDirectoryPreserve == "yes"
      && bootstrap.ExecStart == "${bootstrapPackage}/bin/tiaris-nest-bootstrap prepare --setup-status /run/tiaris-nest-setup/status.json";
    daemonPublishesConsoleStatus = daemon.RuntimeDirectory == "tiaris-nest"
      && daemon.RuntimeDirectoryMode == "0755" && daemon.RuntimeDirectoryPreserve == "yes"
      && builtins.elem "/run/tiaris-nest" daemon.ReadWritePaths;
    daemonStaysHardened = daemon.User == "tiaris-nest" && daemon.NoNewPrivileges
      && daemon.ProtectSystem == "strict" && daemon.CapabilityBoundingSet == "";
    setupKeepsBootstrapLogsOffConsole = bootstrap.StandardOutput == "journal"
      && bootstrap.StandardError == "journal";
    # Install journey, 2026-11-21: the bootstrap waited 30 s for network time.
    setupStartsWithoutTimeWait = !(builtins.elem "systemd-time-wait-sync.service"
      setup.systemd.services.tiaris-nest-bootstrap.after);
    setupMenuInstallsTiarisNest = menuLabel == "Install Tiaris Nest";
    setupUsesManageGrubTheme = setup.isoImage.grubTheme == appliance.grubTheme;
    setupHasRequiredInstallTools = let
      pathNames = map (p: p.pname or p.name or "") setup.systemd.services.tiaris-nest-bootstrap.path;
      hasPrefix = prefix: builtins.any (n: builtins.substring 0 (builtins.stringLength prefix) n == prefix) pathNames;
    in builtins.all hasPrefix [
      "parted"
      "efibootmgr"
      "gptfdisk"
      "e2fsprogs"
      "dosfstools"
      "util-linux"
      "iproute2"
      "curl"
      "jq"
      "zstd"
      "smartmontools"
      "nvme-cli"
    ];
    setupAppliesPreclaimUsbBeforeNetworkd =
      builtins.elem "systemd-networkd.service" setup.systemd.services.tiaris-nest-preclaim-network.before
      && builtins.elem "d /run/systemd/network 0755 root root -" setup.systemd.tmpfiles.rules;
  };
in assert builtins.all (value: value) (builtins.attrValues checks); checks
