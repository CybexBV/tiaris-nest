{ config, lib, pkgs, modulesPath, appliance, ... }:
let
  a = appliance;
  bootstrap = a.bootstrap or (a.package.bootstrap or a.package);
  slot = pkgs.runCommand "tiaris-provisioning-slot" {} ''
    dd if=/dev/zero of=$out bs=8192 count=1 status=none
  '';
  key = pkgs.writeText "release-public-key" (a.releasePublicKey + "\n");
  keys = pkgs.writeText "provisioning-public-keys" (lib.concatStringsSep "\n" a.provisioningPublicKeys + "\n");
  setupStatus = "/run/tiaris-nest-setup/status.json";
in {
  imports = [
    (modulesPath + "/profiles/minimal.nix")
    (modulesPath + "/installer/scan/detected.nix")
    (modulesPath + "/installer/scan/not-detected.nix")
    (import ./single-menu-iso-module.nix { nixpkgs = appliance.nixpkgsPath; })
    ./firmware.nix
  ];
  networking.hostName = "tiaris-nest-setup";
  system.stateVersion = "26.05";
  system.tools.nixos-rebuild.enable = false;
  documentation.enable = lib.mkForce false;
  documentation.man.enable = lib.mkForce false;
  documentation.doc.enable = lib.mkForce false;
  documentation.info.enable = lib.mkForce false;
  documentation.nixos.enable = lib.mkForce false;
  fonts.fontconfig.enable = lib.mkForce false;
  programs.git.enable = lib.mkForce false;
  environment.defaultPackages = lib.mkForce [ ];
  hardware.cpu.intel.updateMicrocode = true;
  hardware.cpu.amd.updateMicrocode = true;
  swapDevices = lib.mkImageMediaOverride [ ];
  fileSystems = lib.mkImageMediaOverride config.lib.isoFileSystems;
  boot.initrd.luks.devices = lib.mkImageMediaOverride { };
  boot.supportedFilesystems = lib.mkForce [ "ext4" "vfat" ];
  boot.initrd.availableKernelModules = [
    "xhci_pci" "xhci-hcd" "ehci-pci" "ohci-pci" "uhci-hcd"
    "ahci" "ata_piix" "ata_generic" "nvme" "vmd"
    "sata_sil24" "sata_via" "sata_nv" "sata_promise"
    "virtio_pci" "virtio_blk" "virtio_scsi" "sd_mod" "sr_mod"
    "usbhid" "usb_storage" "uas"
    "megaraid_sas" "mpt3sas" "mpi3mr" "smartpqi" "hpsa" "aacraid" "mptsas" "mptspi"
    "3w-9xxx" "arcmsr" "aic79xx"
    "hv_vmbus" "hv_storvsc" "vmw_pvscsi" "xen-blkfront"
    "mmc_block" "sdhci" "sdhci-pci" "sdhci-acpi"
  ];
  boot.initrd.systemd.enable = true;
  boot.kernel.sysctl."vm.overcommit_memory" = "1";
  environment.variables.GC_INITIAL_HEAP_SIZE = "1M";
  environment.etc."systemd/pstore.conf".text = ''
    [PStore]
    Unlink=no
  '';
  boot.kernelParams = [ "console=ttyS0,115200n8" "console=tty0" "panic=30" ];
  boot.loader.timeout = lib.mkForce 3;
  boot.loader.grub.memtest86.enable = lib.mkForce false;
  isoImage = {
    makeEfiBootable = true;
    makeUsbBootable = true;
    makeBiosBootable = false;
    volumeID = "TIARIS_NEST_SETUP";
    grubTheme = a.grubTheme;
    # The pinned module labels its entry prepend + distroName + " " + label.
    # single-menu-iso-module.nix removes every other entry, so the menu is
    # exactly "Install Tiaris Nest".
    prependToMenuLabel = "Install ";
    appendToMenuLabel = "";
    squashfsCompression = "zstd -Xcompression-level 10";
    contents = [
      { source = slot; target = "/TIARIS_PROVISIONING.BIN"; }
      { source = key; target = "/tiaris/release-public-key"; }
      { source = keys; target = "/tiaris/provisioning-public-keys"; }
      { source = pkgs.writeText "nixos-appliance" "3\n"; target = "/tiaris/nixos-appliance"; }
      { source = "${bootstrap}/bin/tiaris-nest-bootstrap"; target = "/tiaris/bootstrap/tiaris-nest-bootstrap"; }
    ];
  };
  image.baseName = lib.mkForce "tiaris-nest-appliance-template-${a.package.version}-x86_64-linux";
  system.nixos.distroName = lib.mkForce "Tiaris";
  system.nixos.label = lib.mkForce "Nest";
  networking.networkmanager.enable = lib.mkForce false;
  networking.useDHCP = lib.mkForce false;
  networking.useNetworkd = true;
  systemd.network.enable = true;
  systemd.network.networks."20-tiaris-installer" = { matchConfig.Name = "en* eth*"; networkConfig = { DHCP = "ipv4"; IPv6AcceptRA = false; }; };
  services.resolved.enable = true;
  # The bootstrap does not wait for network time: until timesyncd sets the
  # clock, Tiaris's verified HTTPS answers do (src/provisioning/clock.rs).
  services.timesyncd.enable = true;
  services.openssh.enable = lib.mkForce false;
  services.getty.autologinUser = lib.mkForce null;
  # Lock both accounts and start no serial getty; kernel messages still reach
  # ttyS0, which is all qualification reads from it.
  users.users.root.initialHashedPassword = lib.mkForce "!";
  users.users.nixos = { isNormalUser = true; initialHashedPassword = lib.mkForce "!"; };
  services.getty.helpLine = lib.mkForce "";
  security.sudo.wheelNeedsPassword = lib.mkForce true;
  systemd.services."serial-getty@ttyS0".enable = false;
  environment.systemPackages = [ bootstrap pkgs.nix pkgs.nixos-install-tools pkgs.iputils pkgs.iproute2 pkgs.gptfdisk pkgs.parted pkgs.efibootmgr pkgs.e2fsprogs pkgs.dosfstools pkgs.util-linux pkgs.curl pkgs.jq pkgs.zstd pkgs.python3 pkgs.smartmontools pkgs.nvme-cli ];
  systemd.tmpfiles.rules = [
    "d /run/systemd/network 0755 root root -"
  ];
  nix.settings = { experimental-features = [ "nix-command" ]; substituters = lib.mkForce []; trusted-public-keys = lib.mkForce [ "tiaris-nest-appliance-1:${a.releasePublicKey}" ]; };
  systemd.services.tiaris-nest-preclaim-network = {
    description = "Apply pre-claim static IPv4 from USB before networkd starts";
    wantedBy = [ "network-pre.target" ];
    before = [ "systemd-networkd.service" "network-pre.target" ];
    after = [ "systemd-udevd.service" "systemd-udev-trigger.service" "local-fs.target" "systemd-tmpfiles-setup.service" ];
    path = [ pkgs.util-linux pkgs.systemd pkgs.iproute2 ];
    unitConfig.DefaultDependencies = false;
    serviceConfig = {
      Type = "oneshot";
      ExecStartPre = "-${pkgs.systemd}/bin/udevadm settle --timeout=10";
      ExecStart = "${bootstrap}/bin/tiaris-nest-bootstrap apply-preclaim-usb --no-reload";
      TimeoutStartSec = "30s";
      UMask = "0077";
    };
  };
  systemd.services.tiaris-nest-bootstrap = {
    wantedBy = [ "multi-user.target" ]; after = [ "network-online.target" ]; wants = [ "network-online.target" ];
    path = config.environment.systemPackages;
    preStart = ''
      mkdir -p /cdrom
      mountpoint -q /cdrom || mount --bind /iso /cdrom
    '';
    # The public setup projection for the tty1 kiosk. Preserve it across
    # restarts so a stopped or failed screen stays readable meanwhile.
    serviceConfig = { Type = "simple"; ExecStart = "${bootstrap}/bin/tiaris-nest-bootstrap prepare --setup-status ${setupStatus}"; Restart = "on-failure"; RestartSec = "15s"; StandardOutput = "journal"; StandardError = "journal"; UMask = "0077"; TimeoutStartSec = "infinity"; RuntimeDirectory = "tiaris-nest-setup"; RuntimeDirectoryMode = "0755"; RuntimeDirectoryPreserve = "yes"; };
  };
  systemd.services."getty@tty1".enable = false;
  # getty.target and logind use this alias, not getty@tty1. Mask the exact
  # instance as well so neither boot nor a VT switch starts a login prompt.
  systemd.services."autovt@tty1".enable = false;
  # Native Canopy setup screen (Slint software renderer straight to KMS).
  # Without a usable DRM output it prints its own line-oriented text feed,
  # so tty1 stays readable on nomodeset and serial-only machines.
  systemd.services.tiaris-nest-setup-console = {
    description = "Tiaris Nest setup screen";
    wantedBy = [ "multi-user.target" ];
    after = [ "systemd-logind.service" "systemd-user-sessions.service" ];
    environment = {
      TIARIS_NEST_SETUP_STATUS = setupStatus;
      # Slint embeds the Canopy faces but builds its fallback map through
      # Fontconfig; the ISO has no global Fontconfig profile.
      FONTCONFIG_FILE = "${pkgs.fontconfig.out}/etc/fonts/fonts.conf";
      XDG_RUNTIME_DIR = "/run/tiaris-nest-setup-console";
      HOME = "/root";
    };
    serviceConfig = { Type = "simple"; ExecStart = "${a.installerKiosk}/bin/tiaris-installer-kiosk --nest-setup"; Restart = "always"; RestartSec = "2s"; StandardInput = "tty"; StandardOutput = "tty"; StandardError = "journal"; TTYPath = "/dev/tty1"; TTYReset = true; TTYVHangup = true; TTYVTDisallocate = true; UtmpIdentifier = "tty1"; UtmpMode = "user"; PAMName = "login"; RuntimeDirectory = "tiaris-nest-setup-console"; RuntimeDirectoryMode = "0700"; };
  };
  # Guided pre-claim static IPv4 configurator on tty2 (Alt+F2) for networks
  # without DHCP. Replaces getty@tty2 with a bounded L3-only prompt (no shell).
  systemd.services."getty@tty2".enable = false;
  systemd.services."autovt@tty2".enable = false;
  systemd.services.tiaris-nest-setup-network = {
    description = "Tiaris Nest pre-claim static IPv4 setup";
    wantedBy = [ "multi-user.target" ];
    after = [ "systemd-networkd.service" "systemd-user-sessions.service" ];
    path = [ pkgs.systemd pkgs.iproute2 ];
    serviceConfig = {
      Type = "simple";
      ExecStart = "${bootstrap}/bin/tiaris-nest-bootstrap configure-setup-network";
      Restart = "always";
      RestartSec = "2s";
      StandardInput = "tty";
      StandardOutput = "tty";
      StandardError = "tty";
      TTYPath = "/dev/tty2";
      TTYReset = true;
      TTYVHangup = true;
      TTYVTDisallocate = true;
    };
  };
}
