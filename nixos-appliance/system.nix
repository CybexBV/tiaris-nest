{ config, lib, pkgs, appliance, ... }:
{
  imports = [ ./module.nix ];
  services.qemuGuest.enable = true;
  virtualisation.incus.agent.enable = true;
  systemd.services.incus-agent.unitConfig.ConditionPathExists = "/dev/virtio-ports/org.linuxcontainers.incus";
  services.tiaris-nest = {
    enable = true;
    inherit appliance;
    # Keep the exact workstation agent and the Blueprint custom outputs as
    # cache seeds without starting the agent service on Nest. The signed
    # system closure exports only reachable paths; the module keeps these in
    # the closure and lists them for the daemon to publish into its binary
    # cache. Not the agent's `debug` output: no workstation installs it, and
    # it was 42 MiB of every release and update.
    workstationCacheSeeds =
      map (output: lib.getOutput output appliance.workstationAgent)
        (lib.remove "debug" (appliance.workstationAgent.outputs or [ "out" ]))
      ++ appliance.workstationCacheSeeds.packages;
  };
  networking.hostName = "tiaris-nest";
  system.stateVersion = "26.05";
  boot.loader.systemd-boot.enable = true;
  boot.loader.systemd-boot.editor = false;
  boot.loader.systemd-boot.configurationLimit = 4; # current + 2 known good + pending
  boot.loader.efi.canTouchEfiVariables = true;
  boot.loader.timeout = 3;
  # Include server RAID/HBA, hypervisor, USB/UAS, eMMC, and real-hardware
  # watchdog drivers in initrd so udev can find TIARIS_ROOT and arm the
  # hardware watchdog on bare metal as well as VMs.
  boot.initrd.availableKernelModules = [
    "xhci_pci" "xhci-hcd" "ehci-pci" "ohci-pci" "uhci-hcd"
    "ahci" "ata_piix" "ata_generic" "nvme" "vmd"
    "virtio_pci" "virtio_blk" "virtio_scsi" "sd_mod" "sr_mod"
    "usbhid" "usb_storage" "uas"
    "megaraid_sas" "mpt3sas" "mpi3mr" "smartpqi" "hpsa" "aacraid" "mptsas" "mptspi"
    "hv_vmbus" "hv_storvsc" "vmw_pvscsi" "xen-blkfront"
    "mmc_block" "sdhci" "sdhci-pci" "sdhci-acpi"
    "iTCO_wdt" "lpc_ich" "i2c-i801" "sp5100_tco"
  ];
  boot.initrd.kernelModules = [ "i6300esb" ];
  boot.initrd.systemd.enable = true;
  boot.initrd.systemd.emergencyAccess = false;
  boot.initrd.systemd.settings.Manager = { RuntimeWatchdogSec = "120s"; RebootWatchdogSec = "10min"; };
  boot.initrd.systemd.targets.initrd.unitConfig = { JobTimeoutSec = "180s"; JobTimeoutAction = "reboot-force"; };
  boot.initrd.systemd.services.tiaris-nest-disk-missing = {
    description = "Report missing Nest root disk before emergency reboot";
    wantedBy = [ "emergency.target" ];
    before = [ "emergency.service" ];
    unitConfig = {
      DefaultDependencies = false;
      ConditionPathExists = "!/dev/disk/by-label/TIARIS_ROOT";
    };
    serviceConfig = {
      Type = "oneshot";
      StandardOutput = "journal+console";
      StandardError = "journal+console";
    };
    script = ''
      printf '\n============================================================\n'
      printf 'Tiaris Nest: root disk (TIARIS_ROOT) was not found.\n'
      printf 'Check disk connection or storage controller driver support.\n'
      printf 'Rebooting...\n'
      printf '============================================================\n'
      sleep 3
    '';
  };
  boot.initrd.systemd.services.emergency.serviceConfig.ExecStart = lib.mkForce [ "" "${pkgs.systemd}/bin/systemctl --no-block reboot" ];
  boot.kernelParams = [ "panic=30" "console=ttyS0,115200n8" "console=tty0" ];
  hardware.enableRedistributableFirmware = true;
  hardware.cpu.intel.updateMicrocode = true;
  hardware.cpu.amd.updateMicrocode = true;
  fileSystems."/" = { device = "/dev/disk/by-label/TIARIS_ROOT"; fsType = "ext4"; };
  fileSystems."/boot" = { device = "/dev/disk/by-label/TIARIS_EFI"; fsType = "vfat"; options = [ "umask=0077" ]; };
  fileSystems."/var/lib/tiaris-nest/state" = { device = "/dev/disk/by-label/TIARIS_STATE"; fsType = "ext4"; options = [ "nodev" "nosuid" ]; neededForBoot = true; };
  fileSystems."/nix" = { device = "/var/cache/tiaris-nest/nix"; fsType = "none"; options = [ "bind" "nodev" "nosuid" ]; neededForBoot = true; depends = [ "/" ]; };
  fileSystems."/var/lib/tiaris-nest/control" = { device = "/var/lib/tiaris-nest/state/control"; fsType = "none"; options = [ "bind" "nodev" "nosuid" ]; depends = [ "/var/lib/tiaris-nest/state" ]; };
  fileSystems."/var/lib/tiaris-nest/status" = { device = "/var/lib/tiaris-nest/state/status"; fsType = "none"; options = [ "bind" "nodev" "nosuid" ]; depends = [ "/var/lib/tiaris-nest/state" ]; };
  swapDevices = [ { device = "/dev/disk/by-label/TIARIS_SWAP"; } ];
}
