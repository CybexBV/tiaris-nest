# Shared denylist firmware trim for both the installed Nest appliance
# (`system.nix`) and the Setup ISO (`iso.nix`). Importing the exact same
# module keeps the firmware store path byte-identical between ISO and
# installed system so member-mode installs reuse it straight from the ISO.
#
# Denylist strategy: strip hardware families a wired x86_64 server appliance
# never uses (Wi-Fi, Bluetooth, audio/DSP, cameras/IPU/VPU, DVB/media, ARM/SoC
# blobs, data-center switch ASICs, discrete NVIDIA GPU firmware) while keeping
# all wired server NICs, storage HBAs, CPU microcode, and Intel/AMD KMS
# firmware (i915, xe, amdgpu, radeon) so tty1 stays visible.
{ lib, pkgs, ... }:
let
  removePaths = [
    # ARM / mobile / embedded SoCs and GPUs
    "qcom" "mediatek" "meson" "rockchip" "amlogic" "amphion" "arm" "cnm"
    "imx" "moxa" "nxp" "ti" "ti-keystone" "dpaa2" "airoha" "amdnpu"
    "amdxdna" "powervr" "imagination" "panthor" "mali*" "adreno*" "habanalabs"
    "tegra*"
    # Discrete NVIDIA GPU firmware (nouveau is blacklisted below so tty1 uses simpledrm)
    "nvidia"
    # Data-center switch ASICs (not server NICs)
    "mellanox/mlxsw*" "mrvl/prestera"
    # Wi-Fi and Bluetooth radios
    "intel/iwlwifi" "iwlwifi*" "intel/ibt*"
    "ath6k" "ath9k*" "ath10k" "ath11k" "ath12k" "ar3k" "ar5523*" "carl9170*"
    "htc_*" "qca" "wil6210*"
    "brcm" "cypress" "libertas" "lbtf_*" "mwl8k" "mwlwifi" "rsi" "wfx" "zd1211"
    "rtw88" "rtw89" "rtlwifi" "rt2*" "rt73*" "ti-connectivity"
    "mrvl/sd8*" "mrvl/usb8*" "mrvl/pcie*" "mrvl/sdsd*" "mrvl/usbusb*"
    "mwifiex*" "atmel"
    # Audio, DSP, cameras, IPU, VPU, ISH, DVB, video capture
    "intel/avs" "intel/catpt" "intel/dsp_fw*" "intel/ipu" "intel/irci*"
    "intel/ish" "intel/vpu" "intel/vsc" "intel/sof*"
    "cirrus" "cs35l*" "ess" "korg" "sb16" "yamaha"
    "av7110" "dvb-*" "s5p-*" "s2250*" "v4l-*"
    "LENOVO" "dell" "HP"
  ];
  trimmedFirmware = pkgs.runCommand "tiaris-nest-linux-firmware-${pkgs.linux-firmware.version}" { } ''
    mkdir -p "$out/lib"
    cp -a ${pkgs.linux-firmware}/lib/firmware "$out/lib/firmware"
    chmod -R u+w "$out/lib/firmware"
    cd "$out/lib/firmware"
    shopt -s nullglob
    ${lib.concatMapStringsSep "\n" (pattern: "rm -rf -- ${pattern}") removePaths}
    # Drop symlinks whose targets were intentionally stripped above, then verify
    # no remaining symlink is broken.
    find "$out/lib/firmware" -xtype l -delete
    broken="$(find -L "$out/lib/firmware" -type l -print)"
    if [ -n "$broken" ]; then
      printf 'unexpected broken firmware symlinks:\n%s\n' "$broken" >&2
      exit 1
    fi
    # Verify core wired server NIC and KMS directories survived the denylist.
    for required in i915 xe amdgpu intel/ice bnx2x cxgb4 qed rtl_nic; do
      if [ ! -e "$out/lib/firmware/$required" ]; then
        printf 'missing required Nest firmware path: %s\n' "$required" >&2
        exit 1
      fi
    done
  '';
in
{
  hardware.enableRedistributableFirmware = lib.mkForce false;
  hardware.enableAllFirmware = lib.mkForce false;
  hardware.firmware = [ trimmedFirmware ];
  # Without NVIDIA firmware, keep nouveau unloaded so the kernel stays on
  # simpledrm/EFI framebuffer and the tty1 Canopy console remains visible.
  boot.blacklistedKernelModules = [ "nouveau" ];
}
