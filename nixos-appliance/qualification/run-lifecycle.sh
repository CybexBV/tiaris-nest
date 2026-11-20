#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

usage() {
  echo "usage: $0 --template ISO --manifest JSON --manage-origin URL --token-file FILE --output FILE [--published-predecessor-inputs JSON] [--retain-fixture DIRECTORY] [--require-candidate-runtime | --prepublication-candidate] [--proxmox-reinstall-over FIXTURE_DIRECTORY]" >&2
  exit 2
}

repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
template=""
manifest=""
manage_origin=""
token_file=""
output=""
published_predecessor_inputs=""
predecessor_identity=""
fixture_dir=""
require_candidate_runtime=false
prepublication_candidate=false
proxmox_reinstall_over=""
while (($#)); do
  case "$1" in
    --template) template="${2:-}"; shift 2 ;;
    --manifest) manifest="${2:-}"; shift 2 ;;
    --manage-origin) manage_origin="${2:-}"; shift 2 ;;
    --token-file) token_file="${2:-}"; shift 2 ;;
    --predecessor-identity) predecessor_identity="${2:-}"; shift 2 ;;
    --published-predecessor-inputs) published_predecessor_inputs="${2:-}"; shift 2 ;;
    --retain-fixture) fixture_dir="${2:-}"; shift 2 ;;
    --require-candidate-runtime) require_candidate_runtime=true; shift ;;
    --prepublication-candidate) prepublication_candidate=true; shift ;;
    --proxmox-reinstall-over) proxmox_reinstall_over="${2:-}"; shift 2 ;;
    --output) output="${2:-}"; shift 2 ;;
    *) usage ;;
  esac
done
if [[ "$prepublication_candidate" = true ]] \
  && { [[ "$require_candidate_runtime" = true ]] || [[ -n "$published_predecessor_inputs" ]]; }; then
  echo 'error: prepublication deferral applies only to an unpublished candidate' >&2
  exit 1
fi
test -f "$template" && test -f "$manifest" && test -f "$token_file" && test -n "$output"
if [[ -n "$fixture_dir" ]]; then
  [[ "$fixture_dir" = /* ]] && test ! -e "$fixture_dir" && test ! -L "$fixture_dir"
fi
if [[ -n "$proxmox_reinstall_over" ]]; then
  # Reinstall over an older Nest the way a Proxmox VM does it: the disk and
  # persistent UEFI variables of a retained fixture (--retain-fixture), booted
  # on i440FX with OVMF without SMM or Secure Boot. The fixture is copied, not
  # consumed. The update wrapper boots q35, so this run retains no fixture.
  if [[ -n "$fixture_dir" ]]; then
    echo 'error: a Proxmox-like reinstall run cannot retain an update fixture' >&2
    exit 1
  fi
  test "$(jq -er '.schema' "$proxmox_reinstall_over/fixture.json")" = tiaris.nest.qualification-fixture.v1
  test -f "$proxmox_reinstall_over/appliance.raw" && test -f "$proxmox_reinstall_over/OVMF_VARS.fd"
fi
# The generic ISO is claimed with the code on its screen. Only the isolated
# fixture can read that code (from its own database), so qualification installs
# only against the fixture's Manage, reached through its root-private socket.
test -S "${TIARIS_NEST_QUALIFICATION_STATE:?set the owned development fixture directory}/manage.sock" || {
  echo 'error: qualification claims the generic ISO through the isolated Manage fixture only' >&2
  exit 1
}
python3 -B "$repository_root/nixos-appliance/qualification/development-scope.py" verify \
  --state-dir "${TIARIS_NEST_QUALIFICATION_STATE:?set the owned development fixture directory}" \
  --manage-origin "$manage_origin" \
  --bridge "${TIARIS_NEST_QUALIFICATION_BRIDGE:?set the owned development bridge}"
for command_name in cmp git jq python3 qemu-system-x86_64 truncate sha256sum ssh-keygen ssh rg; do
  command -v "$command_name" >/dev/null || { echo "error: missing $command_name" >&2; exit 1; }
done
python3 -B "$repository_root/tools/nest-release.py" validate-manage-origin \
  --expected-manage-origin "$manage_origin" >/dev/null
test "$(jq -er '.installer_iso_template_v3.manage_origin' "$manifest")" = \
  "$manage_origin"
# New candidates must bind the same exact Nest source used by this harness.
# Legacy descriptors remain supported only when verifying published predecessors.
source_revision="$(git -C "$repository_root" rev-parse HEAD)"
qualification_kind=candidate
if [[ -n "$published_predecessor_inputs" ]]; then
  echo 'error: use a separately verified NixOS predecessor; Ubuntu is reinstall-only' >&2
  exit 1
fi
if [[ -n "$predecessor_identity" ]]; then
  test "$(jq -er '.schema' "$predecessor_identity")" = tiaris.nest.nixos-qualification-predecessor.v1
  test "$(jq -er '.manifest_sha256' "$predecessor_identity")" = "$(sha256sum "$manifest" | awk '{print $1}')"
  qualification_kind=predecessor
fi
jq -e --arg source_revision "$source_revision" --argjson predecessor "$([[ -n "$predecessor_identity" ]] && echo true || echo false)" '
  .appliance_release_v1
  | .schema == "tiaris.nest.appliance-release.v3"
    and (.source_revision == $source_revision or $predecessor == true)
' "$manifest" >/dev/null || {
  echo 'error: qualification requires the exact source-bound V3 candidate' >&2
  exit 1
}
bridge="${TIARIS_NEST_QUALIFICATION_BRIDGE:?set the isolated qualification bridge}"
hardware="$(python3 -B "$repository_root/nixos-appliance/qualification/development-scope.py" hardware \
  --state-dir "$TIARIS_NEST_QUALIFICATION_STATE" --manage-origin "$manage_origin" --bridge "$bridge" --role appliance)"
appliance_mac="$(jq -er '.mac' <<<"$hardware")"
appliance_serial="$(jq -er '.serial' <<<"$hardware")"
appliance_uuid="$(jq -er '.uuid' <<<"$hardware")"
management_cidr="${TIARIS_NEST_QUALIFICATION_MANAGEMENT_CIDR:?set the qualification Management CIDR}"
memory_mib="${TIARIS_NEST_QUALIFICATION_MEMORY_MIB:-18432}"
[[ "$memory_mib" =~ ^[0-9]+$ ]] && ((memory_mib >= 16384 && memory_mib <= 65536))
test -n "$(tr -d '\r\n' < "$token_file")"
release_version="$(jq -er '.version' "$manifest")"
system_closure_sha256="$(jq -er '.appliance_release_v1.system_closure.sha256' "$manifest")"
has_predecessor="${TIARIS_NEST_HAS_PREDECESSOR:?set the governed predecessor state}"
case "$has_predecessor" in
  true|false) ;;
  *) echo 'error: invalid governed predecessor state' >&2; exit 1 ;;
esac

work_dir="$(mktemp -d)"
qemu_pid=""
tap_name=""
session_id=""
lifecycle_succeeded=false
cleanup() {
  if [[ -n "$qemu_pid" ]] && kill -0 "$qemu_pid" 2>/dev/null; then
    kill "$qemu_pid" 2>/dev/null || true
    wait "$qemu_pid" 2>/dev/null || true
  fi
  if [[ -n "$tap_name" ]]; then
    python3 -B "$repository_root/nixos-appliance/qualification/development-scope.py" tap-delete \
      --state-dir "$TIARIS_NEST_QUALIFICATION_STATE" --manage-origin "$manage_origin" \
      --bridge "$bridge" --role appliance
  fi
  if [[ -n "$session_id" && "$lifecycle_succeeded" != true ]]; then
    cleanup_session="$work_dir/cleanup-session.json"
    if api GET "/v1/nest/provisioning-sessions/$session_id" > "$cleanup_session" 2>/dev/null \
      && [[ "$(jq -r '.destructive_started_at // ""' "$cleanup_session")" = "" ]] \
      && [[ "$(jq -r '.state' "$cleanup_session")" =~ ^(created|claimed|awaiting_approval|approved|failed)$ ]]
    then
      api POST "/v1/nest/provisioning-sessions/$session_id/revoke" '{}' >/dev/null 2>&1 || true
    fi
  fi
  if [[ "$lifecycle_succeeded" = true && -n "$fixture_dir" ]]; then
    # Stop the VM before handing off its disk. The update wrapper owns the next
    # boot and final cleanup; no daemon or stale device-ID variable is retained.
    mkdir -m 0700 -- "$fixture_dir"
    mv -- "$work_dir/appliance.raw" "$work_dir/OVMF_VARS.fd" "$fixture_dir/"
    jq -n --arg device_id "$device_id" --arg bridge "$bridge" \
      --argjson hardware "$hardware" \
      --arg manifest_sha256 "$(sha256sum "$manifest" | awk '{print $1}')" \
      '{schema:"tiaris.nest.qualification-fixture.v1",device_id:$device_id,
        bridge:$bridge,manifest_sha256:$manifest_sha256} + $hardware' \
      > "$fixture_dir/fixture.json"
  fi
  if [[ "$lifecycle_succeeded" != true && -n "${TIARIS_NEST_QUALIFICATION_FAILURE_DIRECTORY:-}" && -f "$work_dir/appliance.raw" ]]; then
    # Private local diagnostics only. The owner removes these with the private
    # database; they must never be uploaded as public qualification evidence.
    mkdir -m 0700 -- "$TIARIS_NEST_QUALIFICATION_FAILURE_DIRECTORY"
    mv -- "$work_dir/appliance.raw" "$work_dir/OVMF_VARS.fd" "$work_dir/serial.log" "$TIARIS_NEST_QUALIFICATION_FAILURE_DIRECTORY/"
  fi
  if [[ -n "$session_id" && -f "$work_dir/serial.log" ]]; then
    cp -- "$work_dir/serial.log" "$(dirname -- "$output")/serial-$session_id.log"
    chmod 0600 "$(dirname -- "$output")/serial-$session_id.log"
  fi
  rm -rf -- "$work_dir"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

api() {
  local path="$2" body="${3:-}"
  local rpc_args=(--state-dir "$TIARIS_NEST_QUALIFICATION_STATE" api --path "$path")
  if [[ -n "$body" ]]; then rpc_args+=(--body "$body"); fi
  python3 -B "$repository_root/nixos-appliance/qualification/isolated_manage_rpc.py" "${rpc_args[@]}"
}


# Capture exact released revisions before package staging or VM work. The same
# read-only admission runs in Tiaris readiness. Never reset built-ins to v1.
blueprints="$work_dir/blueprints.json"
python3 -B "$repository_root/nixos-appliance/qualification/blueprint-catalog.py" \
  --manage-origin "$manage_origin" --token-file "$token_file" --state-dir "$TIARIS_NEST_QUALIFICATION_STATE" \
  --fixture-blueprint "${TIARIS_NEST_QUALIFICATION_FIXTURE_BLUEPRINT:-qualification_dock}" \
  > "$blueprints"

# The fixture serves the release's closure privately and its Manage hands that
# copy to the claimed setup (TIARIS_DEV_NEST_APPLIANCE_CLOSURE_TRANSPORT_URL).
test "$(jq -er '.installer_iso_template_v3.package_delivery' "$manifest")" = system-closure-v1

# Boot the release's generic ISO itself, read-only: the same bytes every
# administrator downloads. Its signed template declares the claim protocol and
# its slot is all zeros, so the bootstrap registers for a claim.
manifest_sha256="$(sha256sum "$manifest" | awk '{print $1}')"
template_sha256="$(jq -er '.installer_iso_template_v3.template_sha256' "$manifest")"
test "$(stat -c '%s' "$template")" = "$(jq -er '.installer_iso_template_v3.size_bytes' "$manifest")"
test "$(sha256sum "$template" | awk '{print $1}')" = "$template_sha256"
jq -e '.installer_iso_template_v3.setup_claim_protocol | type == "number" and . >= 1' "$manifest" >/dev/null || {
  echo 'error: the release ISO does not support the setup claim' >&2
  exit 1
}
slot_offset="$(jq -er '.installer_iso_template_v3.personalization_offset' "$manifest")"
test "$(jq -er '.installer_iso_template_v3.personalization_size' "$manifest")" = 8192
cmp -s -n 8192 -i "$slot_offset:0" -- "$template" /dev/zero || {
  echo 'error: the release ISO is not generic: its setup slot is not empty' >&2
  exit 1
}

disk="$work_dir/appliance.raw"
if [[ -n "$proxmox_reinstall_over" ]]; then
  cp --sparse=always -- "$proxmox_reinstall_over/appliance.raw" "$disk"
else
  truncate -s 160G "$disk"
fi
preapproval_digest="$(python3 -B "$repository_root/nixos-appliance/qualification/disk-fingerprint.py" "$disk")"
vars_template="${TIARIS_NEST_OVMF_VARS:-/usr/share/OVMF/OVMF_VARS_4M.fd}"
code="${TIARIS_NEST_OVMF_CODE:-/usr/share/OVMF/OVMF_CODE_4M.secboot.fd}"
if [[ -n "$proxmox_reinstall_over" ]]; then
  vars_template="$proxmox_reinstall_over/OVMF_VARS.fd"
  code="${TIARIS_NEST_OVMF_CODE:-/usr/share/OVMF/OVMF_CODE_4M.fd}"
fi
test -f "$vars_template" && test -f "$code"
cp -- "$vars_template" "$work_dir/OVMF_VARS.fd"

start_qemu() {
  tap_name="$(python3 -B "$repository_root/nixos-appliance/qualification/development-scope.py" tap-create \
    --state-dir "$TIARIS_NEST_QUALIFICATION_STATE" --manage-origin "$manage_origin" --bridge "$bridge" --role appliance)"
  if [[ -n "$proxmox_reinstall_over" ]]; then
    start_proxmox_like_qemu
    return
  fi
  qemu-system-x86_64 \
    -enable-kvm -machine q35,smm=on -global driver=cfi.pflash01,property=secure,value=on -cpu host -smp 4 -m "$memory_mib" -uuid "$appliance_uuid" \
    -drive "if=pflash,format=raw,unit=0,readonly=on,file=$code" \
    -drive "if=pflash,format=raw,unit=1,file=$work_dir/OVMF_VARS.fd" \
    -drive "if=none,id=system,format=raw,file=$disk,cache=none" \
    -device virtio-scsi-pci,id=scsi0 -device "scsi-hd,drive=system,serial=$appliance_serial" \
    -drive "if=none,id=installer,media=cdrom,readonly=on,format=raw,file=$template" \
    -device ide-cd,drive=installer \
    -netdev "tap,id=net0,ifname=$tap_name,script=no,downscript=no" -device "virtio-net-pci,netdev=net0,id=nic0,mac=$appliance_mac,bus=pcie.0,addr=0x3" \
    -device i6300esb,bus=pcie.0,addr=0x4 -watchdog-action reset \
    -boot "once=d,menu=off" -display none -serial "file:$work_dir/serial.log" \
    -qmp "unix:$work_dir/qmp.sock,server=on,wait=off" &
  qemu_pid=$!
}

# Proxmox's default VM (i440FX + PIIX, virtio-scsi, IDE CD-ROM) with the same
# NIC and watchdog slots as the q35 guest.
start_proxmox_like_qemu() {
  qemu-system-x86_64 \
    -enable-kvm -machine pc -cpu host -smp 4 -m "$memory_mib" -uuid "$appliance_uuid" \
    -drive "if=pflash,format=raw,unit=0,readonly=on,file=$code" \
    -drive "if=pflash,format=raw,unit=1,file=$work_dir/OVMF_VARS.fd" \
    -drive "if=none,id=system,format=raw,file=$disk,cache=none" \
    -device virtio-scsi-pci,id=scsi0,bus=pci.0,addr=0x5 -device "scsi-hd,drive=system,serial=$appliance_serial" \
    -drive "if=none,id=installer,media=cdrom,readonly=on,format=raw,file=$template" \
    -device ide-cd,drive=installer \
    -netdev "tap,id=net0,ifname=$tap_name,script=no,downscript=no" -device "virtio-net-pci,netdev=net0,id=nic0,mac=$appliance_mac,bus=pci.0,addr=0x3" \
    -device i6300esb,bus=pci.0,addr=0x4 -watchdog-action reset \
    -boot "once=d,menu=off" -display none -serial "file:$work_dir/serial.log" \
    -qmp "unix:$work_dir/qmp.sock,server=on,wait=off" &
  qemu_pid=$!
}

start_qemu

# Claim the guest with the code on its screen, which the fixture reads from its
# own database. The claim installs the release the fixture's Manage publishes;
# the fixture refuses unless that is this manifest.
claim="$work_dir/claim.json"
for _attempt in $(seq 1 180); do
  python3 -B "$repository_root/nixos-appliance/qualification/isolated_manage_rpc.py" \
    --state-dir "$TIARIS_NEST_QUALIFICATION_STATE" claim-setup \
    --label "Nest release qualification $release_version" --manifest-sha256 "$manifest_sha256" > "$claim"
  if [[ "$(jq -r 'type' "$claim")" = object ]]; then break; fi
  kill -0 "$qemu_pid"
  sleep 5
done
session_id="$(jq -er '.session.id' "$claim")"
test "$(jq -er '.session.created_by_setup_claim' "$claim")" = true
test "$(jq -er '.session.release_version' "$claim")" = "$release_version"
# Manage's answer names the release, not the ISO's hash. The ISO is bound to
# this manifest above, and the fixture refuses a claim for another manifest.
if [[ -n "${TIARIS_NEST_QUALIFICATION_SESSION_RECEIPT:-}" ]]; then
  test ! -e "$TIARIS_NEST_QUALIFICATION_SESSION_RECEIPT"
  jq -n --arg session_id "$session_id" '{session_id:$session_id}' > "$TIARIS_NEST_QUALIFICATION_SESSION_RECEIPT"
  chmod 0600 "$TIARIS_NEST_QUALIFICATION_SESSION_RECEIPT"
fi

session="$work_dir/session.json"
claimed=false
for _attempt in $(seq 1 180); do
  api GET "/v1/nest/provisioning-sessions/$session_id" > "$session"
  state="$(jq -er '.state' "$session")"
  if [[ "$state" = awaiting_approval ]]; then claimed=true; break; fi
  [[ "$state" != failed && "$state" != revoked && "$state" != expired ]]
  kill -0 "$qemu_pid"
  sleep 5
done
test "$claimed" = true
test "$(jq -r '.inventory.secure_boot' "$session")" = false
test "$(jq -er '.inventory.boot_mode' "$session")" = uefi
test "$(jq -er '.blockers | length' "$session")" = 0
test "$(jq -er '[.inventory.disks[] | select(.eligible == true)] | length' "$session")" = 1
# The claimed server is the owned guest: its own disk serial and NIC address.
test "$(jq -er '.inventory.disks[] | select(.eligible == true) | .serial' "$session")" = "$appliance_serial"
jq -e --arg mac "$appliance_mac" \
  '[.inventory.ethernet_interfaces[] | select((.mac | ascii_downcase) == ($mac | ascii_downcase))] | length == 1' \
  "$session" >/dev/null
test "$(python3 -B "$repository_root/nixos-appliance/qualification/disk-fingerprint.py" "$disk")" = "$preapproval_digest"

revision="$(jq -er '.session_revision' "$session")"
inventory_sha="$(jq -er '.inventory_sha256' "$session")"
disk_id="$(jq -er '.inventory.disks[] | select(.eligible == true) | .id' "$session")"
interface_id="$(jq -er '.inventory.ethernet_interfaces[] | select(.link_up == true) | .id' "$session" | head -n 1)"
session_suffix="${session_id%%-*}"
approve_body="$(jq -cn \
  --argjson revision "$revision" --arg inventory "$inventory_sha" \
  --arg disk "$disk_id" --arg interface "$interface_id" --arg cidr "$management_cidr" \
  --arg display_name "Nest release qualification $release_version $session_suffix" \
  --argjson weekday "$(date -u +%w)" --arg start "$(date -u +%H:%M)" \
  '{session_revision:$revision,inventory_sha256:$inventory,display_name:$display_name,target_disk_id:$disk,network:{mode:"dhcp",interface_id:$interface,address_cidr:null,gateway:null,dns_servers:[]},maintenance_window:{timezone:"UTC",weekday:$weekday,start:$start,duration_minutes:240},management_cidrs:[$cidr]}')"
printf '%s\n' "$approve_body" > "$work_dir/initial-approval.json"
api POST "/v1/nest/provisioning-sessions/$session_id/approve" "$approve_body" > "$work_dir/initial-approved.json"
python3 -B "$repository_root/nixos-appliance/qualification/isolated_manage_rpc.py" \
  --state-dir "$TIARIS_NEST_QUALIFICATION_STATE" allow-device --session-id "$session_id"

ready=false
reboot_deadline=0
pre_destructive_deadline=$((SECONDS + 300))
for _attempt in $(seq 1 1080); do
  api GET "/v1/nest/provisioning-sessions/$session_id" > "$session"
  state="$(jq -er '.state' "$session")"
  if [[ "$state" = ready ]]; then ready=true; break; fi
  if [[ -s "$work_dir/serial.log" ]] \
    && grep -aF 'An error occurred. Press enter to start a shell' "$work_dir/serial.log" >/dev/null
  then
    echo 'error: installer entered a fatal recovery shell' >&2
    echo 'bounded qualification serial console follows:' >&2
    tail -n 500 "$work_dir/serial.log" >&2
    exit 1
  fi
  if [[ "$state" = failed || "$state" = revoked || "$state" = expired ]]; then
    jq '{state,failure_code,failure_message,progress}' "$session" >&2
    exit 1
  fi
  if [[ "$state" = approved ]] \
    && [[ "$(jq -r '.destructive_started_at // ""' "$session")" = "" ]] \
    && ((SECONDS >= pre_destructive_deadline))
  then
    echo 'error: approved Nest candidate did not acknowledge its plan before the qualification deadline' >&2
    jq '{state,heartbeat_at,destructive_started_at,progress,failure_code,failure_message}' "$session" >&2
    if [[ -s "$work_dir/serial.log" ]]; then
      echo 'bounded qualification serial console follows:' >&2
      tail -n 500 "$work_dir/serial.log" >&2
    fi
    exit 1
  fi
  if [[ "$state" = rebooting && "$reboot_deadline" -eq 0 ]]; then
    reboot_deadline=$((SECONDS + 300))
  fi
  if ((reboot_deadline > 0 && SECONDS >= reboot_deadline))
  then
    echo 'error: Nest did not report Ready within five minutes of requesting reboot; inspect installed boot and first-boot service evidence; qualification will not force a restart or remove media' >&2
    jq '{state,heartbeat_at,progress,failure_code,failure_message}' "$session" >&2
    if [[ -s "$work_dir/serial.log" ]]; then
      echo 'bounded qualification serial console follows:' >&2
      tail -n 500 "$work_dir/serial.log" >&2
    fi
    exit 1
  fi
  kill -0 "$qemu_pid"
  sleep 5
done
test "$ready" = true

device_id="$(jq -er '.reserved_device_id' "$session")"
nodes="$work_dir/nodes.json"
node="$work_dir/node.json"
appliance_projection_ready=false
for _attempt in $(seq 1 120); do
  api GET '/v1/nest/nodes?limit=100&offset=0' > "$nodes"
  jq -e --arg device "$device_id" '.nodes[] | select(.device_id == $device)' "$nodes" > "$node" || true
  if [[ -s "$node" ]] \
    && [[ "$(jq -er '.appliance_base_os' "$node")" = nixos ]] \
    && [[ "$(jq -er '.appliance_base_os_version' "$node")" = "$(jq -er '.appliance_release_v1.base_os_version' "$manifest")" ]] \
    && [[ "$(jq -r '.appliance_secure_boot' "$node")" = false ]] \
    && [[ "$(jq -er '.appliance_boot_mode' "$node")" = uefi ]] \
    && [[ "$(jq -er '.at_rest_protection' "$node")" = none ]] \
    && [[ "$(jq -er '.appliance_local_health.status' "$node")" = healthy ]] \
    && [[ -n "$(jq -er '.kernel_version' "$node")" ]] \
    && [[ -n "$(jq -er '.system_generation' "$node")" ]] \
    && [[ "$(jq -er '.system_toplevel' "$node")" = "$(jq -er '.appliance_release_v1.system_toplevel' "$manifest")" ]] \
    && [[ "$(jq -er '.system_closure_sha256' "$node")" = "$system_closure_sha256" ]] \
    && [[ "$(jq -er '.nixpkgs_revision' "$node")" = "$(jq -er '.appliance_release_v1.nixpkgs_revision' "$manifest")" ]]
  then
    appliance_projection_ready=true
    break
  fi
  kill -0 "$qemu_pid"
  sleep 5
done
test "$appliance_projection_ready" = true

# Product-level greenfield contract: the exact candidate must converge with
# the organization's untouched built-ins. Checking node-scoped jobs prevents an
# artifact retained on another Nest from making this freshly installed disk
# appear qualified.

runtime_status="$work_dir/workstation-runtime.json"
runtime_operational=false
runtime_converged=false
runtime_prepublication_deferred=false
if [[ "$prepublication_candidate" = true ]]; then
  api GET "/v1/nest/nodes/$device_id/workstation-netboot" > "$runtime_status"
  test "$(jq -er '.state' "$runtime_status")" = absent
  test "$(jq -er '.operational' "$runtime_status")" = false
  test "$(jq -er '.converged' "$runtime_status")" = false
  test "$(jq -r '.desired // ""' "$runtime_status")" = ""
  test "$(jq -r '.active // ""' "$runtime_status")" = ""
  # Tiaris binds runtimes to the exact appliance release. Even with a published
  # predecessor, a new candidate disk cannot acquire its matching runtime until
  # immutable staging. Delivery remains mandatory in the cold phase before the
  # prerelease can become stable. No predecessor state is fabricated here.
  runtime_prepublication_deferred=true
else
  for _attempt in $(seq 1 720); do
    api GET "/v1/nest/nodes/$device_id/workstation-netboot" > "$runtime_status"
    if [[ "$(jq -er '.operational' "$runtime_status")" = true ]] \
      && [[ "$(jq -er '.converged' "$runtime_status")" = true ]]
    then
      runtime_operational=true
      runtime_converged=true
      break
    fi
    if [[ "$(jq -er '.state' "$runtime_status")" = failed ]] \
      && [[ "$(jq -er '.operational' "$runtime_status")" = false ]]
    then
      echo 'error: fresh Nest has no verified usable workstation runtime' >&2
      jq '{state,operational,converged,failure_code,failure_message}' \
        "$runtime_status" >&2
      exit 1
    fi
    kill -0 "$qemu_pid"
    sleep 5
  done
  test "$runtime_operational" = true
  test "$runtime_converged" = true
fi
if [[ "$require_candidate_runtime" = true ]]; then
  # Used after immutable publication with a cold disk. Before publication the
  # normal compatibility lifecycle truthfully exercises the selected predecessor.
  test "$runtime_operational" = true
  for projection in active desired; do
    test "$(jq -er --arg p "$projection" '.[$p].bundle_sha256' "$runtime_status")" = \
      "$(jq -er '.workstation_netboot.sha256' "$manifest")"
    test "$(jq -er --arg p "$projection" '.[$p].runtime_version' "$runtime_status")" = \
      "$(jq -er '.workstation_netboot.runtime_version' "$manifest")"
  done
fi

build_jobs="$work_dir/build-jobs.json"
builtins_deliverable=false
# The authenticated predecessor proves installation and upgrade readiness.
# Its signed cache predates the current Manage compiler and desktop modules.
# Current profiles are qualified after the actual candidate upgrade, and on
# independent fresh/cold candidate disks; never claim them on this old disk.
builtins_upgrade_deferred=false
if [[ "$qualification_kind" = predecessor ]]; then
  builtins_upgrade_deferred=true
fi
if [[ "$runtime_prepublication_deferred" = false && "$builtins_upgrade_deferred" = false ]]; then
for _attempt in $(seq 1 720); do
  api GET "/v1/nest/nodes/$device_id/build/jobs?limit=200&offset=0" > "$build_jobs"
  if jq -e --slurpfile blueprints "$blueprints" '
      ($blueprints[0].blueprints | map(.slug)) as $expected
      | ([.jobs[]
          | select(.status == "succeeded")
          | .build_spec.blueprint_revision_id as $revision
          | $blueprints[0].blueprints[]
          | select(.current_revision_id == $revision)
          | .slug] | unique | sort) == ($expected | sort)
    ' "$build_jobs" >/dev/null
  then
    all_cached=true
    while IFS=$'\t' read -r blueprint_id revision_id; do
      cache_status="$work_dir/cache-status-$blueprint_id.json"
      api GET "/v1/blueprints/$blueprint_id/nest-cache?revision_id=$revision_id" \
        > "$cache_status"
      if [[ "$(jq -er '.cached' "$cache_status")" != true ]] \
        || [[ "$(jq -er '.required_replicas > 0 and .ready_replicas == .required_replicas' "$cache_status")" != true ]]
      then
        all_cached=false
      fi
    done < <(jq -r '.blueprints[]
      | [.id,.current_revision_id] | @tsv' "$blueprints")
    if [[ "$all_cached" = true ]]; then
      builtins_deliverable=true
      break
    fi
  fi
  kill -0 "$qemu_pid"
  sleep 5
done
if [[ "$builtins_deliverable" != true ]]; then
  echo 'error: official built-in Blueprints did not converge on the new Nest' >&2
  jq --slurpfile blueprints "$blueprints" '
    [.jobs[]
      | select(.build_spec.blueprint_revision_id as $revision
          | $blueprints[0].blueprints
          | any(.current_revision_id == $revision))
      | {blueprint_id:.build_spec.blueprint_id,
         blueprint_revision_id:.build_spec.blueprint_revision_id,status,error,
         error_kind:.cache_metadata.error_kind,
         source_build_candidates:.cache_metadata.source_build_candidates}]
    | .[:20]
  ' "$build_jobs" >&2
  exit 1
fi
fi

ssh-keygen -q -t ed25519 -N '' -C qualification -f "$work_dir/operator-key"
certificate_response="$work_dir/ssh-certificate.json"
certificate_request="$(jq -cn \
  --arg public_key "$(cat "$work_dir/operator-key.pub")" \
  '{public_key:$public_key,reason:"exact candidate release qualification",validity_minutes:5,allow_forwarding:false}')"
api POST "/v1/nest/nodes/$device_id/ssh-certificates" "$certificate_request" > "$certificate_response"
test "$(jq -er '.principal' "$certificate_response")" = "$device_id"
valid_after="$(date -u -d "$(jq -er '.valid_after' "$certificate_response")" +%s)"
valid_before="$(date -u -d "$(jq -er '.valid_before' "$certificate_response")" +%s)"
test "$((valid_before - valid_after))" -le 300
jq -er '.certificate' "$certificate_response" > "$work_dir/operator-key-cert.pub"
ssh-keygen -Lf "$work_dir/operator-key-cert.pub" > "$work_dir/certificate-inspection.txt"
grep -E "^[[:space:]]+${device_id}[[:space:]]*$" "$work_dir/certificate-inspection.txt" >/dev/null
if grep -F 'permit-agent-forwarding' "$work_dir/certificate-inspection.txt" >/dev/null \
  || grep -F 'permit-port-forwarding' "$work_dir/certificate-inspection.txt" >/dev/null
then
  echo 'error: non-forwarding qualification certificate contains forwarding extensions' >&2
  exit 1
fi
# Target only the new fixture address on the owned bridge. A compromised
# report cannot redirect this authenticated test to an existing appliance.
ssh_host="$(python3 -B "$repository_root/nixos-appliance/qualification/fixture_address.py" \
  --node "$node" --scope "$TIARIS_NEST_QUALIFICATION_STATE/scope.json" --mac "$appliance_mac")"

ssh_options=(-o BatchMode=yes -o IdentitiesOnly=yes -o ConnectTimeout=10
  -o StrictHostKeyChecking=accept-new -o "UserKnownHostsFile=$work_dir/known-hosts"
  -i "$work_dir/operator-key" -o "CertificateFile=$work_dir/operator-key-cert.pub")
# The identity command is expanded by the remote shell.
# shellcheck disable=SC2016
python3 -B "$repository_root/nixos-appliance/qualification/ssh_certificate.py" \
  --valid-before "$valid_before" -- \
  ssh "${ssh_options[@]}" "tiaris-support@$ssh_host" 'test "$(id -un)" = tiaris-support'
if ssh "${ssh_options[@]}" "root@$ssh_host" true > "$work_dir/root-login.log" 2>&1; then
  echo 'error: direct root login was accepted' >&2; exit 1
fi
rg -q 'Permission denied' "$work_dir/root-login.log"
if ssh "${ssh_options[@]}" -o PubkeyAuthentication=no -o PreferredAuthentications=password,keyboard-interactive \
  "tiaris-support@$ssh_host" true > "$work_dir/password-login.log" 2>&1; then
  echo 'error: password login was accepted' >&2; exit 1
fi
rg -q 'Permission denied' "$work_dir/password-login.log"
rm -f -- "$work_dir/operator-key" "$work_dir/operator-key.pub" \
  "$work_dir/operator-key-cert.pub" "$certificate_response" "$work_dir/certificate-inspection.txt"

# Fail closed if authoring or a released revision moved during this run.
python3 -B "$repository_root/nixos-appliance/qualification/blueprint-catalog.py" \
  --manage-origin "$manage_origin" --token-file "$token_file" --state-dir "$TIARIS_NEST_QUALIFICATION_STATE" \
  --fixture-blueprint "${TIARIS_NEST_QUALIFICATION_FIXTURE_BLUEPRINT:-qualification_dock}" \
  --baseline "$blueprints" >/dev/null

# Routine fixture requests compare sealed identities; rehash every staged
# artifact byte once before this lifecycle receipt is written.
python3 -B "$repository_root/nixos-appliance/qualification/isolated_manage_rpc.py" \
  --state-dir "$TIARIS_NEST_QUALIFICATION_STATE" verify-artifacts
jq -n \
  --slurpfile qualified_blueprints "$blueprints" \
  --arg qualification_kind "$qualification_kind" \
  --arg qualified_manifest_sha256 "$manifest_sha256" \
  --arg harness_revision "$source_revision" \
  --arg schema 'tiaris.nest.nixos-appliance-qualification.v1' \
  --arg release_version "$release_version" \
  --arg system_closure_sha256 "$system_closure_sha256" \
  --arg system_toplevel "$(jq -er '.system_toplevel' "$node")" \
  --arg nixpkgs_revision "$(jq -er '.nixpkgs_revision' "$node")" \
  --arg manage_source_revision "$(jq -er '.appliance_release_v1.manage_source_revision' "$manifest")" \
  --arg system_generation "$(jq -er '.system_generation | tostring' "$node")" \
  --arg session_id "$session_id" --arg template_sha256 "$template_sha256" \
  --arg device_id "$device_id" \
  --argjson candidate_runtime_required "$require_candidate_runtime" \
  --argjson workstation_runtime_operational "$runtime_operational" \
  --argjson workstation_runtime_converged "$runtime_converged" \
  --argjson workstation_runtime_prepublication_deferred "$runtime_prepublication_deferred" \
  --argjson builtins_deliverable "$builtins_deliverable" \
  --argjson builtins_upgrade_deferred "$builtins_upgrade_deferred" \
  --arg completed_at "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
  '{schema:$schema,ok:true,release_version:$release_version,
    harness_revision:$harness_revision,qualification_kind:$qualification_kind,
    qualified_manifest_sha256:$qualified_manifest_sha256,
    qualified_blueprints:(if $builtins_upgrade_deferred then null else $qualified_blueprints[0] end),
    pending_upgrade_blueprints:(if $builtins_upgrade_deferred then $qualified_blueprints[0] else null end),
    base_os:"nixos",system_toplevel:$system_toplevel,nixpkgs_revision:$nixpkgs_revision,
    manage_source_revision:$manage_source_revision,
    system_closure_sha256:$system_closure_sha256,system_generation:$system_generation,
    session_id:$session_id,device_id:$device_id,template_sha256:$template_sha256,
    candidate_runtime_required:$candidate_runtime_required,
    installer_iso_sha256:$template_sha256,installed_from_generic_iso:true,
    setup_claimed_with_code:true,secure_boot:false,
    no_disk_write_before_approval:true,identity_rotation:true,
    installed_media_left_attached:true,appliance_projection_healthy:true,
    workstation_runtime_operational:$workstation_runtime_operational,
    workstation_runtime_converged:$workstation_runtime_converged,
    workstation_runtime_prepublication_deferred:$workstation_runtime_prepublication_deferred,
    builtin_blueprints_deferred_until_upgrade:$builtins_upgrade_deferred,
    builtin_blueprints_source_free:$builtins_deliverable,
    builtin_blueprints_deliverable:$builtins_deliverable,
    builtin_blueprints_qualified_on_new_nest:$builtins_deliverable,
    builtin_blueprints_prepublication_deferred:$workstation_runtime_prepublication_deferred,
    exact_principal_ssh_certificate:true,
    ssh_login_verified:true,ssh_root_rejected:true,ssh_password_rejected:true,
    final_state:"ready",completed_at:$completed_at}' \
  > "$output"
chmod 0600 "$output"
lifecycle_succeeded=true
