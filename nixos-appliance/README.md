# NixOS Nest appliance

This directory is the NixOS successor to the Ubuntu Nest appliance. Its initial
implementation is under development; builds and qualification must not be claimed
complete until their gates pass. Existing Ubuntu appliances require a human
reinstall from the current Nest ISO. They do not receive a NixOS in-place update.

The product journey stays **Download Nest ISO → one disk safety check → Install
Nest once → Ready**, with no local appliance input. Nest requires x86-64 UEFI
with Secure Boot turned off, at least 16 GiB RAM, the existing CPU/wired-Ethernet
requirements and an eligible fixed disk of at least 160 GiB. Firmware Secure Boot
state is reported for information and is not an admission check.

## Build inputs and output contract

Use `release/nixpkgs.nix` through `builtins.fetchTarball`; no flake or separate
appliance pin. The appliance and workstation runtime move their pin together.
The initial pin is NixOS 26.05, revision
`74cc63f702f7d60a557e152a57b40fb1fd0f72ac`. Use that release's default LTS kernel,
redistributable firmware and Intel/AMD microcode. Record actual kernel, firmware,
microcode, Nix, Nest and systemd-boot versions in the closure manifest.
Initial evaluated versions are kernel `6.18.38`, Nix `2.34.7` and systemd-boot
`260.2`; stable OS release is `26.05` despite `lib.version=26.05pre-git`.

The non-flake entrypoint `default.nix` exposes the installed system
toplevel, local closure cache/manifest, installer ISO and NixOS VM tests. Build
scripts accept an exact clean Nest revision, exact Tiaris source checkout and
revision, explicit expected canonical HTTPS Tiaris origin, offline release public
key and sorted unique provisioning public keys. The named appliance Nix key is
derived from the same release public authority.
Private signing keys must never be a Nix derivation input or enter the store.

Outputs are build-once immutable candidates:

* `tiaris-nest-appliance-template-<version>-x86_64-linux.iso`;
* unsigned template metadata with exact digest, length and personalization extent;
* `tiaris-nest-appliance-closure-<version>-x86_64-linux.tar.zst`;
* bounded closure metadata, signed descriptors and the existing release and
  compatibility assets.

The same signed closure serves fresh installation and updates. Qualification and
publication consume the same bytes; rebuilding invalidates qualification. Only
public keys and organization-neutral assets are embedded. Node identities,
customer configuration and private workstation cache keys are created at runtime.

Activation installs `/usr/share/tiaris-nest/workstation-cache-seeds.json`, the
sorted store paths of `services.tiaris-nest.workstationCacheSeeds`. The same list
is the system's `extraDependencies`, so the closure carries every seed the daemon
publishes into the Nest cache.

The exact Tiaris source archive and digest metadata are embedded as immutable
store paths and exposed at `/usr/share/tiaris-nest/manage-source/<revision>.tar`
and `.json`. Activation verifies signed identity and makes atomic fsynced
root-owned 0444 single-link copies in an ordinary root-owned 0755 directory.
Store directories are 0555 and optimized files may be hardlinked, so a directory
symlink or direct bind fails existing verification. Retain bounded secure reopening;
do not weaken it to follow untrusted symlinks. The signed
workstation descriptor, embedded archive and release Tiaris revision must agree.

### Local build commands

From a clean committed checkout, use the wrappers for their source/origin and ISO
content checks. Public inputs may be command arguments; private keys must stay in
protected files outside the Nix store and unsigned builder.

```sh
bash nixos-appliance/build-template.sh \
  --manage-source-dir "$MANAGE_SOURCE" --manage-source-revision "$MANAGE_REVISION" \
  --source-revision "$NEST_REVISION" --expected-manage-origin "$MANAGE_ORIGIN" \
  --release-public-key "$RELEASE_PUBLIC_KEY" \
  --provisioning-public-key "$PROVISIONING_PUBLIC_KEY" --output-dir "$ISO_OUTPUT"
bash nixos-appliance/build-closure.sh \
  --manage-source-dir "$MANAGE_SOURCE" --manage-source-revision "$MANAGE_REVISION" \
  --source-revision "$NEST_REVISION" --expected-manage-origin "$MANAGE_ORIGIN" \
  --release-public-key "$RELEASE_PUBLIC_KEY" \
  --provisioning-public-key "$PROVISIONING_PUBLIC_KEY" --unsigned-output-dir "$CACHE_OUTPUT"
python3 tools/pack-system-closure.py \
  --cache "$CACHE_OUTPUT/cache" --build-metadata "$CACHE_OUTPUT/build-metadata.json" \
  --private-key "$SIGNING_KEY_FILE" --output "$SIGNED_CLOSURE" \
  --metadata-output "$SIGNED_CLOSURE_METADATA"
```

`$ISO_OUTPUT` receives the template ISO and its JSON record, and the USB installer
stick: `tiaris-usb-installer.img` and its build record `tiaris-usb-installer.json`,
copied from the `usbInstaller` store path. Release signing publishes the image as
`tiaris-usb-installer-VERSION.img` and names it in the manifest
(`nest-release.py manifest --usb-installer-image ... --usb-installer-image-record ...`).
It is not in the installed system and the Nest does not serve it. A pinned Tiaris
revision without a stick does not build.

## Disk and state contract

All sizes use GiB (1024³ bytes), checked arithmetic and 1 MiB alignment. Read disk
bytes independently of logical sector size; `blockdev --getsz` reports 512-byte
sectors even on 4 KiB-sector hardware.

| Partition | Label | Size / filesystem | Purpose |
| --- | --- | --- | --- |
| 1 | `TIARIS_STATE` | 16 GiB ext4 | created first; identity, SQLite, config and receipts |
| 2 | `TIARIS_EFI` | 1 GiB FAT32 | `/boot`, UEFI systemd-boot |
| 3 | `TIARIS_SWAP` | 8 GiB swap | no hibernation contract |
| 4 | `TIARIS_ROOT` | remainder, ext4 | root, writable store, caches and build output |

A 160 GiB disk leaves approximately 135 GiB minus GPT/alignment slack for root;
require at least 134 GiB computed root capacity. Root ext4 reserves 1% for root.
The final admission uses actual available bytes including filesystem overhead,
not the nominal partition size. `/nix` is an executable `nodev,nosuid` bind of
`/var/cache/tiaris-nest/nix`; root owns the store and its parents. Nest is an
allowed Nix daemon user, never a trusted Nix user.

STATE mounts at `/var/lib/tiaris-nest/state` with `nodev,nosuid`. Its `agent/` and
`inbox/` are Nest-owned 0700; its `control/` and `status/` are root:Nest 0750,
bind-mounted at the historical control/status paths. Protected files are bounded,
single-link regular files, 0640 root:Nest or 0600 root for secrets. Signed plan,
identity transition, config, CA/principal, CIDRs, network decisions and update
receipts persist across every generation. Do not place secrets in store paths.

ROOT has one free-space floor: room for one largest build
(`build.max_artifact_size_bytes`, 20 GiB) plus 1 GiB headroom, **21 GiB**
(`free_space_floor` in `src/disk.rs`; there is no other reserve). Cache
retention keeps it free, a build needs it to start, and an installation or
update must leave it after its missing store paths and simultaneous staging
files. An update that does not fit makes room before it is refused: the root
updater asks cache retention for the bytes the verifier names
(`tiaris-nest free-cache-space`, run as the service user), then collects
garbage as the daily GC does (`generation_update.make_room`). Only then the
root verifier ends the attempt, with the reason `insufficient_store_space`.
Current, pending and two preceding good generations, active job roots and
protected artifacts cannot be reclaimed to make an update fit. Daily GC uses
the job/update exclusion barrier.

The EFI partition needs no such cleanup: at every switch NixOS's boot loader
installer first removes the kernels and initrds that none of the four kept
generations names (`configurationLimit = 4`), so it holds at most four pairs
of about 54 MiB. An update that still finds less than 256 MiB free there ends
with the reason `insufficient_esp_space`.

Bulk downloaded/private update staging and database rollback copies live under
`/var/cache/tiaris-nest/appliance-updates/` on ROOT. Only protected verified and
transaction receipts live on STATE. The download only has to fit (its size plus
1 GiB); root admits the update. When staging/store share a filesystem,
admission charges new staging + missing NAR bytes + the floor once. A distinct
staging filesystem reserves 2 GiB; the store still preserves the floor. Pending
and preparation/commit/rollback receipts fence queued builds after reboot until
root recovery finishes.

## Closure archive and safety limits

Export the complete toplevel reference graph to a local binary cache with `nix
copy --to file://...`, sign every NARInfo with the offline appliance Nix key, and
pack canonical USTAR through zstd. The archive contains only `manifest.json`,
`nix-cache-info`, `<hash>.narinfo`, `nar/` and `nar/<safe filename>.nar.zst`.
Directory/file ownership is numeric root, mtime zero, directory mode 0755 and
regular-file mode 0644. The explicit `nar/` header precedes all NAR payloads. Reject
duplicates, absolute/traversal paths, links, devices, sparse/extended headers,
unexpected files, trailing data and incomplete streams.

The public Nix key is `tiaris-nest-appliance-1:<canonical standard Base64 raw
release Ed25519 public key>`, reusing the offline release authority with Nix's NAR
signature format, distinct from node-generated workstation cache keys. Build the
cache unsigned; external private signing staging adds signatures before packing.
No private signing key enters a derivation, store path or log. Keep historical
`--appliance-package-snapshot` options as aliases; derive the closure filename
from its signed URL instead of constructing an Ubuntu filename.

Maximum sizes: **4 GiB compressed archive**, **8 GiB expanded tar**, **32 GiB
summed NAR payload**, **65536 archive members**, **16 MiB manifest**, **1 MiB per
NARInfo**, **128 MiB zstd window** for archive and NARs. GitHub publication also
requires **less than 2 GiB per asset**, including ISO and closure. The installer
holds at most the 4 GiB archive plus bounded decoder and runtime buffers in RAM.
It verifies the whole signature/size/hash/archive and every inner NAR's compressed
and uncompressed hashes/sizes, trusted NARInfo signature and exact reference graph before
destructive work, streams validation without unpacking a second RAM copy, and
extracts/imports onto the target only after authorized partitioning. Installation
requires sufficient measured available RAM for this budget.

`manifest.json` is canonical recursively key-sorted compact UTF-8 JSON plus LF,
schema `tiaris.nest.system-closure.v1`. It contains descriptor identity fields,
the pinned public Nix signing key, exact Tiaris source identity, Intel/AMD
microcode versions, sorted `store_paths` with NAR hashes/sizes/references and
`total_nar_bytes`. The signed archive hash authenticates it; the manifest does
not contain its own archive digest or final descriptor. The immutable system
metadata also omits its own toplevel; derive actual boot identity from
`/run/current-system` and the external signed STATE receipt. Import trusts the key
already installed in the ISO/system policy, not a key supplied only by the archive.

Manifest `nar_hash` is `sha256:<52-character canonical Nix-base32>`, references
are sorted full store paths, and NARInfo references are their sorted basenames.
NARInfo filename is the store path hash plus `.narinfo`; its URL is one exact
`nar/...` archive member, never remote/absolute. Reject duplicate fields and
require `Compression: zstd`, hashes, sizes, store path, references and trusted
signature to agree. Order manifest and NARInfos before NAR payloads, allowing
bounded pre-destructive nested verification without retaining whole NAR buffers.

Every NAR signature, compressed hash, NAR size/hash and reference graph must
validate. No public substituter or build fallback is allowed during installation
or update import. Root reopens and privately pins a daemon-downloaded archive
before verifying/importing it; an untrusted inbox path is never a trust receipt.

The installed Blueprint builder uses `https://cache.nixos.org` with its pinned
public signing key and mandatory signatures for workstation dependencies. This
is separate from appliance import: the ISO has release-only trust, and the
installer/updater verify the release archive and disable remote substitution.
The Nest service remains an untrusted Nix daemon user.

## V3 release and media contract

Nest protocol remains **4**; workstation epoch **1** and `split-squashfs-v1`
remain unchanged. The outer release manifest remains `tiaris.nest.release.v1`.
It contains `installer_iso_template_v3`; its historically named
`appliance_release_v1` contains the inner V3 descriptor. Compatibility keeps
`artifacts.appliance_package_snapshot` as the historical envelope name for the
closure identity. Never publish both V2 and V3 template descriptors in one current
manifest or fall back to V2 after a V3 validation failure.

The appliance descriptor has exactly:

```text
schema = tiaris.nest.appliance-release.v3
release_id, source_revision, base_os = nixos, base_os_version
nixpkgs_revision, manage_source_revision, system_toplevel
system_closure = {url, sha256, size_bytes}
required_system_versions = {kernel, linux-firmware, nix, tiaris-nest, systemd-boot}
sqlite_migrations_sha256
minimum_protocol = 4, minimum_state_schema = 3, rollback_compatible = true
release_notes, signature
```

All fields are mandatory. The five anchors are exact; `tiaris-nest` equals
`release_id`. No Ubuntu snapshot/package/expected-kernel fields appear in V3.
The signature is standard Base64 Ed25519 over
`TIARIS-NEST-APPLIANCE-RELEASE-V3\n` plus recursively sorted compact JSON without
`signature`, with no final LF. Digests/revisions are lowercase hex, URLs canonical
immutable HTTPS, toplevel one validated store path. Historical V1/V2 objects retain
their original encoding and signature domain for audit but are not update targets.

The ISO descriptor has required `version`, `architecture=x86_64-linux`,
`base_os=nixos`, `base_os_version`, `url`, `size_bytes`, `template_sha256`,
`personalization_offset`, `personalization_size=8192`, `placeholder_sha256`,
sorted unique `provisioning_public_keys`, `package_delivery=system-closure-v1`,
`manage_origin`, `signature`. Sign domain
`TIARIS-NEST-INSTALLER-ISO-TEMPLATE-V3`, then each preceding field except
signature in that exact order, one field per line, with a final LF; join key array
with commas. Two optional integers follow `manage_origin` as further signed lines:
`envelope_max_validity_hours` (24-744, from `tiaris-nest-bootstrap
envelope-max-validity-hours`) and then, only together with it,
`setup_claim_protocol` (>= 1, from `tiaris-nest-bootstrap setup-claim-protocol`:
the ISO may stay generic and be claimed). `build.py` copies both from the
compiled bootstrap; a template without them verifies as before. Origin is independently supplied and checked against compiled
bootstrap bytes. Release/ISO use standard Base64 signatures; install/network
plans retain URL-safe unpadded signatures.

The ISO uses installation-cd hardware support, UEFI USB-hybrid boot and the single
branded **Install Tiaris Nest** entry, drawn with Manage's presentation-only
`deploy/nixos/tiaris-grub-theme.nix` (`variant = "nest-installer"`). The pinned
module's options submenu (copy-to-RAM, nomodeset, debug), firmware-setup and
shutdown entries are removed; the tty1 screen needs no basic-graphics entry
because it falls back to text without DRM. `/TIARIS_PROVISIONING.BIN` is an ordinary
uncompressed ISO9660 file consisting of exactly 8192 zero bytes in one extent.
Derive its offset from final xorriso LBA metadata, reopen its exact bytes, and
export slot identity. The slot stays all zeros and every server is claimed,
release qualification's too. Test HTTP ranges at both edges and compare the rest of the image. Keep an arping-capable binary
in the live image for static-address safety checks.

New `tiaris.nest.install-plan.v3` preserves every V2 field name, including
`package_transport_url`, but binds NixOS, `system-closure-v1` and the V3
descriptor. Its signature domain is `TIARIS-NEST-INSTALL-PLAN-V3\n`; unsigned
canonical JSON excludes `signature` and `plan_sha256`, and that JSON's SHA-256
is `plan_sha256`. Provisioning-envelope V1 and identity cross-signatures remain
unchanged. Decode historical plans for audit, but never execute an Ubuntu plan.

## Provisioning and first boot

The bootstrap service verifies media, claims a session and reports bounded
inventory while waiting for the administrator's exact-disk approval. Before
partitioning it verifies and stages the closure, recollects disk/UEFI/wired-link
identity, and repeats static ARP/gateway/DNS/TLS safety checks. Preflight failure
reports a safe code, leaves the disk untouched and supports Review and try again
with the same ISO. `plan_acknowledged` and `partitioning` events must be accepted
before the first disk write.

Create and fsync STATE first, generate the permanent key there, persist UUID and
slug, signed plan/digest and event sequence, and complete the existing cross-signed
temporary-to-permanent transition. Remaining GPT creation is idempotent. Import
the verified closure offline into the target store and use `nixos-install --system
<toplevel> --no-root-passwd` with the explicit target root. Installed systemd-boot
can touch EFI variables. Materialize STATE config/network/CA/principal/CIDRs,
record completion durably and reboot without prompting.

A generic ISO (all-zero slot) gets its envelope by being claimed (top-level
README) and then runs this same flow. Its order on every start: STATE holding a
retained envelope (`.setup-claim-envelope.bin`, written right after STATE is
created and before the durable state) of an interrupted installation resumes
while its setup window is open, after asking Management without changing
anything whether the setup is still open (the media-key plan poll, or once the
device identity is active an unchanged replay of event 3). A server that
already holds an installed Nest (a completed installation with its retained
envelope, or, with no usable envelope, STATE in partition 1 and the
`TIARIS_EFI` ESP in partition 2 of the same disk with exactly one UEFI entry
loading `\EFI\systemd\systemd-bootx64.efi` from that ESP's partition GUID)
registers and shows the claim screen first: claimed, the new session runs the
existing flow and the old STATE is a different session's; not claimed within
3 minutes (from this boot's first claim screen, kept in
`/run/tiaris-nest-claim/starts-installed-at` across service restarts, network
or not, and started again when a claimed setup ends), it starts the installed
Nest, with the envelope as the completed-install path does, without one by
setting that entry as BootNext and restarting (nothing mounted read-write,
nothing written on disk). When that fails, the claim screen stays without
`starts_installed_at`. Otherwise this boot's `/run/tiaris-nest-claim`
registration continues (a claimed envelope kept there is reused); otherwise it
registers. An expired, unverifiable or orphaned retained copy is a setup that
ended: STATE is released and the server is claimed again, after which that STATE
is a different session's and needs a new exact-disk approval. A retained copy
that is valid except that it looks issued more than 5 minutes in the future
(this server's clock is behind, for example before NTP answered) is not one:
the run fails as the slot path does and the service retries every 15 seconds
until the clock is right, unless its installation completed: then the server
counts as an installed Nest with no usable envelope (claim screen, then its
UEFI entry), so a Nest with a wrong clock and no internet still starts. If power fails
between GPT erasure and the STATE copy, the generic ISO is claimed again too.

A setup Management closed before this run changed the disk leads back to the
claim screen with a new code: a plan poll refused with `409` and no
`diagnostic_code` (revoked, superseded or expired, or the media identity
retired), a session claim refused with `409 provisioning_session_expired`, or
a vanished claimed registration (`404`: also failed, ready or past its review
window). This holds while waiting for approval, while waiting for a retry
after a safe failure, and before resuming from a retained envelope ("Start
over"). `provisioning_recovery_required`, `media_already_claimed`, `401`,
`403`, `404` of the session and network failures keep the existing behaviour.

Recovery probes existing STATE `ro,noload,nodev,nosuid`. Same-session resume
requires exact media/session/plan/geometry and freshly verified closure while
installation is incomplete. Before permanent activation, media-key polling may
recover the exact active signed plan even if power failed before STATE was
formatted or persisted. Replaying the exact plan-acknowledged and partitioning
events must succeed before recreating that exact disk's STATE. Empty/unmountable
STATE alone grants no authority. Once installation is complete, the attached ISO
performs a signed-plan/hardware/permanent-identity/disk-bound boot-only handoff;
expired media or unavailable original closure transport cannot block that handoff.
Expired incomplete media never grants new destructive authority. A
different session's old STATE is discovery only, never a source of identity,
tenant, keys or config: unmount it for fresh inventory and wait for a new signed
exact-disk Console approval with accepted acknowledgement/destructive events
before replacing it. Existing-device recovery retains server-side settings/history
under same-org/hardware/offline/competing-install fences and creates a new key and
incarnation. No manual disk wipe or automatic foreign-state resume is permitted.
A completed same-media boot selects the exact installed EFI
entry and reboots automatically, including when ISO remains attached.

Every start runs the start-up checks (`tiaris-nest-first-boot.service`; the name
is historical): protected ownership, mounted store/state, actual booted closure
and identity, and staging the credential-free immutable iPXE/TFTP files. They read
only the Nest's own disk. nginx, the boot file server, SSH and the Nest service
require them, so a Nest restarted while the internet or Tiaris is unreachable (a
power cut: the internet comes back last) still starts all of them. Reaching Tiaris
is a fact the Nest reports, not a condition to start: `tiaris-nest-network-guard`
(required by nothing) keeps the approved network when Tiaris answers on it, keeps
the DHCP fallback when a fixed address does not reach Tiaris and DHCP does, and,
when Tiaris answers on neither, starts on the one that reached Tiaris last (the
DHCP fallback while its marker is there, else the approved network). The Nest service
then needs only an address on its interface (`tiaris-nest-network-runtime`, retried
each minute). What needs Tiaris waits: network start is answered only with an
inventory from Tiaris of the last five minutes, and installs, updates and builds
need Tiaris. The screen says "can't reach Tiaris" two minutes after such a start.
The running Nest also names its own UEFI entry as BootNext (`runtime/boot_next.py`),
so a virtual machine that still has the Nest ISO attached starts the Nest, not
the installer, at the next start. TFTP readiness verifies exact complete transfers; HTTP boot
readiness uses the current local IPv4 origin. Administration stays in Tiaris.

## tty1 screens

Both tty1 screens run Manage's native `tiaris-installer-kiosk`
(`deploy/nixos/tiaris-installer-kiosk-package.nix`): `--nest-setup` on the setup
ISO (`tiaris-nest-setup-console.service`) and `--appliance` on the installed Nest
(`tiaris-nest-console.service`). Each owns tty1 with getty/autovt masked, restarts
always, and prints its own line-oriented text feed on tty1 when no DRM output is
usable (nomodeset, serial). The kiosk reads at most 64 KiB, ignores unknown fields,
treats a wrong `schema` as unavailable and a missing file as no status yet.
Both projections are presentation only, written atomically (same-directory
temporary, fsync, rename) as 0644 JSON of at most 16 KiB, and never contain
secrets, keys, tokens, serials, raw errors or URLs with paths.

`tiaris-nest-bootstrap prepare` writes `/run/tiaris-nest-setup/status.json`
(`--setup-status`; `RuntimeDirectory` 0755, preserved across restarts), schema
`tiaris.nest-setup-status.v1`. A write failure is logged and never changes
provisioning. `state` is `claim` on a generic ISO before its envelope is
verified: only `schema`, `state`, `updated_at`, `tiaris_host` and `claim`, whose
`state` is `connecting`, `claimable` (`letters`, `code`), `backoff`
(`retry_at`), `claimed` (`organization`, cleaned and cut to 80; written only
after the handed-over envelope verified, and skipped when Tiaris sent no
name) or `outdated`, plus `url` once Tiaris
answered (left out, never cut, when longer than 80 characters), and `starts_installed_at` (RFC 3339, only in `connecting`, `claimable`
and `backoff`) when this server already runs a Nest that the ISO starts at that
time unless it is claimed; letters and code appear in no other state and never in a log. A claim
screen replaces a preserved `stopped` screen. Then `checking` (rows `firmware`, `processor`, `memory`,
`ethernet`, `disk`, `tiaris` with `done|active|queued|error`; a row below the
Tiaris admission minimum of UEFI, 4 cores, 16 GiB, a linked wired interface and
an eligible 160 GiB disk is `error`), `awaiting_approval` (`tiaris_host`,
`network`, `boot_mode`, and `disk` only when exactly one disk is eligible),
`installing` (`approved_at`, `organization`, `name`, plan `disk`/`network`,
`system`, `encrypted` and `step` 1-5 of: stage the signed release, verify
signatures and system, recheck disk/memory/link, partition and format, install
the system; `progress_percent` only for the measured closure download),
`stopped` (`stop.disk_untouched: true`: a hardware minimum or a pre-destructive
failure code, with public `reason`, up to three `steps` and the failing `check`),
`failed` (`disk_untouched: false` after any disk write or during resume) or
`rebooting` (step 6). A restarted bootstrap keeps showing a preserved `stopped`
screen until it passes the point where the earlier run stopped (media
verification, inventory, session claim or a new approved plan), and a preserved
`failed` screen until resumed installation progress replaces it.

The `tiaris-nest` daemon rewrites `/run/tiaris-nest/console-status.json`
(`RuntimeDirectory` 0755, preserved so a stopped daemon leaves a visibly stale
file) every 15 seconds and after each accepted Tiaris report, schema
`tiaris.nest-console-status.v1`. `state` is `attention` > `starting` >
`healthy`: a failed watched unit is `service_failed` with its friendly name;
Tiaris silence for more than ten minutes (measured from the later of the last
contact and daemon start; two minutes while this boot has not reached Tiaris
at all) is `tiaris_unreachable` with `since` the last contact;
six consecutive not-ready checks spanning 75 seconds is `not_ready`. Otherwise
`starting` has `stage` `first_boot`, `enrolling` (no accepted Tiaris report this
boot) or `services` (units, local PXE readiness and discovery not yet ready).
Identity fields come from the sealed root:tiaris-nest 0640 install plan (`name`,
`organization`, `interface`), the live boot URL (`address`), the Manage origin
(`tiaris_host`), the PXE supervisor (`pxe`), `/proc/stat` (`booted_at`) and the
immutable system identity (`system`). `active_installs` counts distinct
workstations that started the installer in the last ten minutes. The kiosk treats
a status older than 90 seconds as stale attention.

## Services and network

The NixOS module provides unprivileged Nest, sandboxed Nix daemon, nginx IPv4
listener, immutable TFTP root, dnsmasq ProxyDHCP supervisor,
certificate-only OpenSSH, atomic management-CIDR SSH nftables policy, watchdog,
time synchronization, bounded journald and coordinated daily GC. Nest has private
HOME/XDG/TMP leaves and no Linux capabilities or Nix trusted-user status.

PXE keeps authenticated complete/fresh inventory and per-device placement: the
site's one Nest answers new computers and the computers assigned to it. It never
assigns DHCP addresses. Workstation netboot/runtime import, signed binary cache and
Blueprint builds are the existing product paths.

Networkd renders STATE's approved deterministic network JSON before startup.
The network is the one the install plan approved; recurring boot validation
rechecks it against that immutable plan. Changing it after install is not
offered. Historical `netplan-*.json` filenames and candidate hashing are preserved, while
Netplan itself is absent. Render `/run/systemd/network/10-tiaris-nest.network`
0640 root:systemd-network, match the approved MAC/name, reload/reconfigure, then
verify networkd selected that exact file and obtained the intended address.

Preserve approved-static DHCP recovery tied to the exact approved digest and
runtime advertised-origin reconciliation.

CA keys, exact device principal and CIDRs live in STATE and rematerialize on every
generation. SSH permits only locked `tiaris-support`, disables root/password/
keyboard-interactive login and delegates forwarding permission to the short-lived
certificate extensions. Private key material never appears in evidence or logs.

## Generation update, commit and rollback

NixOS advertises `appliance_update_v3`, retains `appliance_update_v1` for network
and recovery SSH, and keeps the qualification transport capability. A V2-only
Ubuntu node requires reinstall; do not send it a V3 update payload.

The updater/root verifier use a local build/GC/update/network lock and preserve
the server-owned nonexpiring, non-stealable maintenance lease and device→settings
admission locks. Lease and hold remain distinct. No new inbox field grants
Update now or lease authority. Admit only within the approved maintenance
window or authorized Update now, without holds/active work. Verify the descriptor,
private pinned archive, space, closure and SQLite rollback compatibility before
activating anything. Root scheduling authorization must not come from the writable
inbox.

Initial SQLite admission requires equal source/candidate migration inventory
digests and exact successful live SQLx version/checksum rows. The canonical
`sqlite-migrations.json` is recursively sorted compact JSON plus LF with schema
`tiaris.nest.sqlite-migrations.v1`, sorted `migrations` entries containing
`filename`, SHA-256 `sha256`, SHA-384 `sqlx_checksum`, and integer `version`.
Hash the entire file including LF. Do not rewrite SQLx history or restore an
old database on rollback. Another inventory is admitted only as declared
expand/contract migrations: the candidate migrates a private copy of the root
snapshot and the running release must still start, read and write on it as
its rollback target; retained generations that cannot leave the boot menu
first (`docs/sqlite-schema-evolution.md`). Releases before schema evolution
keep requiring equal inventories.

Fsync preparation intent before any profile/ESP mutation and set/verify persistent
EFI `LoaderEntryDefault` to the exact source entry **before** the boot action.
Create a normal next system profile generation and run its
`switch-to-configuration boot`; verify the source EFI override remains authoritative
despite the candidate default written to loader.conf. Preparation-only power-loss
recovery restores source profile/default and cleans only the owned candidate.
Write the pending seal durably before `bootctl set-oneshot <candidate>`, verify
both boot selections and reboot. Seal binds attempt/request/archive/source/
release/toplevel and both exact profile and loader generation identities.

Candidate commit requires `/run/current-system` equal to the sealed toplevel,
correct release/store/state, required units, three fresh successful health probes
at least five seconds apart and a fresh authenticated Tiaris heartbeat/report.
Use a 210-second deadline and 5-minute service cap. The supervisor starts even if
Nest/first-boot fails (Wants/After, not Requires on checked services); dependency
waits are included in a bounded boot deadline. A bare public health endpoint
is not identity/reachability proof. After success, fsync commit intent, set/verify
candidate default, update known-good/installed receipt, fsync succeeded/committed
status, then clear pending/inbox/archive. Resume interrupted steps idempotently
only against the exact protected transaction.

Failure restores source default/profile, records rollback intent and reboots.
Booting source with an unresolved pending seal terminalizes rolled_back, including
candidate failure before reporting. Preserve identity/database; remove only the
failed candidate generation/boot entry/owned GC root after verifying source boot.
Never report completed rollback while candidate still runs, and never reinterpret
an already committed receipt as failure after a manual retained-generation boot.
Retain current plus two preceding known-good generations; failed candidates are
not known-good retention. Garbage collection honors all active job roots.

Receipts live on shared STATE, not inside root generations:
`verified-update.json`, `known-good-system.json`, `system-prepare-intent.json`, `pending-system-generation.json`,
`system-commit-intent.json`, `system-rollback-intent.json`,
`appliance-update-status.json`, and `appliance-release.json`. Root writes them
atomically with file and parent-directory fsync and exact transaction identity.
Reports include NixOS release/pin/toplevel/closure digest/system generation,
actual kernel/firmware/microcode, boot/Secure Boot evidence and truthful update
status. Unobservable `secure_boot`, firmware or microcode are omitted in V3,
never synthesized as false or a fabricated version. The retained report object
`package_update` carries closure fields for V3.

Runtime watchdog alone does not cover failure before systemd starts. Include
`panic=30`, bounded initrd boot/failure reboot, early watchdog drivers, runtime
handoff and commit timeout reboot. QEMU i6300esb resets its timer on machine reset;
arming it in the predecessor does not prove early candidate coverage. Qualification
must prove a failing pre-switch-root
candidate resets and reaches source without host assistance. Arbitrary firmware
or very-early kernel hangs need a hardware/BMC watchdog surviving reboot and are
not universally guaranteed. Native systemd-boot counting can be considered when
the shared pin moves to 26.11; this port does not depend on it.

## Qualification and release policy

Use disposable, explicitly owned UEFI VMs with Secure Boot off, isolated networking,
an explicit development Tiaris origin and private untracked evidence. Reject a
production origin before any VM/API mutation. Existing lab appliances are not
qualification fixtures. Never use a host reset as evidence of automatic rollback.

Required real scenarios: generic-ISO claim, install/identity/Ready; untouched disk
on preflight failure and same-media retry; interrupted install resume; workstation
PXE/runtime/install/adoption/Blueprint; window and Update now updates,
holds/schedules and retention; failing-service, failed-health and nonbooting
candidate rollback; power-cut receipt recovery; certificate-only SSH/CIDR isolation; existing-device recovery/decommission;
recorded V2 reinstall-required/cancelled-update fixture. Test archive and signature
corruption, traversal/duplicates/links/size bounds, inode replacement, migration
mismatch and Nix untrusted-user/store policy.

Run format, locked Rust tests and release build, tools unit tests, every Nix output
and NixOS service/store/firewall/SSH/watchdog/console VM test, plus branch CI. A
release candidate records exact input/output identities and bounded redacted
results. VM success does not assert physical hardware/controller qualification.
Remove temporary build output, `result*`, closure caches and owned VM disks after
successful use; keep only necessary evidence. Never commit raw evidence, secrets,
generated archives or customer configuration.

Failed isolated qualification keeps bounded listener diagnostics after fixture
cleanup. Each record identifies the listener endpoint, exit code and elapsed
time, with at most 8 KiB of redacted stdout/stderr per listener. Credentials,
PEM material and oversized lines are omitted. A private, run-specific
`tiaris-nest-<phase>-diagnostics.json` survives both startup failures and later
qualification errors. Warm and published-cold workflows upload these records
on failure for 30 days; successful release evidence remains a separate gate.

Retain the Ubuntu implementation until the complete NixOS qualification matrix
passes. Only then remove Ubuntu-only code and update the security/support policy.
Human release operators publish the qualified release and later reinstall existing
Ubuntu appliances after backups and service continuity review. A feature branch,
development deployment or local candidate is not a production release.
