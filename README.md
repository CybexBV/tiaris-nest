> CI and release compute run on The Beast. See [local CI](docs/local-ci.md).

# Tiaris Nest

Tiaris Nest is a managed NixOS appliance that builds and serves Tiaris
workstation netboot releases. The only supported installation route is the
generic Nest ISO, claimed in Tiaris with the code it shows on its screen.

## Naming transition

This source uses Tiaris and Tiaris Nest throughout the appliance and management
protocol. Existing domains and the Git repository address are unchanged. The
namespace change requires newly built, signed and qualified appliance and
workstation releases together with the renamed management API. Existing signed
artifacts cannot be relabelled; use the signed recovery/install flow when
replacing an existing appliance. Applied SQLite migrations remain immutable;
the new rename migration preserves device identities and boot assignments.
The GitHub repository, sealed `CYBEX_*` secrets/variables, and `cybex-james-lab`
runner label retain their existing infrastructure identities. Workflows map these
to the new `TIARIS_*` process inputs without rotating signing authorities. The original signed
recovery authorization remains historical evidence and cannot authorize a
renamed release.

## Installation

Download the Nest ISO from Tiaris (Settings → Downloads or
downloads.tiaris.com) and boot the target appliance from it. In Tiaris, open
Nests and claim it with the code on its screen. When the appliance appears,
select its target disk and network configuration, review the destructive
installation warning, and approve the installation there.

The claim hands the server a signed, single-use provisioning envelope. The bootstrap
verifies the envelope before installation, activates the reserved device
identity, imports the independently verified signed NixOS closure, and writes the
activated device key and ID into the installed state partition. The signed
install plan also binds the canonical organization UUID and slug; both are
validated and written to the installed managed configuration so Nest can
issue organization-scoped workstation boot grants immediately. There is no
Proxmox/LXC path. Use x86-64 UEFI with Secure Boot turned off, four cores, at
least 16 GiB RAM and a 160 GiB fixed disk.

**Generic ISO with a claim code.** The release's ISO template as built (its
8192-byte slot `/TIARIS_PROVISIONING.BIN` all zeros) is a generic Nest ISO
that never expires. Booted, it registers with Tiaris
(`POST /v1/agent/nest/setup-registrations`, signed by a registration key kept
only in memory and in `/run/tiaris-nest-claim`, mode 0700/0600), polls over
IPv4 and, with a global IPv6 route, also IPv6, and shows four letters and a
full code (`KX-4821-QM`) on its screen. An administrator claims it in the
Console; Tiaris then hands over the session's signed envelope. The bootstrap
verifies those bytes exactly as it verifies a filled slot and runs the existing flow: session claim, disk approval,
installation. The envelope is kept in `/run` until STATE exists and on STATE
(`.setup-claim-envelope.bin`, root 0600, left out of state backups) from then
on, so resuming after a power cut never needs the ISO. Booted on a server
that already holds an installed Nest (a completed installation with that
envelope, or a STATE partition whose NixOS Nest has its systemd-boot UEFI
entry, as every Nest a personalized ISO installed), the ISO shows the claim
screen with `starts_installed_at` and starts the installed Nest after 10
minutes unless it is claimed (it polls once more at the deadline, so a claim
that landed since the last poll wins; a `429` or no answer at all is asked again,
as `Retry-After` says, up to three polls in all; with the envelope as the completed-install path
does, without one by selecting that UEFI entry and restarting, changing
nothing on disk), so the generic ISO can always reinstall or recover it (a new
claim treats the old STATE as another session's). A Nest that cannot be
started that way leaves the claim screen up without a deadline. A vanished
registration (`404`), or a setup Management closed (revoked, superseded,
expired or failed) before this run changed the disk, also while waiting for
approval or for a retry, or when resuming from STATE after "Start over",
registers again with a new code, also without a reboot (this boot's claim of
that setup in `/run` is forgotten too). Whether the setup STATE would resume
is still open is decided from Tiaris's answers, not from the saved
`identity_active` flag alone: the media key's plan poll and, when Tiaris
answers it `403` (identity already activated), a replay of event 3 with the
device key; only a `409` refusal counts as closed. When IPv4 and IPv6 disagree in one poll, `claimed`
wins. The organization name is display text only (control characters
removed, cut to 80) and never refuses a claim; "Claimed by" shows only after
the envelope verified, and without a name the setup goes straight on; `410 nest_installer_outdated` shows "too old"
and retries hourly; network failures retry quietly. Any other slot content
takes the personalized path unchanged. Tiaris stopped making personalized ISOs
in November 2026, and release qualification installs the generic ISO and
claims it too (`nixos-appliance/qualification/run-lifecycle.sh`). `tiaris-nest-bootstrap
setup-claim-protocol` prints the protocol (`1`), signed into the ISO template
as `setup_claim_protocol`.

The bootstrap accepts an envelope signed for up to 31 days
(`tiaris-nest-bootstrap envelope-max-validity-hours`). The signed ISO template
declares that limit as `envelope_max_validity_hours`, so Tiaris signs one ISO
for the whole 30-day setup. Bootstraps from earlier releases accept 24 hours.

If provisioning is unavailable in Tiaris, installation is unavailable. No
fallback installer is supported.

## Workstation software bases

Each report lists `workstation_nixpkgs_commits`, the workstation nixpkgs
commits this Nest can build. `tools/software-base.py` drafts, signs and
publishes the Cybex-signed software bases Tiaris offers as kernel and app
updates. See [docs/workstation-software-bases.md](docs/workstation-software-bases.md),
including what supporting a second commit requires.

Nest also checks its NixOS channel daily (and when Tiaris asks): it derives
the build profile of a new commit from the shipped Tiaris reference
Blueprints (never from an organization's Blueprints), verifies the commit is
on its channel's branch after the release pin, and records the commit as
`ready` or `blocked` with a reason. Ready
commits are admitted for Blueprint jobs and, to a Tiaris that accepts Nest
protocol 5, reported in `detected_nixpkgs_commits`.
When Nest has built the update candidate Manage prepares from a released
Blueprint at such a commit, it scans the release and candidate closures with
vulnix and reports the advisories the candidate fixes, with the cache status
of each App List package at that commit, in `software_update_findings`.

## Workstation cache seeds

Workstations use the Nest cache (`/cache`) before cache.nixos.org. The outputs
cache.nixos.org cannot serve (every output of the exact workstation agent and
the Blueprint custom outputs selected by Manage's
`deploy/nixos/tiaris-workstation-cache-seeds.nix`) ship in the signed appliance
closure and are listed in `/usr/share/tiaris-nest/workstation-cache-seeds.json`
(`cache.seed_manifest_path`). Nest publishes them into its own cache, signed
with its cache key, without a build job (`src/cache/seeds.rs`): when the daemon
starts, 10 minutes after a failure, hourly while a seed cannot be
authenticated, when the manifest changes and once a day. Only seeds that are
valid in the local store and signed by the appliance release key are copied; a
seed whose verified closure is already cached is left alone, and a closure that
fails verification is quarantined like a failed build export. Seeds are not
artifacts: they are not reported to Tiaris and retention never evicts them,
though they count towards the cache size. The cache sweep keeps the closures
the current manifest lists, so the seeds of an earlier release are swept like
any other unreferenced member.

## Self-substitution

Nest's Nix daemon substitutes from Nest's own signed export first
(`file:///var/cache/tiaris-nest/www/cache?priority=10`, then cache.nixos.org
and the Tiaris software cache), so a build after the daily `nix-store --gc`
takes what Nest already exported from its own disk instead of the internet.
The daemon trusts the Nest cache key only through
`/etc/tiaris-nest/nix-self-cache.conf`, which the root unit
`tiaris-nest-self-cache-trust` writes from the Nest's public key whenever it
changes: one validated `extra-trusted-public-keys` line and nothing else
(`nixos-appliance/runtime/self_cache_trust.py`). Before the key exists, or if
it is invalid, the include is empty and the export is simply not used.
tmpfiles creates the export layout (`cache/`, `nar/`, `realisations/`) as the
Nest, because Nix's daemon would otherwise create a missing layout as root.

Trusting that key lets the `tiaris-nest` service user, which holds the
private key, place arbitrary store paths in the root store (sign and import
them, or ask the daemon to substitute them). Workstations already trust every
path that key signs, so nothing changes for them. Appliance updates stay on
the release-key-only path: the importer copies with no substituters, roots the
closure, and refuses the candidate unless every installed member's NAR hash is
the signed release's (`generation_update.verify_store_closure`), before it
runs anything from the new system.

## Development

```sh
cargo fmt --all --check
cargo test --locked
cargo build --release --locked
python3 -B -m unittest discover -s tools/tests -v
cargo test --locked python_packer_archive_verifies_and_extracts_in_rust -- --ignored
cargo test --locked --test cache_seeds_nix -- --ignored
python3 -B -m unittest discover -s nixos-appliance/tests -p 'test_*.py'
bash -n nixos-appliance/build-closure.sh
bash -n nixos-appliance/build-template.sh
```

The real cache tests use private local Nix stores and temporary keys; they run
automatically in disposable CI and need no VM qualification. Set `TIARIS_TEST_NIX`
to select a Nix binary. Optional non-mutating development API checks run with
`TIARIS_NEST_LIVE_ORIGIN=https://dev.tiaris.com` on the Python appliance suite.

The installed service uses `/etc/tiaris-nest/config.toml` and the V2-activated
identity at `/var/lib/tiaris-nest/state/manage-state.json`. It reports
`appliance_update_v1` for networking/recovery and additive `appliance_update_v3`
for signed system-closure updates from Tiaris. Workstation-netboot publication and appliance maintenance coordinate
through a shared lock so runtime promotion cannot race an appliance update.
Runtime compatibility is the explicit epoch in `protocol/compatibility.json`,
not equality between the running Tiaris revision and the descriptor's signed
`manage_source_revision`. That SHA remains provenance for reproduction and
audit, and selects the exact root-owned offline Tiaris source archive used by
installer-target builds. Compatible desired runtimes reconcile automatically in a single-flight
background task, so downloads and import failures do not delay Build, Cache,
appliance reporting, or managed heartbeats. Nest keeps serving its verified
active runtime while a newer candidate is retried; the candidate import state
and current service availability are intentionally separate signals in Tiaris.

Nest also advertises `workstation_netboot_transport_v1` for explicitly allowlisted
offline qualification fixtures. Its optional unsigned `bundle_transport_url` changes
only the download endpoint; the original signed descriptor and every integrity,
source and anti-rollback check remain authoritative. See the
[transport contract](protocol/workstation-transport-v1.md).

Nest advertises `installer_target_build_v3` when it accepts the device-agnostic
cohort identity `tiaris.installer-target.build.v3` for exact installation jobs.
That identity names only closure inputs — Blueprint revision and artifact
hash, generated-Nix, expected-state, hardware-module and target-module digests,
driver policy, Tiaris source revision, nixpkgs pin, and source lock — and Nest
verifies every digest against the module text it evaluates before building, so
the echoed identity proves the exact inputs of a closure Tiaris may reuse for
every workstation in the same hardware cohort. Nest also still advertises
`installer_target_build_v2` and accepts the per-device v1/v2 identity shapes so
retained jobs from before the upgrade remain retryable; current Tiaris issues
only v3 and refuses to prepare installations on a Nest without it
(`nest_installer_closure_unsupported`). Deploy Nest before Tiaris.

Source-free Blueprint preparation classifies the exact evaluated derivation
graph in an isolated store. Deterministic NixOS composition outputs and their
qualified tool providers are admitted by strict fingerprints, while an
unrecognized source-producing derivation remains blocked and is reported in
bounded `source_build_candidates` diagnostics.
The `/etc` compositions with retained fixtures (Tiaris KDE Standard, GNOME
Taskbar/Dock, Tiling and the generic desktop prebuild, plus the retained
production Standard, Dock and Tiling recipes) are pinned independently of the
configured time zone: only the zone of NixOS's single `/etc/localtime` entry
may vary, and only as an IANA-style name (one to three `/`-separated
components that start with a letter and contain only `A-Z a-z 0-9 _ + -`, at
most 64 bytes). The older Standard, Dock and Hyprland `/etc` pins without a
fixture still match only their recorded zone. NixOS's
`xkb-validated` keyboard check is admitted for any model, layout, variant and
option list limited to letters, digits and `_ - , : + ( )` when it uses the
exact reviewed command with the cache-backed `xkbvalidate` and
`xkeyboard-config` outputs. A regional time zone or keyboard layout therefore
needs no permission to compile packages from source.

Runtime integrity maintenance rechecks retained bundles every 12 hours and
renews the active runtime's reported verification time only after a successful
check. This keeps healthy nodes within Tiaris's 24-hour verification window.
Maintenance also repairs stale runtime evidence after an upgrade, even when
the bundle was checked recently; a corrupt or predecessor bundle cannot renew
the active runtime's evidence.

The migration history retains the multicast state migration already used by
the `.19` development appliances. Later builds must preserve that migration
and its checksum even though multicast is retired, so those appliances can
restart or upgrade without discarding their state.

The SQLite schema starts with the inventory of the published releases
(`release/sqlite-migrations.sha256`): releases before schema evolution refuse
an update whose migration inventory differs (`rollback_database_incompatible`).
Later releases admit declared expand/contract migrations that the installed
release can still run on after a rollback, proven on a copy of the live
database before the update; see `docs/sqlite-schema-evolution.md`. `cargo test`,
the tool tests and the `manifest` signing step refuse any other change to
`migrations/`, and still refuse every new migration until
`release/sqlite-schema-evolution.json` says the releases Nests update from run
declared changes. Until then new state lives in files under the Nest state
directory (`src/state_files.rs`): detected commits, scans and upload grants.

Nest state and keys can be backed up encrypted and restored onto a
replacement Nest: `docs/nest-state-backup.md`.

## Off-site software uploads

A computer away from school cannot reach its Nest. For updates it may
download off-site (Manage `docs/software-cache.md`, design section 7), Nest
uploads what it built itself to its organization's tree of the Tiaris
software cache (`src/software_cache_upload.rs`). Grants and their progress are
files under `<data_dir>/software-cache-uploads/`: the grant document as Manage
sent it (`<id>.grant`) and its state (`<id>.state.json`), whose progress names
items only by their index in the grant. A corrupt state restarts the grant with
exactly its own items; a missing or altered document fails that grant.

- **Capability.** Nest advertises `software_cache_upload_v1` only when
  Manage's configuration says it accepts it
  (`software_cache_upload_supported: true`); a Manage that does not know the
  capability rejects the whole report.
- **Configuration.** `software_cache.upload` is `{url, token, expires_at,
  grants}`: the tree `https://cache.tiaris.com/o/<issuer>/o-<organization hex>`,
  a `tsc2` write token, and Manage's signed upload grants
  (`[{grant: "tug1.<payload>.<mac>", grant_id, …}]`). The token is kept in
  `<data_dir>/software-cache-upload.json` (0600, written and read without
  following links) and never logged. Grants Manage stops sending are
  forgotten; without `upload`, the token file and every grant are removed.
- **Uploading.** Each grant is registered (`POST <tree>/upload-grants`), then
  each granted store path is uploaded from the Nest cache, NAR before
  narinfo, the narinfo exactly as Nix wrote it with the Nest signature.
  Every PUT carries the write token as the Basic password and
  `X-Tiaris-Upload-Grant: <grant id>`. Nothing outside a grant is sent: a path
  whose local narinfo or NAR does not match the grant is refused locally
  (`narinfo_mismatch`, `nar_mismatch`, `not_in_cache`); a NAR's FileHash is
  checked before the same open file is sent. Files a grant names (Manage's
  source archive, which Manage stopped granting on 17 November 2026) are
  never uploaded. A path already in the tree is skipped; a stored grant that no
  longer decodes fails alone (`grant_invalid`).
- **Bounds.** One grant and one upload at a time, at most 8 MiB/s. Network,
  server and token errors stop the pass and retry the grant 1, 2, 4 …
  minutes, at most an hour, after the failure (not after the pass started);
  success resets the backoff. An expired grant or token is never used. A 507
  fails the grant (`quota_exceeded`).
- **Report.** To such a Manage each report carries
  `software_cache_uploads`: per grant `{grant_id, manifest_id, state:
  pending|uploading|uploaded|failed|expired, paths_total, paths_uploaded,
  items_failed, bytes_uploaded, error?, updated_at}`.

## Wake-on-LAN

Nest advertises `wake_on_lan_v1` and accepts bounded, signed wake requests
from Tiaris. Each request is tied to an existing workstation placement and a
normalized MAC address. Nest sends the standard magic packet three times on
UDP ports 9 and 7, stores a durable `sent` or `failed` receipt in SQLite, and
replays that receipt until Tiaris acknowledges it. Repeated configuration
syncs therefore never create an unbounded wake storm.

Wake-on-LAN is best effort. A failed or expired wake request does not fail or
cancel the authoritative Blueprint operation: the workstation remains safely
queued and converges when it next checks in. Nest reports only bounded error
codes and never treats a wake receipt as proof that a workstation actually
started.

## What a network boot starts

A computer that is not installed gets the installer every time it starts
from the network, until it is installed. An installed computer starts from
its disk. Tiaris decides which it is, not whether the Nest saw the MAC address
before: the boot configuration lists the computers Tiaris knows by the
fingerprint of their system UUID (`machines: [{fingerprint, installed}]`) and
says whether that list is complete (`machines_complete`). `autoexec.ipxe`
sends the UUID (`uuid=${uuid}`).

| The computer | Starts |
| --- | --- |
| Has a profile assigned on its MAC (a reinstall Tiaris asked for, a custom profile) | that profile |
| Listed as installed | its disk, then the menu |
| Listed as not installed: waiting for approval on Add, being installed or reinstalled, or its installation failed halfway | the installer |
| Not in a complete list: new, or removed or rejected in Tiaris | the installer |
| Cannot tell: no usable system UUID, or no complete list on this Nest | the installer the first time the Nest sees its MAC, afterwards its disk, then the menu |

- The installer here is the one default Nest installer profile. It only
  starts the signed installer runtime; nothing is erased before an
  administrator approves it in Tiaris. Without exactly one default installer
  profile the computer gets the menu.
- Tiaris lists a computer as installed as soon as its installation has
  finished: it restarts within seconds, before the regular sync (every 30
  seconds). So before the Nest starts the installer on the list's word, it
  asks Tiaris for the newest boot configuration (`manage::refresh_boot_config`,
  at most 5 seconds; concurrent boots share one request).
- **No fresh list is the safe default.** When Tiaris does not answer, the
  last list stands; the installer waits for Tiaris by itself. When the Nest
  has no complete list at all, or the computer reports no usable system UUID,
  the old rule applies (last row of the table), so an installed computer
  never enters the installer by itself.
- Requests without a MAC address and the Nest's own health check never start
  anything by themselves.

## Laptops that share one network adapter

Laptops without their own network port start through a USB adapter or dock
that moves from laptop to laptop, so the MAC address names no single
computer. `autoexec.ipxe` therefore also sends the SMBIOS serial
(`serial_hex=${serial:hexraw}`) and system UUID (`uuid=${uuid}`); menu links
carry both. The Nest hashes the UUID into the hardware fingerprint the Tiaris
agent reports (`sha256("tiaris-hardware-v1\ndmi_product_uuid=<uuid>")`).

- **Reinstall.** A network reinstall armed on a MAC goes only to the computer
  Manage names for it (`reinstall_machine` on the boot client: its
  fingerprints, and `required` when the MAC is shared). A boot whose UUID is
  another computer's, or on a shared MAC a boot without a UUID, gets the menu
  and no reinstall binding, also in the installer grant. The computer the
  reinstall is for gets it even when the MAC is registered to another
  laptop's serial. `GET /boot/<mac>/kexec.json` is unchanged: the computer's
  own agent asks for it on Manage's signed command.
- **Known computers.** On another computer's adapter the list from Tiaris
  decides as on a computer's own adapter: an installed computer starts its
  local disk first, one that is not installed gets the installer. Where
  Tiaris cannot tell, a computer whose serial this Nest knows from another
  adapter gets the menu, and a computer nobody knows gets the menu with the
  "registered to another computer" notice; neither enters the installer by
  itself.
- Without a usable UUID the serial rule decides as before. What Manage says
  is kept in the state file `boot-identity/boot-identity.json`, written before
  the boot configuration that needs it is committed.

Nest advertises `boot_machine_identity_v1` only when Manage says it accepts
the capability (`boot_machine_identity_supported`); Manage arms a network
reinstall on a shared MAC only for such a Nest.

## USB installer stick

Computers that cannot network-boot (no PXE through their USB Ethernet adapter,
Chromebooks with MrChromebox UEFI firmware, Wi-Fi-only laptops) start from a
USB stick instead (Tiaris `docs/design/usb-installer.md`). There is one
generic stick for every Nest, downloaded from Tiaris. It finds its Nest on the
network, or uses the Nest address file the administrator saves on it from the
Console. The Nest does not serve or personalize the stick (it did until
November 2026); it answers the stick protocol:

- `GET /usb-installer/v1/boot?mac=&serial_hex=` answers with a `launch` (the
  `tiaris.nest.kexec.v1` session plus the runtime's component digests), with
  the identification, selection, one-time consumption and boot events of
  `/boot/<mac>`. Where `/boot/<mac>` would start the disk, custom iPXE or the
  menu, the stick gets the default installer profile: someone started the
  stick on that computer on purpose. There is no menu; a Nest without exactly
  one default installer profile answers `404 profile_unavailable`. A running
  installer asks the same question to renew its boot grant.
  `GET /usb-installer/v1/runtime` names the active runtime without creating a
  session. A stick older than `MINIMUM_STICK_PROTOCOL` gets `410`.

The stick starts the runtime with `kexec`; the grant, enrollment and approval
are those of network boot, and its Wi-Fi password never reaches Nest.

`build-template.sh` writes the stick image beside the template ISO, as
`tiaris-usb-installer.img` and its build record `tiaris-usb-installer.json`
(checked against each other), when the pinned Tiaris revision builds a stick.
Tiaris publishes that copy as a public download (Tiaris `docs/downloads.md`).
It is not a release asset, not part of the installed Nest, and nothing signed
changes: the release manifest keeps its exact keys.

## Retired rootfs multicast

Nest no longer sends the workstation root filesystem by multicast (November
2026); computers download it over HTTP. Older runtimes still ask for a
multicast offer, get a 404 and download over HTTP at once. Its SQLite tables
stay, unused: a Nest update refuses any database migration.

## NixOS appliance

The implementation is under [`nixos-appliance/`](nixos-appliance/): immutable
personalized ISO templates, a writable Nix store, persistent STATE, ordinary
system generations, supervised one-shot boot and automatic rollback. Signed
two-phase systemd-networkd changes, certificate-only SSH and workstation
netboot keep their existing management contracts. Firmware Secure Boot is
informational; it is not an update or network admission rule.

Ubuntu V1/V2 appliances require a human reinstall from the current ISO. There
is no Ubuntu-to-NixOS update. Ubuntu builders and appliance runtime scripts
have been removed; historical signed descriptors remain readable for ancestry.

## Release format

`tiaris.nest.release.v1` retains its outer schema and `appliance_release_v1`
member. New releases contain `installer_iso_template_v3` with
`package_delivery=system-closure-v1`, and inner
`tiaris.nest.appliance-release.v3`. The descriptor signs the exact system
toplevel, archive digest/size, source and nixpkgs revisions, SQLite migration
inventory and system version anchors. The same closure installs and updates
Nest. Protocol 4 and workstation runtime epoch 1 remain unchanged.

The canonical signed `tiaris-nest-release-compatibility.json` retains its
historical `appliance_package_snapshot` identity slot for the closure archive.
Its signature binds every published artifact and the exact main manifest.
It embeds the component contract and its full digest. Nest accepts both
`tiaris.component-compatibility.v1` and Manage's additive v2, which keeps every
v1 field unchanged and adds `component_floors` and `signed_artifacts`; Nest
checks only the v1 fields (its projection), so v2 changes no signed tuple.
The closure's embedded Tiaris source archive must match the source hash and
size in the workstation descriptor. Historical V1/V2 signatures remain
verifiable; they do not authorize current installations or updates.

See [`RELEASES.md`](RELEASES.md), [`SECURITY.md`](SECURITY.md), and the
[appliance build and layout guide](nixos-appliance/README.md).

### Coordinated Tiaris releases

Release candidates build in a disposable Docker container on The Beast, using
dedicated local Cargo and Nix caches. Builders export unsigned Nix caches;
private signing keys remain outside the builder and Nix store. Signed files stay on the server
through appliance qualification; GitHub Actions retains a small hash receipt.
Publication uploads the verified files once, and the public-closure check
downloads the published closure through the candidate downloader. On-demand VM
qualification (`nest-vm-qualification.yml`) downloads the published payload
independently. See [the local release environment](release/beast/README.md)
for isolation, retention and recovery details.

Qualification retries use evidence directories unique to the workflow run and attempt.
Failed or canceled runs return directory ownership to the runner for cleanup; old
acceptance evidence is never overwritten or reused by a retry.

The Tiaris release controller on The Beast (`tiaris-release`, implemented in CybexHQ/tiaris
`deploy/manage/beast_release_workflow.py`) creates a candidate tag with `release/coordinated.json` and
an immutable workstation source pin to `CybexHQ/tiaris`. The normal release workflow still signs,
builds once, publishes an immutable prerelease and verifies its public closure; under release policy
fast-v1 VM qualification is on demand (`Tiaris-VM-Qualification: nightly`). These tags skip
automatic stable promotion. `approve-coordinated-release.yml` promotes only explicitly approved
tag/source/run and artifact identities, reusing the canonical predecessor/public-closure verifier and
publication lock. `promote-production-release.py --verify-only` checks the same evidence without
changing publication.

The authoritative runtime pin of a release is the `release/workstation-netboot-source.json` committed
at its tag, not the copy on `main`; see [where the runtime pin lives](RELEASES.md#where-the-runtime-pin-lives).

The `production-release` environment holds a read-only key for the private development repository
in `CYBEX_DEVELOPMENT_SOURCE_SSH_KEY` (a sealed secret keeps its pre-rename storage name). Never copy
development changes into the production Tiaris checkout to build a runtime.
The coordinator retains source bundles for recovery; version tags and signed assets must never be
rewritten. A failed or cancelled coordinated preparation can leave a safe, unpromoted prerelease.

The production-release environment admits version tags only. The former source-access dispatch
(`check-development-source.yml`) is retired: local preparation checks source availability, and the
tagged producer checks out the exact development commit with that protected key before any build or
signing step. The private deploy key is available only inside that protected environment.

### Managed appliance updates

The Nest prepares an update as soon as it arrives, while the running release
keeps serving: root independently verifies the bounded archive and the live
SQLite migration inventory, imports and roots its closure, checks it against the
release and rehearses the database (status `waiting_window`, stage
`preparing_ahead`). Nothing touches boot state yet. Signed policy then admits
the switch: **Update now**, the Nest being idle (mode `when_idle`, the default
from Manage), or the maintenance window (mode `window`, and every v1 policy).
While it waits the stage is `nest_busy` or `maintenance_window`. At the switch
root checks the closure again, seals the next generation and selects it for one
boot. Holds, active builds, maintenance leases and network transactions defer
it. The service polls requests every 30 seconds.

Idle means nothing kept the Nest busy for 10 minutes: no request from a
computer in flight or served (boot, netboot, installer, USB stick, cache; health
probes do not count), no unexpired boot grant and no queued or running build.
The daemon writes this to `/run/tiaris-nest/activity.json`
every 20 seconds (`src/activity.rs`). A missing or stale report counts as busy
until the Nest has been up for 30 minutes: then the daemon serves nothing.

The known-good EFI default stays in place until repeated fresh local health
and permanent-identity Tiaris contact succeed. Failure returns to the known-good
generation and reports a reason. Durable receipts recover power loss without
turning an unfinished attempt into success. Retention preserves current plus
two preceding known-good generations. The old Ubuntu snapshot cutoff and
root-service immediate-update override are not NixOS policy inputs.

## Production releases

Only NixOS Nest V3 is built and released. See [production qualification](nixos-appliance/qualification/PRODUCTION.md) for isolated exact-origin verification and the separate production approval step. Ubuntu appliance execution support has been removed; historical signed releases remain ancestry evidence, and existing Ubuntu appliances require reinstallation.

Memory accounting, bounded build/cache I/O, admission settings and the performance
qualification procedure are documented in [Nest memory](docs/memory-implementation.md).

## Licence

The source code in this repository is licensed under the
[Apache License 2.0](LICENSE). See [NOTICE](NOTICE).

The Nest image also contains other software, each under its own licence. This
includes a source archive of the Tiaris workstation software: the build
([`build-manage-source-archive.sh`](nixos-appliance/build-manage-source-archive.sh))
packs one exact commit of the separate Tiaris repository into
`/usr/share/tiaris-nest/manage-source/<revision>.tar`. That archive is not part
of this repository and is not covered by this licence. The licence does not
grant use of the Tiaris name or logo.
