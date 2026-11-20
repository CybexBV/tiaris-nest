# Generic desktop prebuild with the DNS retry timer

`generic-desktop-prebuild-dns-retry-generators.json` is the unmodified output
of one `nix derivation show` call (Nix 2.26.3, unversioned derivation JSON) on
nine derivations evaluated on 2026-11-20. Nothing was built and nothing was
reconstructed: the systems were only instantiated.

They are what Tiaris' release check "deployment contracts"
(`deploy/nixos/check-workstation-cache-contract.py`) evaluates for the built-in
profiles Dock and Taskbar, and what the strict source policy refused there for
both Nest `bc92bb4` and Nest `a04f15b`:

| Profile | `system-units` | `etc` | `activate` | system |
| --- | --- | --- | --- | --- |
| Dock | `kiaf8h7z…` | `bfh66n74…` | `gjknz57f…` | `ygpm964s…` |
| Taskbar | `rz0m22zm…` | `nycq53bg…` | `hj9hi1il…` | `q7vq2y5d…` |

The ninth is the unit file both `system-units` recipes link,
`3k88py0x…-unit-tiaris-networkmanager-dns-retry.timer.drv`.

Source pins:

- Tiaris (compiler and desktop module): `da5ab0c83c256056c1d0e11c42d061f9aaf3dd29`.
  Its `export_workstation_cache_contract_fixtures` test wrote the exports.
  SHA-256: `desktop.nix`
  `52d3caa71e0754e9cd426ce7e1e663c79f5163fac315d3466fc185652ba19c5a`, `dock.nix`
  `956503e15acc672eb15b1429fcefa8617ed0a11d17972e8da55706f36dbe2ed7`, `taskbar.nix`
  `8217b25c92ec8e1da6ca1e5cf97701f19d88d21a0dc377802524d4e4c288e67e`.
- Nest prebuild templates: `nest_nixos_configuration` and
  `blueprint_compat_module` from `src/build.rs` at `a04f15b` (byte-identical at
  `bc92bb4`), extracted as the check does.
- nixpkgs: `74cc63f702f7d60a557e152a57b40fb1fd0f72ac`.

Each system is the check's own fixture flake: `nixos/lib/eval-config.nix` over
`[ nest-configuration.nix, <profile>.nix ]`.

## What changed

The same evaluation at Tiaris `8930faa96` (production release of 2026-11-19)
gives the reviewed recipes: `system-units` `4afc0bcc…`/`f05a7ab5…` and the
zone-independent `/etc` pair `9cdb204a…`/`58300043…`. At `da5ab0c8` only the
`system-units` recipe differs, for both profiles alike. After store-path
normalization the whole difference is one more unit file in the list of the
recipe's `for i in …; do` line (line 59 of 200), between
`unit-tiaris-network-priority.service` and
`unit-tiaris-networkmanager-dns.service`:

```text
/nix/store/<hash>-unit-tiaris-networkmanager-dns-retry.timer
```

Tiaris commit `71d968509` ("the DNS writer retries when the profile lock stays
busy") added it. The unit is a text file with a `[Timer]` section
(`OnActiveSec=30s`, `RemainAfterElapse=false`,
`Unit=tiaris-networkmanager-dns.service`) and no `[Install]` section, so the
recipe gains no `.wants` link. Builder, arguments, stdenv, environment
attributes, input sources and the one executable provider (`lndir`) are
unchanged; no build command or phase hook was added. Its only new input is the
timer unit, which the existing NixOS materialization rule admits by itself.

The new fingerprint pair, the same for Dock and Taskbar:

- Store-normalized: `2c373e0992a2964430499d242b1c1c8add6b11541e62bd1ff68df40113ce4e70`.
- Executable-pinned: `7a47622b1b8dd64dde2a501a86556f3d8d1997a870c16c5d879a09fc871248c3`.

The earlier pair stays pinned: computers on the previous runtime still build
the recipe without the timer.

The `/etc`, `activate` and system recipes are byte-identical to the reviewed
ones after store-path normalization. They were refused only because they
depend on the refused `system-units`.

Between the two revisions the text of four existing units changed as well:
`tiaris-networkmanager-dns` in `71d968509`, and `tiaris-ensure-printers`,
`tiaris-network-priority` and `tiaris-reconcile-device-restrictions` in
`a198c6781`. `b93d41efe` removed three settings from `etc-tiaris-policy.json`.
Those are plain materializations the policy already admitted, and no recipe
names their content.

The regressions check both profiles' real graphs parents first. They assert
the pair, that removing the one unit file gives the earlier pair, and that the
halves of the two pairs cannot be mixed. They reject the whole chain above
`system-units` when its recipe gains a compiler command or a phase hook or
changes its executable provider, and the whole chain when the timer unit runs
a command. Source-file verification is synthetic only in unit tests.
