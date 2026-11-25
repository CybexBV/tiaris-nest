{ config, lib, pkgs, ... }:
let
  cfg = config.services.tiaris-nest;
  a = cfg.appliance;
  bootstrapPackage = a.bootstrap or (a.package.bootstrap or a.package);
  runtime = import ./runtime.nix { inherit pkgs; inherit (a) package; bootstrap = bootstrapPackage; };
  # Override vulnix's nix input to nix.out so build-time -dev headers (boost-dev,
  # nix-dev: ~212 MiB unpacked) never leak into the Nest appliance closure.
  vulnix = (pkgs.vulnix.override { nix = pkgs.nix.out; }).overrideAttrs (_: {
    disallowedReferences = [ pkgs.boost.dev pkgs.nix.dev ];
  });
  coturn = pkgs.coturn.overrideAttrs (previous: {
    patches = (previous.patches or [ ]) ++ [ ./coturn-max-allocation-lifetime.patch ];
  });
  ipxe = pkgs.ipxe.override { additionalTargets."bin-x86_64-efi/snponly.efi" = null; };
  command = name: "${runtime}/bin/tiaris-nest-${name}";
  publicKey = pkgs.writeText "nest-release-public-key" (a.releasePublicKey + "\n");
  provisioningKeys = pkgs.writeText "nest-provisioning-public-keys" (lib.concatStringsSep "\n" a.provisioningPublicKeys + "\n");
  immutableMetadata = pkgs.writeText "nest-system-inputs.json" (builtins.toJSON {
    schema = "tiaris.nest.system-inputs.v3";
    release_id = a.package.version; base_os = "nixos"; base_os_version = "26.05";
    source_revision = a.sourceRevision; manage_source_revision = a.manageSourceRevision;
    nixpkgs_revision = a.nixpkgsRevision; manage_origin = a.manageOrigin;
    required_system_versions = { kernel = config.boot.kernelPackages.kernel.version; linux-firmware = pkgs.linux-firmware.version; nix = config.nix.package.version; tiaris-nest = a.package.version; systemd-boot = config.systemd.package.version; };
  });
  baseUnit = { path = [ pkgs.coreutils pkgs.curl pkgs.jq pkgs.util-linux pkgs.systemd pkgs.nix pkgs.python3 a.package bootstrapPackage runtime ]; };
  rootService = name: {
    description = "Tiaris Nest ${name}";
    serviceConfig = { Type = "oneshot"; ExecStart = command name; UMask = "0077"; };
  } // baseUnit;
  # The manifest's store paths carry their string context, so the file itself
  # references every seed and cannot ship without them.
  seedManifest = pkgs.writeText "tiaris-nest-workstation-cache-seeds.json" (builtins.toJSON cfg.workstationCacheSeedManifest);
in {
  options.services.tiaris-nest = {
    enable = lib.mkEnableOption "managed NixOS Nest appliance";
    appliance = lib.mkOption { type = lib.types.attrs; description = "Organization-neutral package, source identity and public trust inputs"; };
    workstationCacheSeeds = lib.mkOption {
      type = lib.types.listOf lib.types.package;
      default = [ ];
      description = ''
        Workstation outputs that cache.nixos.org cannot substitute. They are
        carried in the signed system closure, listed in
        /usr/share/tiaris-nest/workstation-cache-seeds.json, and published by
        tiaris-nest into its own binary cache (src/cache/seeds.rs).
      '';
    };
    workstationCacheSeedManifest = lib.mkOption {
      type = lib.types.attrs;
      internal = true;
      readOnly = true;
      description = "Contents of /usr/share/tiaris-nest/workstation-cache-seeds.json.";
    };
  };
  config = lib.mkIf cfg.enable {
    # One list feeds both the closure and the shipped manifest, so the daemon
    # publishes exactly the seeds this generation carries.
    system.extraDependencies = [ a.sourceArchiveFile ] ++ cfg.workstationCacheSeeds;
    services.tiaris-nest.workstationCacheSeedManifest = {
      schema = "tiaris.nest.workstation-cache-seeds.v1";
      store_paths = lib.unique (lib.sort builtins.lessThan (map toString cfg.workstationCacheSeeds));
    };
    users.groups.tiaris-turn.gid = 437;
    users.users.tiaris-turn = { uid = 437; group = "tiaris-turn"; isSystemUser = true; };
    users.groups.tiaris-nest.gid = 985;
    users.groups.nix-users = {};
    users.groups.tftp = {};
    users.users.tiaris-nest = { uid = 985; group = "tiaris-nest"; extraGroups = [ "nix-users" ]; isSystemUser = true; home = "/var/cache/tiaris-nest/agent/home"; createHome = false; };
    users.users.tiaris-support = { isNormalUser = true; hashedPassword = "!"; home = "/var/lib/tiaris-support"; };
    users.users.tftp = { isSystemUser = true; group = "tftp"; };
    users.users.dnsmasq = { isSystemUser = true; group = "nogroup"; };
    users.groups.nogroup = {};
    networking.useDHCP = false;
    networking.useNetworkd = true;
    networking.networkmanager.enable = lib.mkForce false;
    networking.firewall.enable = false; # owned atomic default-deny nftables input allowlist (tiaris-nest-firewall)
    boot.kernelModules = [ "nf_conntrack_tftp" ];
    systemd.network.enable = true;
    services.resolved.enable = true;
    services.timesyncd.enable = true;
    services.journald.extraConfig = "SystemMaxUse=256M\nRuntimeMaxUse=64M\nMaxRetentionSec=14day";
    systemd.settings.Manager = { RuntimeWatchdogSec = "120s"; RebootWatchdogSec = "10min"; };
    nix.settings = {
      sandbox = true;
      allowed-users = [ "root" "@nix-users" ];
      trusted-users = [ "root" ];
      # Blueprint builds need upstream binary dependencies. Appliance imports
      # separately verify every NAR against the release key and disable remote
      # substitution explicitly; recovery media retains release-only trust.
      # The Tiaris software cache serves what cache.nixos.org does not build
      # (unfree apps, NVIDIA, directory sign-in); Manage supplies its access
      # token, which src/software_cache.rs writes to the netrc file. Only then
      # is the cache a substituter, after cache.nixos.org: the root unit
      # tiaris-nest-self-cache-trust adds it through the include below. Where
      # the cache is off, Nix never asks that host. Its key is trusted here.
      # The Nest's own signed export comes first: a build after the daily
      # garbage collection takes what the Nest already exported from its own
      # disk, not from the internet. Its key is trusted through the include
      # below (tiaris-nest-self-cache-trust); without it, or for a path the
      # export lacks, Nix moves on to the next substituter.
      substituters = lib.mkForce [
        "file:///var/cache/tiaris-nest/www/cache?priority=10"
        "https://cache.nixos.org"
      ];
      trusted-public-keys = lib.mkForce [
        "tiaris-nest-appliance-1:${a.releasePublicKey}"
        "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY="
        "cache.tiaris.com-1:xIrpkpeFBAzhhUQojSWqkpAWTwGoW4HtUEtHAcd4taY="
      ];
      netrc-file = "/var/lib/tiaris-nest/state/agent/software-cache.netrc";
      require-sigs = true;
      experimental-features = [ "nix-command" "flakes" ]; # existing Blueprint jobs use governed flakes
      auto-optimise-store = false; # source exposure explicitly preserves nlink=1
    };
    # Root-written (runtime/self_cache_trust.py): one validated
    # `extra-trusted-public-keys` line naming this Nest's own cache key, absent
    # until the Nest has generated its key, and the fixed line that adds the
    # Tiaris software cache as a substituter while Manage gives access to it.
    # Appliance updates never depend on it: they
    # import with no substituters and check every closure member against the
    # signed release (generation_update.verify_store_closure).
    nix.extraOptions = ''
      !include /etc/tiaris-nest/nix-self-cache.conf
    '';
    nix.gc.automatic = false;
    # Include daemon-side builders in diagnostics. No throttling/OOM limits:
    # smaller budgets require the performance qualification gate first.
    systemd.services.nix-daemon.serviceConfig.MemoryAccounting = true;
    documentation.enable = lib.mkForce false;
    documentation.man.enable = lib.mkForce false;
    documentation.doc.enable = lib.mkForce false;
    documentation.info.enable = lib.mkForce false;
    documentation.nixos.enable = lib.mkForce false;
    environment.defaultPackages = lib.mkForce [ ];
    environment.systemPackages = [ a.package bootstrapPackage runtime pkgs.iproute2 pkgs.iputils pkgs.curl pkgs.jq pkgs.nftables pkgs.dnsmasq pkgs.openssh pkgs.python3 pkgs.tftp-hpa ];
    services.openssh = {
      enable = true;
      settings = { PasswordAuthentication = false; KbdInteractiveAuthentication = false; PermitRootLogin = "no"; PubkeyAuthentication = true; AllowUsers = [ "tiaris-support" ]; TrustedUserCAKeys = "/etc/ssh/tiaris-nest-ca.pub"; AuthorizedPrincipalsFile = "/etc/ssh/tiaris-nest-principals"; AllowAgentForwarding = true; AllowTcpForwarding = "yes"; GatewayPorts = "no"; PermitTunnel = "no"; X11Forwarding = false; };
    };
    systemd.services.sshd = { aliases = [ "ssh.service" ]; requires = [ "tiaris-nest-first-boot.service" "tiaris-nest-firewall.service" ]; after = [ "tiaris-nest-first-boot.service" "tiaris-nest-firewall.service" ]; };
    services.nginx = import ./nginx.nix { pxeMenu = "${a.package}/share/tiaris-nest/assets/pxe-menu.png"; };
    systemd.services.nginx = { after = [ "tiaris-nest-first-boot.service" ]; requires = [ "tiaris-nest-first-boot.service" ]; };
    systemd.tmpfiles.rules = [
      "d /var/lib/tiaris-nest 0750 root tiaris-nest -"
      "d /var/cache/tiaris-nest 0755 root root -"
      "d /var/cache/tiaris-nest/appliance-updates 0755 root root -"
      "d /var/cache/tiaris-nest/appliance-updates/inbox 0700 tiaris-nest tiaris-nest -"
      "d /var/cache/tiaris-nest/appliance-updates/private 0700 root root -"
      "d /var/cache/tiaris-nest/www 0755 tiaris-nest tiaris-nest -"
      "d /var/cache/tiaris-nest/www/assets 0755 tiaris-nest tiaris-nest -"
      # Nix's daemon creates a missing file:// substituter layout as root;
      # the Nest owns its export, so create the layout as the Nest first.
      "d /var/cache/tiaris-nest/www/cache 0755 tiaris-nest tiaris-nest -"
      "d /var/cache/tiaris-nest/www/cache/nar 0755 tiaris-nest tiaris-nest -"
      "d /var/cache/tiaris-nest/www/cache/realisations 0755 tiaris-nest tiaris-nest -"
      # nginx sends the verified runtime bundles below it (nginx.nix); the
      # daemon's staging tree inside stays 0700.
      "d /var/cache/tiaris-nest/www/netboot 0755 tiaris-nest tiaris-nest -"
      "d /var/cache/tiaris-nest/vulnix 0700 tiaris-nest tiaris-nest -"
      # Remove legacy vulnix cache on TIARIS_STATE; the scanner caches NVD data
      # on TIARIS_ROOT (/var/cache/tiaris-nest/vulnix) instead.
      "R! /var/lib/tiaris-nest/state/agent/vulnix"
      # Clear Nix's corruptible binary-cache SQLite cache at boot (matching
      # workstations) so a power cut cannot wedge future evaluations or builds.
      "r! /var/cache/tiaris-nest/agent/cache/nix/binary-cache-v*.sqlite*"
      "r! /root/.cache/nix/binary-cache-v*.sqlite*"
      "d /run/lock/tiaris-nest 0750 root tiaris-nest -"
      "f /run/lock/tiaris-nest/maintenance.lock 0660 root tiaris-nest -"
      "d /etc/tiaris-nest 0755 root root -"
      "d /etc/netplan 0700 root root -"
    ];
    system.activationScripts.tiaris-nest-public-assets = {
      deps = [ "users" ];
      text = ''
        install -d -m0755 /usr/bin /usr/sbin /usr/lib/tiaris-nest /usr/share/tiaris-nest /usr/lib/ipxe
        install -m0644 -o root -g root ${ipxe}/snponly.efi /usr/lib/ipxe/snponly.efi
        install -m0644 -o root -g root ${ipxe}/ipxe.efi /usr/lib/ipxe/ipxe-amd64.efi
        install -m0644 -o root -g root ${./autoexec.ipxe} /usr/share/tiaris-nest/autoexec.ipxe
        ln -sfn ${pkgs.tzdata}/share/zoneinfo /usr/share/zoneinfo
        ln -sfn ${a.package}/bin/tiaris-nest /usr/bin/tiaris-nest
        ln -sfn ${bootstrapPackage}/bin/tiaris-nest-bootstrap /usr/lib/tiaris-nest/tiaris-nest-bootstrap
        ln -sfn ${pkgs.nix}/bin/nix /usr/bin/nix
        ln -sfn ${pkgs.iproute2}/bin/ip /usr/sbin/ip
        ln -sfn ${pkgs.dnsmasq}/bin/dnsmasq /usr/sbin/dnsmasq
        for program in ${runtime}/bin/*; do ln -sfn "$program" "/usr/lib/tiaris-nest/$(basename "$program")"; done
        install -m0444 ${publicKey} /usr/share/tiaris-nest/release-public-key
        install -m0444 ${provisioningKeys} /usr/share/tiaris-nest/provisioning-public-keys
        install -m0444 ${immutableMetadata} /usr/share/tiaris-nest/appliance-release.json
        install -m0444 ${immutableMetadata} /usr/share/tiaris-nest/system-identity.json
        install -m0444 ${a.migrations}/sqlite-migrations.json /usr/share/tiaris-nest/sqlite-migrations.json
        install -m0444 ${seedManifest} /usr/share/tiaris-nest/workstation-cache-seeds.json
        ${pkgs.python3}/bin/python3 ${./runtime/source-copy.py} ${a.sourceArchive} /usr/share/tiaris-nest/manage-source
      '';
    };
    systemd.services.tiaris-nest-network-render = (rootService "network-render") // {
      wantedBy = [ "network-pre.target" ]; requiredBy = [ "systemd-networkd.service" ];
      before = [ "systemd-networkd.service" "network-pre.target" ];
      after = [ "local-fs.target" "systemd-tmpfiles-setup.service" ]; unitConfig.DefaultDependencies = false;
      unitConfig.RequiresMountsFor = [ "/var/lib/tiaris-nest/control" ];
    };
    # The start-up checks, at every start (the name is historical). They read
    # only the Nest's own disk and never wait for the network or for Tiaris:
    # nginx, the boot file server, SSH and the Nest service require this unit,
    # and a Nest restarted during an internet fault must still start them.
    systemd.services.tiaris-nest-first-boot = (rootService "first-boot") // {
      wantedBy = [ "multi-user.target" ]; after = [ "sshd-keygen.service" "systemd-tmpfiles-setup.service" ];
      # sshd Requires= this unit, so a failed attempt fails sshd's start job for
      # the boot. The network-runtime timer retries this unit through Nest; pull
      # sshd into that transaction so recovery SSH starts once this succeeds.
      wants = [ "sshd.service" ];
      requires = [ "sshd-keygen.service" ];
      before = [ "tiaris-nest.service" "nginx.service" "tftpd-hpa.service" ];
      unitConfig.RequiresMountsFor = [ "/var/lib/tiaris-nest/state" "/var/lib/tiaris-nest/control" "/var/lib/tiaris-nest/status" "/nix" ];
      environment.TIARIS_IPXE_SOURCE = toString ipxe;
      environment.TIARIS_HANDOFF_SOURCE = "${./autoexec.ipxe}";
      serviceConfig = { Type = "oneshot"; ExecStart = command "first-boot"; RemainAfterExit = true; TimeoutStartSec = "180s"; };
    };
    # Chooses the approved network or, for a fixed address that cannot reach
    # Tiaris while DHCP can, the DHCP fallback. Nothing requires it: when
    # Tiaris does not answer at all the Nest keeps the network that reached
    # Tiaris last, and its service starts and reports the silence
    # (runtime/tiaris-nest-network-guard).
    systemd.services.tiaris-nest-network-guard = (rootService "network-guard") // {
      wantedBy = [ "multi-user.target" ]; after = [ "tiaris-nest-first-boot.service" "network-online.target" ]; wants = [ "network-online.target" ];
      before = [ "tiaris-nest-network-runtime.service" "tiaris-nest.service" ];
      serviceConfig = { Type = "oneshot"; ExecStart = command "network-guard"; RemainAfterExit = true; TimeoutStartSec = "240s"; };
    };
    systemd.services.tiaris-nest-firewall = (rootService "firewall") // {
      wantedBy = [ "multi-user.target" ]; after = [ "tiaris-nest-first-boot.service" ]; before = [ "sshd.service" ];
      serviceConfig = { Type = "oneshot"; ExecStart = command "firewall"; RemainAfterExit = true; };
    };
    # The boot file server leaves at once while the server has no IPv4 address
    # ("cannot resolve local IPv4 bind address"). It starts once the network is
    # up and is started again for as long as it takes, without a start limit:
    # after a power cut the school's DHCP server can come back minutes after
    # the Nest, and a boot file server that gave up means no computer starts
    # from the network until someone restarts the Nest.
    systemd.services.tftpd-hpa = {
      wantedBy = [ "multi-user.target" ]; after = [ "tiaris-nest-first-boot.service" "network-online.target" ]; wants = [ "network-online.target" ]; requires = [ "tiaris-nest-first-boot.service" ];
      startLimitIntervalSec = 0;
      serviceConfig = { ExecStart = "${pkgs.tftp-hpa}/bin/in.tftpd --foreground --listen --address 0.0.0.0:69 --user tftp --secure /var/cache/tiaris-nest/tftp"; Restart = "always"; RestartSec = "5s"; };
    };
    # The watchdog restarts a hung daemon: it is told the daemon lives only
    # while its own HTTP server answers on loopback (src/main.rs). Five
    # minutes leave a busy Nest alone.
    systemd.services.tiaris-nest = {
      wantedBy = [ "multi-user.target" ]; after = [ "network-online.target" "tiaris-nest-first-boot.service" "tiaris-nest-network-guard.service" "tiaris-nest-network-runtime.service" "nginx.service" "tftpd-hpa.service" "nix-daemon.service" ];
      requires = [ "tiaris-nest-first-boot.service" "tiaris-nest-network-runtime.service" ]; wants = [ "network-online.target" "tiaris-nest-network-guard.service" "nginx.service" "tftpd-hpa.service" "nix-daemon.service" ];
      environment = { HOME = "/var/cache/tiaris-nest/agent/home"; XDG_CACHE_HOME = "/var/cache/tiaris-nest/agent/cache"; XDG_CONFIG_HOME = "/var/cache/tiaris-nest/agent/config"; XDG_STATE_HOME = "/var/cache/tiaris-nest/agent/state"; TMPDIR = "/var/cache/tiaris-nest/agent/tmp"; NIX_USER_CONF_FILES = "/dev/null"; };
      # vulnix scans update candidates (src/software_updates/findings.rs); its
      # NVD database is cached in /var/cache/tiaris-nest/vulnix on TIARIS_ROOT.
      path = [ pkgs.nix pkgs.gitMinimal pkgs.openssh pkgs.coreutils pkgs.iproute2 pkgs.systemd vulnix ];
      serviceConfig = { MemoryAccounting = true; Type = "notify"; NotifyAccess = "main"; WatchdogSec = "5min"; User = "tiaris-nest"; Group = "tiaris-nest"; ExecStart = "${a.package}/bin/tiaris-nest --config /etc/tiaris-nest/config.toml serve"; Restart = "always"; RestartSec = "3s"; UMask = "0077"; NoNewPrivileges = true; PrivateTmp = true; PrivateDevices = true; ProtectSystem = "strict"; ProtectHome = true; ProtectKernelTunables = true; ProtectKernelModules = true; ProtectControlGroups = true; CapabilityBoundingSet = ""; AmbientCapabilities = ""; RestrictAddressFamilies = [ "AF_UNIX" "AF_INET" "AF_INET6" "AF_NETLINK" ]; ReadWritePaths = [ "/var/lib/tiaris-nest/state/agent" "/var/lib/tiaris-nest/state/inbox" "/var/cache/tiaris-nest" "/run/lock/tiaris-nest/maintenance.lock" "/run/tiaris-nest" ];
        # Public console projection (console-status.json, 0644) for the root
        # tty1 kiosk. Preserved across restarts so a stopped daemon leaves a
        # visibly stale status instead of an apparent first boot.
        RuntimeDirectory = "tiaris-nest"; RuntimeDirectoryMode = "0755"; RuntimeDirectoryPreserve = "yes"; };
    };
    systemd.services.tiaris-nest-pxe = {
      wantedBy = [ "multi-user.target" ]; after = [ "tiaris-nest.service" ]; wants = [ "tiaris-nest.service" ];
      serviceConfig = { ExecStart = command "pxe"; Restart = "always"; RestartSec = "5s"; RuntimeDirectory = "tiaris-nest-pxe"; RuntimeDirectoryMode = "0755"; User = "root"; UMask = "0022"; NoNewPrivileges = true; ProtectSystem = "strict"; ProtectHome = true; PrivateTmp = true; ReadWritePaths = [ "/run/tiaris-nest-pxe" ]; CapabilityBoundingSet = [ "CAP_NET_BIND_SERVICE" "CAP_NET_RAW" "CAP_NET_ADMIN" "CAP_SETUID" "CAP_SETGID" "CAP_DAC_READ_SEARCH" "CAP_KILL" ]; AmbientCapabilities = [ "CAP_SETUID" ]; };
    };
    # Computers on a network that blocks public NTP take the time from the
    # Nest (runtime/tiaris-nest-time): the clock timesyncd keeps, answered
    # only while synchronized and only to private addresses.
    systemd.services.tiaris-nest-time = {
      description = "Tiaris Nest time for computers on its network";
      wantedBy = [ "multi-user.target" ]; after = [ "network.target" ];
      serviceConfig = { ExecStart = command "time"; Restart = "always"; RestartSec = "5s"; DynamicUser = true; AmbientCapabilities = [ "CAP_NET_BIND_SERVICE" ]; CapabilityBoundingSet = [ "CAP_NET_BIND_SERVICE" ]; NoNewPrivileges = true; ProtectSystem = "strict"; ProtectHome = true; PrivateTmp = true; PrivateDevices = true; RestrictAddressFamilies = [ "AF_INET" "AF_UNIX" ]; MemoryMax = "64M"; };
    };
    systemd.services.tiaris-nest-network-runtime = (rootService "network-runtime") // { after = [ "tiaris-nest-first-boot.service" "tiaris-nest-network-guard.service" "network-online.target" ]; wants = [ "network-online.target" ]; before = [ "tiaris-nest.service" ]; serviceConfig = { Type = "oneshot"; ExecStart = command "network-runtime"; TimeoutStartSec = "30s"; }; };
    systemd.services.tiaris-nest-assist-turn = (rootService "assist-turn") // {
      environment.TIARIS_NEST_TURN_DB_SCHEMA = "${coturn}/share/turnserver/schema.sql";
      wantedBy = [ "multi-user.target" ];
      requires = [ "tiaris-nest-first-boot.service" ];
      after = [ "tiaris-nest-first-boot.service" "tiaris-nest-network-runtime.service" ];
    };
    systemd.paths.tiaris-nest-assist-turn = {
      wantedBy = [ "multi-user.target" ];
      pathConfig.PathChanged = "/var/lib/tiaris-nest/state/agent/assist-turn.json";
    };
    systemd.timers.tiaris-nest-assist-turn = {
      wantedBy = [ "timers.target" ];
      timerConfig = { OnBootSec = "30s"; OnUnitInactiveSec = "30s"; AccuracySec = "1s"; };
    };
    systemd.services.tiaris-nest-turn = {
      description = "Tiaris Nest LAN TURN relay";
      unitConfig.ConditionPathExists = "/run/tiaris-nest-turn/turnserver.conf";
      serviceConfig = {
        Type = "exec";
        ExecStart = "${coturn}/bin/turnserver -c /run/tiaris-nest-turn/turnserver.conf";
        ExecStopPost = "+${pkgs.coreutils}/bin/rm -f /run/tiaris-nest-turn/status.json";
        User = "tiaris-turn";
        UMask = "0077";
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        PrivateDevices = true;
        CapabilityBoundingSet = "";
        RestrictAddressFamilies = [ "AF_INET" "AF_UNIX" "AF_NETLINK" ];
        ReadWritePaths = [ "/var/lib/tiaris-nest-turn" "/run/tiaris-nest-turn/turnserver.pid" ];
        LimitCORE = 0;
        MemoryMax = "256M";
        CPUQuota = "50%";
        Restart = "on-failure";
        RestartSec = "2s";
      };
    };
    systemd.timers.tiaris-nest-network-runtime = { wantedBy = [ "timers.target" ]; timerConfig = { OnBootSec = "1min"; OnUnitActiveSec = "1min"; }; };
    # Updates are prepared while the Nest serves computers: verification and
    # import yield CPU and disk to them (generation_update.prepare). The first
    # look comes soon after a start, once the commit of a new generation is
    # done and the daemon has reported: an update that waited for a restart
    # goes on then, not a minute later.
    systemd.services.tiaris-nest-appliance-update = (rootService "appliance-update") // { after = [ "tiaris-nest.service" "tiaris-nest-generation-commit.service" ]; serviceConfig = { Type = "oneshot"; ExecStart = command "appliance-update"; TimeoutStartSec = "4h"; Nice = 10; IOSchedulingClass = "best-effort"; IOSchedulingPriority = 7; }; };
    systemd.timers.tiaris-nest-appliance-update = { wantedBy = [ "timers.target" ]; timerConfig = { OnBootSec = "15s"; OnUnitInactiveSec = "30s"; RandomizedDelaySec = "5s"; }; };
    systemd.services.tiaris-nest-generation-commit = (rootService "generation-commit") // {
      wantedBy = [ "multi-user.target" ]; after = [ "tiaris-nest.service" "nginx.service" "tftpd-hpa.service" ]; wants = [ "tiaris-nest.service" ];
      unitConfig = { ConditionPathExists = "/var/lib/tiaris-nest/control/pending-system-generation.json"; FailureAction = "reboot"; JobTimeoutSec = "5min"; JobTimeoutAction = "reboot"; };
      serviceConfig = { Type = "oneshot"; ExecStart = command "generation-commit"; TimeoutStartSec = "5min"; };
    };
    systemd.services.tiaris-nest-gc = (rootService "gc");
    systemd.services.tiaris-nest-disk-health = (rootService "disk-health") // {
      path = [ pkgs.coreutils pkgs.util-linux pkgs.smartmontools pkgs.nvme-cli pkgs.python3 runtime ];
      after = [ "tiaris-nest-first-boot.service" ];
      serviceConfig = {
        Type = "oneshot";
        ExecStart = command "disk-health";
        TimeoutStartSec = "30s";
        UMask = "0027";
        RuntimeDirectory = "tiaris-nest-disk-health";
        RuntimeDirectoryMode = "0750";
        RuntimeDirectoryPreserve = "yes";
      };
    };
    systemd.timers.tiaris-nest-disk-health = {
      wantedBy = [ "timers.target" ];
      timerConfig = { OnBootSec = "2min"; OnUnitActiveSec = "1h"; RandomizedDelaySec = "30s"; };
    };
    systemd.services.tiaris-nest-network-reconfigure = (rootService "network-reconfigure") // {
      path = baseUnit.path ++ [ pkgs.iproute2 pkgs.nftables ];
      wantedBy = [ "multi-user.target" ];
      requires = [ "tiaris-nest-first-boot.service" ];
      after = [ "tiaris-nest-first-boot.service" "tiaris-nest-network-guard.service" "tiaris-nest-generation-commit.service" ];
      unitConfig.ConditionPathExists = "/var/lib/tiaris-nest/state/agent/network-reconfigure.json";
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${bootstrapPackage}/bin/tiaris-nest-bootstrap apply-network-reconfigure";
        TimeoutStartSec = "300s";
        UMask = "0077";
      };
    };
    systemd.paths.tiaris-nest-network-reconfigure = {
      wantedBy = [ "multi-user.target" ];
      pathConfig.PathChanged = "/var/lib/tiaris-nest/state/agent/network-reconfigure.json";
    };
    systemd.services.tiaris-nest-self-cache-trust = (rootService "self-cache-trust") // {
      wantedBy = [ "multi-user.target" ]; after = [ "tiaris-nest-first-boot.service" "tiaris-nest.service" ];
    };
    systemd.paths.tiaris-nest-self-cache-trust = {
      wantedBy = [ "multi-user.target" ];
      pathConfig.PathChanged = [ "/var/lib/tiaris-nest/state/agent/cache-public.pem" "/var/lib/tiaris-nest/state/cache-public.pem" "/var/lib/tiaris-nest/state/agent/software-cache.netrc" ];
    };
    systemd.timers.tiaris-nest-gc = { wantedBy = [ "timers.target" ]; timerConfig = { OnCalendar = "daily"; Persistent = true; }; };
    # Mask both login paths. A dedicated unit avoids getty@.service.d's
    # template ExecStart override replacing our console command with agetty.
    systemd.services."autovt@tty1".enable = false;
    systemd.services."getty@tty1".enable = false;
    # Native Canopy appliance screen; it falls back to its own text feed on
    # tty1 when no DRM output is usable. Status comes from the daemon.
    systemd.services.tiaris-nest-console = {
      description = "Tiaris Nest console";
      wantedBy = [ "getty.target" ]; conflicts = [ "rescue.service" ]; before = [ "getty.target" "rescue.service" ];
      after = [ "systemd-logind.service" "systemd-user-sessions.service" ];
      environment = {
        TIARIS_NEST_CONSOLE_STATUS = "/run/tiaris-nest/console-status.json";
        FONTCONFIG_FILE = "${pkgs.fontconfig.out}/etc/fonts/fonts.conf";
        XDG_RUNTIME_DIR = "/run/tiaris-nest-console";
        HOME = "/root";
      };
      serviceConfig = { Type = "idle"; ExecStart = "${a.installerKiosk}/bin/tiaris-installer-kiosk --appliance"; Restart = "always"; RestartSec = "2s"; StandardInput = "tty"; StandardOutput = "tty"; StandardError = "journal"; TTYPath = "/dev/tty1"; TTYReset = true; TTYVHangup = true; TTYVTDisallocate = true; UtmpIdentifier = "tty1"; UtmpMode = "user"; PAMName = "login"; RuntimeDirectory = "tiaris-nest-console"; RuntimeDirectoryMode = "0700"; };
    };
  };
}
