# The real module and runtime, with the enrollment and boot identity supplied
# by a local fixture. This test never connects to Manage or an outside network.
{ smoke ? false
, nixpkgs ? let pin = import ../../release/nixpkgs.nix;
            in builtins.fetchTarball { inherit (pin) url sha256; }
}:
import (nixpkgs + "/nixos/tests/make-test-python.nix") ({ pkgs, ... }: {
  name = "tiaris-nest-assist-turn${if smoke then "-smoke" else ""}";
  nodes = {
    appliance = { lib, ... }:
      let
        bootstrap = pkgs.writeShellScript "turn-fixture-network-bootstrap" ''
          address=$(${pkgs.iproute2}/bin/ip -j -4 addr show dev eth1 |
            ${pkgs.jq}/bin/jq -r 'first(.[].addr_info[] | select(.dynamic == true) | .local) // empty')
          if [[ -z "$address" ]] || grep -Fxq "public_base_url = \"http://$address\"" /etc/tiaris-nest/config.toml; then
            printf 'unchanged\n'
            exit
          fi
          config=$(mktemp /etc/tiaris-nest/.turn-fixture-config.XXXXXX)
          printf '[server]\npublic_base_url = "http://%s"\n' "$address" > "$config"
          chmod 0640 "$config"
          mv -- "$config" /etc/tiaris-nest/config.toml
          printf 'changed\n'
        '';
        package = pkgs.runCommand "turn-fixture-nest" { version = "0.0.0"; } ''
          mkdir -p $out/bin $out/share/tiaris-nest/assets
          ln -s ${pkgs.coreutils}/bin/true $out/bin/tiaris-nest
          ln -s ${bootstrap} $out/bin/tiaris-nest-bootstrap
          touch $out/share/tiaris-nest/assets/pxe-menu.png
        '';
      in {
        imports = [ ../module.nix ];
        services.tiaris-nest = {
          enable = true;
          appliance = {
            inherit package;
            sourceRevision = builtins.concatStringsSep "" (lib.replicate 40 "0");
            manageSourceRevision = builtins.concatStringsSep "" (lib.replicate 40 "1");
            nixpkgsRevision = (import ../../release/nixpkgs.nix).revision;
            manageOrigin = "https://example.invalid";
            releasePublicKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
            provisioningPublicKeys = [ ];
            sourceArchive = pkgs.emptyDirectory;
            sourceArchiveFile = pkgs.emptyDirectory;
            migrations = pkgs.writeTextDir "sqlite-migrations.json" "{}";
            installerKiosk = package;
          };
        };
        system.stateVersion = "26.05";
        virtualisation = { memorySize = 1024; vlans = [ 1 ]; };
        virtualisation.qemu.options = [ "-no-user-config" ];
        services.timesyncd.enable = lib.mkForce false;
        networking.interfaces.eth1.ipv4.addresses = lib.mkForce [
          { address = "100.64.50.10"; prefixLength = 24; }
          { address = "100.64.50.12"; prefixLength = 24; }
          { address = "198.51.100.10"; prefixLength = 24; }
        ];
        networking.interfaces.eth1.ipv6.addresses = lib.mkForce [
          { address = "fd42:50::10"; prefixLength = 64; }
        ];
        systemd.services.tiaris-nest-network-render.serviceConfig.ExecStart = lib.mkForce "${pkgs.coreutils}/bin/true";
        systemd.services.tiaris-nest-network-guard.serviceConfig.ExecStart = lib.mkForce "${pkgs.coreutils}/bin/true";
        systemd.services.tiaris-nest-first-boot = {
          wants = lib.mkForce [ ];
          requires = lib.mkForce [ ];
          serviceConfig.ExecStart = lib.mkForce "${pkgs.coreutils}/bin/true";
        };
        systemd.services.tiaris-nest.serviceConfig = {
          Type = lib.mkForce "simple";
          WatchdogSec = lib.mkForce "0";
          ExecStart = lib.mkForce "${pkgs.coreutils}/bin/sleep infinity";
        };
        systemd.services.tiaris-nest-console.wantedBy = lib.mkForce [ ];
        system.activationScripts.turn-test = {
          deps = [ "users" ];
          text = ''
            install -d -m0755 /etc/tiaris-nest
            install -d -m0750 -o root -g tiaris-nest /var/lib/tiaris-nest/state
            install -d -m0700 -o tiaris-nest -g tiaris-nest /var/lib/tiaris-nest/state/{agent,inbox}
            install -d -m0755 /var/cache/tiaris-nest/tftp
            install -d -m0750 /var/lib/tiaris-nest/control
            install -m0640 /dev/null /var/lib/tiaris-nest/control/management-cidrs.txt
            printf '[server]\npublic_base_url = "http://100.64.50.10"\n' > /etc/tiaris-nest/config.toml
            chmod 0640 /etc/tiaris-nest/config.toml
          '';
        };
        environment.systemPackages = [ pkgs.coturn ];
        environment.etc."assist-turn-fixture.py".source = ./assist-turn-fixture.py;
      };
    peer = { lib, ... }: {
      system.stateVersion = "26.05";
      virtualisation = { memorySize = 768; vlans = [ 1 ]; };
      virtualisation.qemu.options = [ "-no-user-config" ];
      networking.firewall.enable = false;
      networking.interfaces.eth1.ipv4.addresses = lib.mkForce [
        { address = "100.64.50.20"; prefixLength = 24; }
        { address = "198.51.100.20"; prefixLength = 24; }
      ];
      networking.interfaces.eth1.ipv6.addresses = lib.mkForce [
        { address = "fd42:50::20"; prefixLength = 64; }
      ];
      environment.systemPackages = [ pkgs.coturn pkgs.dnsmasq (pkgs.python3.withPackages (ps: [ ps.aioice ])) ];
      environment.etc."assist-turn-fixture.py".source = ./assist-turn-fixture.py;
    };
  };
  testScript = ''
    import time

    smoke = ${if smoke then "True" else "False"}
    fixture = "python3 /etc/assist-turn-fixture.py"
    status = "/run/tiaris-nest-turn/status.json"
    unit = "tiaris-nest-turn.service"

    def assert_address(address):
        appliance.wait_until_succeeds(f"jq -e '.state == \"running\" and .listen_ipv4 == \"{address}\"' {status}", timeout=25)
        listeners = appliance.succeed("ss -H -luntp | grep -F turnserver").splitlines()
        assert listeners and all(
            line.startswith("udp ") and f" {address}:3478 " in line
            for line in listeners
        ), listeners

    start_all()
    appliance.wait_for_unit("multi-user.target")
    peer.wait_for_unit("multi-user.target")
    peer.wait_until_succeeds("ping -c1 -W1 100.64.50.12", timeout=25)
    appliance.wait_until_succeeds(f"jq -e '.state == \"stopped\"' {status}", timeout=25)
    appliance.fail(f"systemctl is-active {unit}")
    appliance.succeed("systemd-run --unit=turn-fixture $(command -v python3) /etc/assist-turn-fixture.py config-server")
    appliance.wait_for_open_port(8085, addr="100.64.50.12")
    peer.succeed(f"{fixture} keygen")
    peer.succeed("systemd-run --unit=turn-peer $(command -v turnutils_peer) -L 100.64.50.20 -p 5000")
    peer.succeed("systemd-run --unit=turn-low-peer $(command -v turnutils_peer) -L 100.64.50.20 -p 900")
    peer.succeed("systemd-run --unit=turn-public-peer $(command -v turnutils_peer) -L 198.51.100.20 -p 5000")
    appliance.succeed("systemd-run --unit=turn-local-peer $(command -v turnutils_peer) -L 100.64.50.12 -p 5000")
    peer.wait_until_succeeds("ss -H -4lun | grep -F '198.51.100.20:5000'", timeout=15)
    peer.succeed(f"{fixture} provision initial")
    assert_address("100.64.50.10")
    appliance.succeed("grep -Fx 'max-bps=500000' /run/tiaris-nest-turn/turnserver.conf")
    appliance.succeed("grep -Fx 'bps-capacity=5000000' /run/tiaris-nest-turn/turnserver.conf")
    peer.succeed(f"{fixture} positive 100.64.50.10 0")
    appliance.succeed("test $(stat -c %a /var/lib/tiaris-nest/state/agent/assist-turn.json) = 600")
    appliance.succeed("test $(stat -c %U:%G:%a /run/tiaris-nest-turn/turnserver.conf) = root:tiaris-turn:640")
    appliance.fail("runuser -u nobody -- test -r /var/lib/tiaris-nest-turn/turndb")

    with subtest("abandoned allocation expires and libnice-style Refresh keeps a live relay"):
        started = time.monotonic()
        peer.succeed("systemd-run --unit=turn-lifetimes --property=RuntimeMaxSec=145s $(command -v python3) /etc/assist-turn-fixture.py lifetimes")
        peer.wait_until_succeeds("test -s /run/turn-abandoned-port", timeout=10)
        port = int(peer.succeed("cat /run/turn-abandoned-port").strip())
        assert 61000 <= port <= 61040
        sockets = f"ss -H -4lunp 'sport = :{port}'"
        appliance.succeed(f"{sockets} | grep -F turnserver")
        appliance.wait_until_succeeds(
            f'rows=$({sockets}) && test -z "$rows"',
            timeout=max(1, 130 - round(time.monotonic() - started)),
        )
        print(f"Abandoned TURN relay closed within {time.monotonic() - started:.1f} seconds")
        peer.wait_until_succeeds("test -f /run/turn-lifetimes-verified", timeout=15)

    if not smoke:
        appliance.succeed("systemctl stop tiaris-nest-assist-turn.timer")
        with subtest("STUN and relay boundaries"):
            appliance.wait_until_succeeds("ss -H -lun | grep -F '100.64.50.12:5000'", timeout=15)
            peer.succeed("ss -H -lun | grep -F '100.64.50.20:900'")
            peer.succeed(f"{fixture} boundary")
            appliance.succeed("nft list chain inet tiaris_nest_turn input | grep -E 'saddr != @private4 counter packets ([2-9]|[1-9][0-9]+) '")
            appliance.succeed("nft list chain inet tiaris_nest_turn output | grep -E 'daddr != @private4 counter packets [1-9][0-9]* '")
            appliance.succeed("nft list chain inet tiaris_nest_turn output | grep -E 'fib daddr type .*counter packets [1-9][0-9]* '")
            appliance.succeed("nft list chain inet tiaris_nest_turn output | grep -E 'udp dport 0-1023 counter packets [1-9][0-9]* '")
        with subtest("overlap, live allocation and retirement"):
            pid = appliance.succeed(f"systemctl show -p MainPID --value {unit}").strip()
            peer.succeed(f"{fixture} rotation")
            appliance.succeed(f"test $(systemctl show -p MainPID --value {unit}) = {pid}")
            appliance.succeed(f"jq -e '.secret_ids == [\"20261123-00000002\"]' {status}")
        with subtest("re-render after DHCP assigns a new address"):
            appliance.succeed("systemctl stop tiaris-nest-network-runtime.timer")
            peer.succeed("systemd-run --unit=turn-test-dhcp $(command -v dnsmasq) --no-daemon --port=0 --interface=eth1 --bind-interfaces --dhcp-authoritative --log-dhcp --dhcp-leasefile=/run/turn-test-dhcp.leases --dhcp-range=100.64.50.11,100.64.50.11,255.255.255.0,5m --dhcp-option=option:router --dhcp-option=option:dns-server")
            peer.wait_until_succeeds("ss -H -4lunp 'sport = :67' | grep -F dnsmasq", timeout=10)
            appliance.succeed("install -d /run/systemd/network/40-eth1.network.d; printf '[Network]\nDHCP=ipv4\n' > /run/systemd/network/40-eth1.network.d/turn-dhcp.conf; networkctl reload; networkctl reconfigure eth1")
            appliance.wait_until_succeeds("ip -4 addr show dev eth1 dynamic | grep -F '100.64.50.11/24'", timeout=30)
            appliance.succeed("systemctl start tiaris-nest-network-runtime.service")
            assert_address("100.64.50.11")
            peer.succeed(f"{fixture} positive 100.64.50.11 1")

    peer.succeed(f"{fixture} provision off")
    appliance.wait_until_succeeds(f"jq -e '.state == \"stopped\"' {status}", timeout=25)
    appliance.fail(f"systemctl is-active {unit}")
    appliance.fail("nft list table inet tiaris_nest_turn")
    appliance.succeed("nft list table inet tiaris_nest >/dev/null")
    appliance.succeed("jq -e '.enabled == false and (has(\"secrets\") | not)' /var/lib/tiaris-nest/state/agent/assist-turn.json")
    appliance.succeed("test ! -e /var/lib/tiaris-nest-turn && test ! -e /run/tiaris-nest-turn/turnserver.conf")
  '';
}) { system = "x86_64-linux"; }
