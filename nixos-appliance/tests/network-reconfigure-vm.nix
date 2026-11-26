{ nixpkgs, common }:
let
  pkgs = import nixpkgs { system = "x86_64-linux"; };
  pki = pkgs.runCommand "tiaris-nest-reconfigure-vm-pki" {
    nativeBuildInputs = [ pkgs.openssl pkgs.coreutils ];
  } ''
    mkdir -p $out
    openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
      -keyout $out/ca.key -out $out/ca.crt \
      -subj "/CN=Tiaris VM Test CA" \
      -addext "basicConstraints=critical,CA:TRUE" \
      -addext "keyUsage=critical,keyCertSign,cRLSign"
    openssl req -newkey rsa:2048 -nodes \
      -keyout $out/server.key -out $out/server.csr \
      -subj "/CN=manage.tiaris.com"
    cat > $out/ext.cnf <<'EOF'
    basicConstraints=CA:FALSE
    keyUsage=digitalSignature,keyEncipherment
    extendedKeyUsage=serverAuth
    subjectAltName=DNS:manage.tiaris.com
    EOF
    openssl x509 -req -in $out/server.csr -CA $out/ca.crt -CAkey $out/ca.key \
      -CAcreateserial -out $out/server.crt -days 30 -extfile $out/ext.cnf
    openssl genpkey -algorithm ED25519 -out $out/prov.pem
    openssl pkey -in $out/prov.pem -pubout -outform DER | tail -c 32 | base64 -w0 > $out/prov.pub.b64
  '';
  initialNetplan = pkgs.writeText "reconfigure-initial-netplan.json" (builtins.toJSON {
    network = {
      version = 2;
      renderer = "networkd";
      ethernets.tiaris-nest = {
        match.macaddress = "52:54:00:12:01:01";
        set-name = "eth1";
        dhcp4 = true;
        dhcp6 = false;
      };
    };
  });
  configToml = pkgs.writeText "reconfigure-config.toml" ''
    [server]
    listen_addr = "127.0.0.1:8080"
    public_base_url = "http://10.0.0.60"
    [paths]
    data_dir = "/var/lib/tiaris-nest/state/agent"
    database_path = "/var/lib/tiaris-nest/state/agent/tiaris-nest.sqlite"
    boot_assets_dir = "/var/cache/tiaris-nest/www"
    static_dir = "/var/cache/tiaris-nest/www/assets"
    tftp_dir = "/var/cache/tiaris-nest/tftp"
    [auth]
    admin_token = "public-qualification-fixture-only"
    [build]
    work_dir = "/var/cache/tiaris-nest/build"
    output_dir = "/var/cache/tiaris-nest/build-outputs"
    nix_binary = "/usr/bin/nix"
    manage_source_url_template = "tarball+file:///usr/share/tiaris-nest/manage-source/{revision}.tar"
    [cache]
    root_dir = "/var/cache/tiaris-nest/www/cache"
    private_key_path = "/var/lib/tiaris-nest/state/agent/cache-private.pem"
    public_key_path = "/var/lib/tiaris-nest/state/agent/cache-public.pem"
    [update]
    trusted_public_key = "${common.releasePublicKey}"
    [manage]
    enabled = true
    api_url = "https://manage.tiaris.com"
    organization_id = "00000000-0000-4000-8000-000000000001"
    organization_slug = "qualification"
    state_path = "/var/lib/tiaris-nest/state/agent/manage-state.json"
  '';
  mockManageServer = pkgs.writeText "mock-manage-health.py" ''
    import http.server
    import json
    import ssl

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/v1/health":
                body = json.dumps({"status": "ok", "service": "tiaris", "version": "0.1.732"}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                self.send_response(404)
                self.end_headers()
        def log_message(self, fmt, *args):
            pass

    server = http.server.ThreadingHTTPServer(("10.0.0.1", 443), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain("${pki}/server.crt", "${pki}/server.key")
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    server.serve_forever()
  '';
in import (nixpkgs + "/nixos/tests/make-test-python.nix") ({ pkgs, ... }: {
  name = "tiaris-nest-network-reconfigure";
  nodes = {
    machine = { lib, ... }: {
      imports = [ ../module.nix ];
      services.tiaris-nest = { enable = true; appliance = common; };
      system.stateVersion = "26.05";
      virtualisation = { memorySize = 1024; vlans = [ 1 ]; };
      services.timesyncd.enable = lib.mkForce false;
      networking.hosts."10.0.0.1" = [ "manage.tiaris.com" ];
      security.pki.certificateFiles = [ "${pki}/ca.crt" ];
      environment.systemPackages = [ pkgs.openssl pkgs.jq pkgs.python3 ];

      # Preserve real network-render, firewall, network-runtime, and
      # network-reconfigure units while stubbing disk-mount-only first-boot
      # and the long-running daemon.
      systemd.services.tiaris-nest-first-boot = {
        wants = lib.mkForce [ ];
        requires = lib.mkForce [ ];
        unitConfig.RequiresMountsFor = lib.mkForce [ ];
        serviceConfig.ExecStart = lib.mkForce (pkgs.writeShellScript "vm-first-boot" ''
          /usr/lib/tiaris-nest/tiaris-nest-bootstrap materialize-effective-network || rm -f /run/tiaris-nest-network/netplan-approved.json /run/tiaris-nest-network/management-cidrs.txt
        '');
      };
      systemd.services.tiaris-nest-network-guard.serviceConfig.ExecStart = lib.mkForce "${pkgs.coreutils}/bin/true";
      systemd.services.tiaris-nest.serviceConfig = {
        Type = lib.mkForce "simple";
        WatchdogSec = lib.mkForce "0";
        ExecStart = lib.mkForce "${pkgs.coreutils}/bin/sleep infinity";
      };
      systemd.services.tiaris-nest-console.wantedBy = lib.mkForce [ ];

      system.activationScripts.reconfigure-fixture = {
        deps = [ "users" "tiaris-nest-public-assets" ];
        text = ''
          # Add the VM fixture's provisioning signing key alongside the release key
          # so incoming supersessions verify against /usr/share/tiaris-nest/provisioning-public-keys.
          if ! grep -Fxq "$(cat ${pki}/prov.pub.b64)" /usr/share/tiaris-nest/provisioning-public-keys; then
            { cat /usr/share/tiaris-nest/provisioning-public-keys; cat ${pki}/prov.pub.b64; echo; } > /usr/share/tiaris-nest/.provisioning-public-keys.tmp
            chmod 0444 /usr/share/tiaris-nest/.provisioning-public-keys.tmp
            mv /usr/share/tiaris-nest/.provisioning-public-keys.tmp /usr/share/tiaris-nest/provisioning-public-keys
          fi
          install -d -m0750 -o root -g tiaris-nest /var/lib/tiaris-nest/control /var/lib/tiaris-nest/state /var/lib/tiaris-nest/status
          install -d -m0700 -o tiaris-nest -g tiaris-nest /var/lib/tiaris-nest/state/agent /var/lib/tiaris-nest/state/inbox
          install -d -m0755 -o tiaris-nest -g tiaris-nest /var/cache/tiaris-nest/www /var/cache/tiaris-nest/www/assets /var/cache/tiaris-nest/www/cache
          install -d -m0755 -o root -g root /var/cache/tiaris-nest/tftp /etc/tiaris-nest
          if [ ! -f /var/lib/tiaris-nest/control/provisioning-state.json ]; then
            install -m0600 -o root -g root ${initialNetplan} /var/lib/tiaris-nest/control/netplan-approved.json
            install -m0600 -o root -g root ${initialNetplan} /var/lib/tiaris-nest/control/netplan-dhcp-fallback.json
            printf '10.0.0.0/24\n' > /var/lib/tiaris-nest/control/management-cidrs.txt
            chown root:tiaris-nest /var/lib/tiaris-nest/control/management-cidrs.txt
            chmod 0640 /var/lib/tiaris-nest/control/management-cidrs.txt
            install -m0640 -o root -g tiaris-nest ${configToml} /etc/tiaris-nest/config.toml
            ${pkgs.python3}/bin/python3 - <<'PY'
import json
from pathlib import Path
pub_b64 = Path("${pki}/prov.pub.b64").read_text().strip()
plan = {
    "schema": "tiaris.nest.install-plan.v3",
    "id": "11111111-1111-4111-8111-111111111111",
    "organization_id": "00000000-0000-4000-8000-000000000001",
    "organization_slug": "qualification",
    "plan_revision": 1,
    "session_id": "22222222-2222-4222-8222-222222222222",
    "session_revision": 1,
    "inventory_sha256": "0" * 64,
    "hardware_digest": "1" * 64,
    "provisioning_public_key_fingerprint": "2" * 64,
    "reserved_device_id": "nest-vm-01",
    "display_name": "VM Nest 1",
    "target_disk_id": "disk-1",
    "target_disk": {
        "id": "disk-1", "path": "/dev/vda", "model": "VirtIO", "serial": "S1",
        "wwn": "", "size_bytes": 214748364800, "removable": False,
        "mounted": False, "held": False, "eligible": True, "blocker_codes": [],
    },
    "network_interface": {
        "id": "pci-0000:00:03.0", "name": "eth1", "mac": "52:54:00:12:01:01",
        "link_up": True, "addresses": ["10.0.0.60/24"], "gateway": "10.0.0.1",
    },
    "network": {
        "mode": "dhcp", "interface_id": "pci-0000:00:03.0",
        "address_cidr": None, "gateway": None, "dns_servers": [],
    },
    "maintenance_window": {
        "timezone": "UTC", "weekday": 0, "start": "02:00", "duration_minutes": 120,
    },
    "management_cidrs": ["10.0.0.0/24"],
    "ssh_ca_public_keys": [],
    "base_os": "nixos",
    "base_os_version": "26.05",
    "release_version": "0.2.200",
    "at_rest_protection": "none",
    "issued_at": "2026-11-26T00:00:00Z",
    "expires_at": "2026-12-26T00:00:00Z",
    "plan_sha256": "3" * 64,
    "signature": "sig",
}
durable = {
    "schema": "tiaris.nest.provisioning-state.v1",
    "session_id": plan["session_id"],
    "manage_origin": "https://manage.tiaris.com",
    "management_signing_public_key_b64": pub_b64,
    "device_private_key_b64": "priv",
    "device_public_key_b64": "pub",
    "device_public_key_fingerprint": "fp",
    "next_event_sequence": 1,
    "identity_active": True,
    "installation_complete": True,
    "updated_at": "2026-11-26T00:00:00Z",
    "plan": plan,
}
path = Path("/var/lib/tiaris-nest/control/provisioning-state.json")
path.write_text(json.dumps(durable) + "\n")
path.chmod(0o600)
PY
          fi
        '';
      };
    };
    router = { ... }: {
      system.stateVersion = "26.05";
      virtualisation = { memorySize = 512; vlans = [ 1 ]; };
      networking = { useNetworkd = true; useDHCP = false; firewall.enable = false; };
      systemd.network.enable = true;
      systemd.network.networks."10-router" = {
        name = "eth1";
        networkConfig = { Address = "10.0.0.1/24"; DHCPServer = true; };
        dhcpServerConfig = { PoolOffset = 60; PoolSize = 10; };
      };
      systemd.services.mock-manage-health = {
        wantedBy = [ "multi-user.target" ];
        after = [ "systemd-networkd.service" "network-online.target" ];
        wants = [ "network-online.target" ];
        serviceConfig = {
          ExecStart = "${pkgs.python3}/bin/python3 ${mockManageServer}";
          Restart = "always";
          RestartSec = "1s";
        };
      };
    };
  };
  testScript = ''
    import base64
    import datetime
    import json
    import subprocess
    import tempfile

    def deliver_supersession(revision, network, cidrs):
        now = datetime.datetime.now(datetime.timezone.utc)
        doc = {
            "schema": "tiaris.nest.network-supersession.v1",
            "organization_id": "00000000-0000-4000-8000-000000000001",
            "device_id": "nest-vm-01",
            "device_incarnation_id": "33333333-3333-4333-8333-333333333333",
            "provisioning_session_id": "22222222-2222-4222-8222-222222222222",
            "revision": revision,
            "issued_at": (now - datetime.timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "expires_at": (now + datetime.timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "network": network,
            "management_cidrs": cidrs,
        }
        canonical = json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()
        payload = b"TIARIS-NEST-NETWORK-SUPERSESSION-V1\n" + canonical
        with tempfile.NamedTemporaryFile() as msg_file:
            msg_file.write(payload)
            msg_file.flush()
            sig = subprocess.check_output(
                ["${pkgs.openssl}/bin/openssl", "pkeyutl", "-sign", "-rawin", "-inkey", "${pki}/prov.pem", "-in", msg_file.name],
            )
        doc["signature"] = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
        encoded = json.dumps(doc, sort_keys=True, separators=(",", ":"))
        b64 = base64.b64encode(encoded.encode()).decode()
        machine.succeed(
            f"printf '%s' '{b64}' | base64 -d > /var/lib/tiaris-nest/state/agent/.network-reconfigure.tmp && "
            "chown tiaris-nest:tiaris-nest /var/lib/tiaris-nest/state/agent/.network-reconfigure.tmp && "
            "chmod 0600 /var/lib/tiaris-nest/state/agent/.network-reconfigure.tmp && "
            "mv /var/lib/tiaris-nest/state/agent/.network-reconfigure.tmp /var/lib/tiaris-nest/state/agent/network-reconfigure.json"
        )

    start_all()
    router.wait_for_unit("mock-manage-health.service")
    router.wait_for_open_port(443, addr="10.0.0.1")
    machine.wait_for_unit("multi-user.target")
    machine.wait_until_succeeds("ip -4 address show dev eth1 | grep -E '10\\.0\\.0\\.(6[0-9])/24'", timeout=45)
    machine.succeed("curl --fail --silent https://manage.tiaris.com/v1/health | jq -e '.status == \"ok\" and .service == \"tiaris\"'")

    orig_netplan = machine.succeed("cat /var/lib/tiaris-nest/control/netplan-approved.json")
    orig_cidrs = machine.succeed("cat /var/lib/tiaris-nest/control/management-cidrs.txt")

    with subtest("Case 1: valid static reconfiguration commits atomically and converges services"):
        deliver_supersession(
            1,
            {
                "mode": "static",
                "interface_id": "pci-0000:00:03.0",
                "address_cidr": "10.0.0.20/24",
                "gateway": "10.0.0.1",
                "dns_servers": ["10.0.0.1"],
            },
            ["10.0.0.0/24", "10.99.0.0/24"],
        )
        machine.wait_until_succeeds(
            "jq -e '.revision == 1 and .applied_revision == 1 and .status == \"applied\"' /run/tiaris-nest-network/reconfigure-status.json",
            timeout=90,
        )
        machine.succeed("ip -4 address show dev eth1 | grep -F '10.0.0.20/24'")
        machine.succeed("test -f /var/lib/tiaris-nest/control/network-supersession.json")
        machine.succeed("grep -Fx 'public_base_url = \"http://10.0.0.20\"' /etc/tiaris-nest/config.toml")
        machine.succeed("nft list table inet tiaris_nest | grep -F '10.99.0.0/24'")
        machine.succeed("test ! -f /run/tiaris-nest-network/pending-revert.yaml")
        machine.succeed("test ! -f /run/tiaris-nest-network/retry-pending")
        assert machine.succeed("cat /var/lib/tiaris-nest/control/netplan-approved.json") == orig_netplan
        assert machine.succeed("cat /var/lib/tiaris-nest/control/management-cidrs.txt") == orig_cidrs

    with subtest("Case 2: SIGKILL during candidate probe triggers ExecStopPost automatic revert"):
        deliver_supersession(
            2,
            {
                "mode": "static",
                "interface_id": "pci-0000:00:03.0",
                "address_cidr": "198.51.100.20/24",
                "gateway": "198.51.100.1",
                "dns_servers": ["198.51.100.1"],
            },
            ["10.0.0.0/24"],
        )
        machine.wait_until_succeeds(
            "test -f /run/tiaris-nest-network/pending-revert.yaml && ip -4 address show dev eth1 | grep -F '198.51.100.20/24'",
            timeout=45,
        )
        machine.succeed("systemctl kill -s KILL --kill-who=main tiaris-nest-network-reconfigure.service")
        machine.wait_until_succeeds(
            "test ! -f /run/tiaris-nest-network/pending-revert.yaml && ip -4 address show dev eth1 | grep -F '10.0.0.20/24'",
            timeout=60,
        )
        machine.wait_until_succeeds(
            "jq -e '.revision == 2 and .applied_revision == 1 and .status == \"reverted\"' /run/tiaris-nest-network/reconfigure-status.json",
            timeout=30,
        )
        machine.succeed("jq -e '.revision == 2 and .status == \"reverted\"' /var/lib/tiaris-nest/control/network-reconfigure-last.json")
        machine.succeed("ping -c 1 10.0.0.1")

    with subtest("Case 3: unreachable candidate auto-reverts after probe timeout and stays reverted across reboot"):
        deliver_supersession(
            3,
            {
                "mode": "static",
                "interface_id": "pci-0000:00:03.0",
                "address_cidr": "198.51.100.30/24",
                "gateway": "198.51.100.1",
                "dns_servers": ["198.51.100.1"],
            },
            ["10.0.0.0/24"],
        )
        machine.wait_until_succeeds(
            "ip -4 address show dev eth1 | grep -F '198.51.100.30/24'",
            timeout=45,
        )
        machine.wait_until_succeeds(
            "jq -e '.revision == 3 and .applied_revision == 1 and .status == \"reverted\"' /run/tiaris-nest-network/reconfigure-status.json",
            timeout=160,
        )
        machine.succeed("ip -4 address show dev eth1 | grep -F '10.0.0.20/24'")
        machine.succeed("test ! -f /run/tiaris-nest-network/pending-revert.yaml")
        machine.succeed("ping -c 1 10.0.0.1")

        # Reboot and confirm committed rev 1 renders cleanly while reverted rev 3 is never re-applied.
        machine.shutdown()
        machine.start()
        machine.wait_for_unit("multi-user.target")
        machine.wait_until_succeeds("ip -4 address show dev eth1 | grep -F '10.0.0.20/24'", timeout=45)
        machine.wait_until_succeeds(
            "jq -e '.revision == 3 and .applied_revision == 1 and .status == \"reverted\"' /run/tiaris-nest-network/reconfigure-status.json",
            timeout=45,
        )
        machine.succeed("ping -c 1 10.0.0.1")
        machine.succeed("nft list table inet tiaris_nest | grep -F '10.99.0.0/24'")
        assert machine.succeed("cat /var/lib/tiaris-nest/control/netplan-approved.json") == orig_netplan
        assert machine.succeed("cat /var/lib/tiaris-nest/control/management-cidrs.txt") == orig_cidrs

    with subtest("Case 4: static-to-DHCP reconfiguration acquires live DHCP lease and updates config"):
        deliver_supersession(
            4,
            {
                "mode": "dhcp",
                "interface_id": "pci-0000:00:03.0",
                "address_cidr": None,
                "gateway": None,
                "dns_servers": [],
            },
            ["10.0.0.0/24"],
        )
        machine.wait_until_succeeds(
            "jq -e '.revision == 4 and .applied_revision == 4 and .status == \"applied\"' /run/tiaris-nest-network/reconfigure-status.json",
            timeout=120,
        )
        dhcp_ip = machine.succeed(
            "ip -j -4 address show dev eth1 scope global | jq -er 'first(.[].addr_info[] | select(.dynamic == true) | .local)'"
        ).strip()
        assert dhcp_ip.startswith("10.0.0.6"), f"unexpected DHCP IP: {dhcp_ip}"
        machine.succeed(f"grep -Fx 'public_base_url = \"http://{dhcp_ip}\"' /etc/tiaris-nest/config.toml")
        machine.succeed("test ! -f /run/tiaris-nest-network/retry-pending")

    with subtest("Case 5: retry-pending marker triggers the retry timer and clears after convergence"):
        machine.succeed("install -m 0600 /dev/null /run/tiaris-nest-network/retry-pending && printf '1\\n' > /run/tiaris-nest-network/retry-pending")
        machine.wait_until_succeeds("test ! -f /run/tiaris-nest-network/retry-pending", timeout=120)
        machine.succeed(
            "jq -e '.revision == 4 and .applied_revision == 4 and .status == \"applied\"' /run/tiaris-nest-network/reconfigure-status.json"
        )

    with subtest("Case 6: boot convergence preserves active DHCP fallback after static supersession"):
        deliver_supersession(
            5,
            {
                "mode": "static",
                "interface_id": "pci-0000:00:03.0",
                "address_cidr": "10.0.0.25/24",
                "gateway": "10.0.0.1",
                "dns_servers": ["10.0.0.1"],
            },
            ["10.0.0.0/24"],
        )
        machine.wait_until_succeeds(
            "jq -e '.revision == 5 and .applied_revision == 5 and .status == \"applied\"' /run/tiaris-nest-network/reconfigure-status.json",
            timeout=90,
        )
        machine.succeed("ip -4 address show dev eth1 | grep -F '10.0.0.25/24'")
        # Simulate tiaris-nest-network-guard selecting DHCP fallback on boot.
        machine.succeed(
            "approved_sha=$(sha256sum /run/tiaris-nest-network/netplan-approved.json | awk '{print $1}') && "
            "jq -n --arg approved_sha256 \"$approved_sha\" '{schema:\"tiaris.nest.network-fallback.v1\",approved_sha256:$approved_sha256}' > /var/lib/tiaris-nest/control/network-fallback-active && "
            "chmod 0600 /var/lib/tiaris-nest/control/network-fallback-active && "
            "install -m 0600 /var/lib/tiaris-nest/control/netplan-dhcp-fallback.json /etc/netplan/90-tiaris-nest.yaml && "
            "TIARIS_NETWORK_FORCE_RELOAD=1 /usr/lib/tiaris-nest/tiaris-nest-netplan-activate"
        )
        machine.wait_until_succeeds("ip -4 address show dev eth1 | grep -E '10\\.0\\.0\\.(6[0-9])/24'", timeout=45)
        # Replaying tiaris-nest-network-reconfigure at boot must NOT overwrite active DHCP fallback.
        machine.succeed("systemctl start tiaris-nest-network-reconfigure.service")
        machine.succeed("cmp -s /etc/netplan/90-tiaris-nest.yaml /var/lib/tiaris-nest/control/netplan-dhcp-fallback.json")
        machine.succeed("ip -4 address show dev eth1 | grep -E '10\\.0\\.0\\.(6[0-9])/24'")
        machine.succeed("ping -c 1 10.0.0.1")
  '';
}) { system = "x86_64-linux"; }
