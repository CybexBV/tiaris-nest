# Qualification host on The Beast

The release runner (`cybex-james-runner.service`, user `john`) qualifies Nest releases against a
private Manage fixture for `https://manage.tiaris.com` (`../../../nixos-appliance/qualification/PRODUCTION.md`).
That fixture needs a publicly trusted certificate for `manage.tiaris.com`; this folder keeps it current.

- Certbot lineage `tiaris-nest-qualification` (DNS-01 through Cloudflare; the DNS credential stays root-only).
- `tiaris-nest-qualification-certificate.timer` runs `renew-certificate.sh` twice a day. It calls Certbot through
  `certbot-ipv4.py`, because the credential's egress policy allows IPv4 only.
- The lineage's renew hook, `install-fixture-certificate.sh`, copies the new certificate and key to
  `/etc/cybex/nixos-production-qualification/tls-tiaris.{crt,key}`, the paths the fixture template names.
- `runner-release-tools.conf` is the runner's user drop-in (`release-tools.conf`): the runner's PATH, and a check
  of the publication tools before it accepts jobs. It reads Tiaris's `deploy/manage/release_checks.py` from The
  Beast's release checkout.

Install or update from a clean checkout of `main` on The Beast:

```bash
sudo release/beast/qualification-host/install.sh
```

It installs to `/opt/tiaris-nest-qualification` and `/etc/systemd/system`, sets the renew hook and enables the
timer. It also removes the setup this replaced on 28 November 2026: `/opt/cybex-james-qualification` (a hand-kept
copy of Tiaris's former `deploy/qualification`), its timer and network units, the unused `jamesqual0` bridge
with its Docker rules, and the `manage.cybex.net` certificate that no fixture served any more.

Check it with `systemctl list-timers tiaris-nest-qualification-certificate.timer` and
`sudo openssl x509 -in /etc/cybex/nixos-production-qualification/tls-tiaris.crt -noout -enddate`.
