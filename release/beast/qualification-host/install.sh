#!/usr/bin/env bash
# Installs the qualification fixture certificate renewal on The Beast from this checkout,
# and removes the setup it replaces. Run as root: sudo release/beast/qualification-host/install.sh
set -euo pipefail
test "$(hostname)" = thebeast
test "$(id -u)" = 0
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
target=/opt/tiaris-nest-qualification
renewal=/etc/letsencrypt/renewal/tiaris-nest-qualification.conf
test -f "$renewal"

install -d -o root -g root -m 0755 "$target"
for file in certbot-ipv4.py renew-certificate.sh install-fixture-certificate.sh; do
  install -o root -g root -m 0755 "$here/$file" "$target/$file"
done
for unit in tiaris-nest-qualification-certificate.service tiaris-nest-qualification-certificate.timer; do
  install -o root -g root -m 0644 "$here/$unit" "/etc/systemd/system/$unit"
done
# The release runner's PATH and publication-tool check (identical on every install).
runner_dropins=/home/john/.config/systemd/user/cybex-james-runner.service.d
if [ -d "$runner_dropins" ]; then
  install -o john -g john -m 0644 "$here/runner-release-tools.conf" "$runner_dropins/release-tools.conf"
fi

hook="renew_hook = $target/install-fixture-certificate.sh"
if grep -q '^renew_hook = ' "$renewal"; then
  sed -i "s|^renew_hook = .*|$hook|" "$renewal"
else
  sed -i "s|^\[renewalparams\]$|&\n$hook|" "$renewal"
fi
grep -qx "$hook" "$renewal"

# The setup this replaces (until 28 November 2026): a hand-kept copy of Tiaris's
# deploy/qualification, its manage.cybex.net certificate and the unused jamesqual0 bridge.
systemctl disable --now cybex-james-qualification-certificate.timer 2>/dev/null || true
systemctl disable --now cybex-james-qualification-network.service 2>/dev/null || true
rm -f /etc/systemd/system/cybex-james-qualification-certificate.timer \
  /etc/systemd/system/cybex-james-qualification-certificate.service \
  /etc/systemd/system/cybex-james-qualification-network.service
while iptables -C DOCKER-USER -i jamesqual0 -s 10.62.57.0/24 -j ACCEPT 2>/dev/null; do
  iptables -D DOCKER-USER -i jamesqual0 -s 10.62.57.0/24 -j ACCEPT
done
while iptables -C DOCKER-USER -o jamesqual0 -d 10.62.57.0/24 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null; do
  iptables -D DOCKER-USER -o jamesqual0 -d 10.62.57.0/24 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
done
if incus network show jamesqual0 >/dev/null 2>&1; then
  incus network delete jamesqual0
fi
if [ -e /etc/letsencrypt/renewal/cybex-james-qualification.conf ]; then
  certbot delete --non-interactive --cert-name cybex-james-qualification
fi
rm -rf /opt/cybex-james-qualification

systemctl daemon-reload
systemctl enable --now tiaris-nest-qualification-certificate.timer
echo "Installed $target and tiaris-nest-qualification-certificate.timer"
