#!/usr/bin/env bash
# Certbot renew hook of lineage tiaris-nest-qualification: installs the manage.tiaris.com
# fixture certificate where the fixture template names it. The key stays root-private.
set -euo pipefail
lineage="${RENEWED_LINEAGE:-/etc/letsencrypt/live/tiaris-nest-qualification}"
case "$lineage" in */tiaris-nest-qualification) ;; *) exit 0 ;; esac
dir=/etc/cybex/nixos-production-qualification
install -o root -g root -m 0600 "$lineage/fullchain.pem" "$dir/.tls-tiaris.crt.new"
install -o root -g root -m 0600 "$lineage/privkey.pem" "$dir/.tls-tiaris.key.new"
mv -f "$dir/.tls-tiaris.crt.new" "$dir/tls-tiaris.crt"
mv -f "$dir/.tls-tiaris.key.new" "$dir/tls-tiaris.key"
