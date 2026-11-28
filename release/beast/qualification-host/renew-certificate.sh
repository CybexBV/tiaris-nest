#!/usr/bin/env bash
# Renews the qualification fixture's manage.tiaris.com certificate (Certbot lineage
# tiaris-nest-qualification) over IPv4. The lineage's renew hook installs it.
set -euo pipefail
/usr/bin/python3 /opt/tiaris-nest-qualification/certbot-ipv4.py renew \
  --cert-name tiaris-nest-qualification --quiet
