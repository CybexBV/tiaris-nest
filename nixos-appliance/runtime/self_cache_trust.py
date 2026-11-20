"""Trust this Nest's own cache signing key for its self-substituter.

The Nest daemon (user tiaris-nest) generates its cache key pair and signs
every closure it exports to /var/cache/tiaris-nest/www/cache. Nix's daemon
lists that export first, so a rebuild after garbage collection takes paths
the Nest already holds from its own disk instead of the internet. Only this
root unit writes the nix.conf include, and only one validated
`extra-trusted-public-keys` line: the service user can change which key is
trusted, never any other Nix option.

The same include names the Tiaris software cache as a substituter, and only
while Manage sends this Nest access to it (the daemon then keeps
software-cache.netrc). Where the cache is off, Nix never asks that host. The
line is fixed: the service user decides whether it is there, not what it says.
"""
import base64
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile

from appliance_state import UID, read, sync_dir

# The appliance configuration pins the key to the agent state directory; the
# Ubuntu-to-NixOS bridge kept it one level up (src/config.rs).
PUBLIC_KEYS = (
    Path('/var/lib/tiaris-nest/state/agent/cache-public.pem'),
    Path('/var/lib/tiaris-nest/state/cache-public.pem'),
)
INCLUDE = Path('/etc/tiaris-nest/nix-self-cache.conf')
KEY = re.compile(r'tiaris-nest-cache:[A-Za-z0-9+/]{43}=')
# What src/software_cache.rs writes for the one cache whose key module.nix trusts.
SOFTWARE_CACHE_NETRC = Path('/var/lib/tiaris-nest/state/agent/software-cache.netrc')
SOFTWARE_CACHE_ACCESS = re.compile(r'machine cache\.tiaris\.com login nest password [A-Za-z0-9._-]{1,512}\n')
SOFTWARE_CACHE_LINE = 'extra-substituters = https://cache.tiaris.com\n'


def public_key(paths=PUBLIC_KEYS, owner=UID):
    """The Nest's own cache public key, or None before it exists."""
    for path in paths:
        try:
            body = read(path, maximum=512, owner=owner)
        except FileNotFoundError:
            continue
        text = body.decode('ascii').strip()
        if not KEY.fullmatch(text) or len(base64.b64decode(text.split(':', 1)[1], validate=True)) != 32:
            raise ValueError('invalid Nest cache public key: ' + str(path))
        return text
    return None


def software_cache_on(netrc=SOFTWARE_CACHE_NETRC, owner=UID):
    """Whether Manage gave this Nest access to the Tiaris software cache."""
    try:
        return SOFTWARE_CACHE_ACCESS.fullmatch(read(netrc, maximum=1024, owner=owner).decode('ascii')) is not None
    except (OSError, ValueError, UnicodeDecodeError):
        return False


def render(key, software_cache=False):
    return ('' if key is None else 'extra-trusted-public-keys = ' + key + '\n') + (SOFTWARE_CACHE_LINE if software_cache else '')


def apply(include=INCLUDE, paths=PUBLIC_KEYS, owner=UID, restart=None, netrc=SOFTWARE_CACHE_NETRC):
    """Write the include; restart the Nix daemon when it changed. Any invalid
    key leaves no trust at all: the self-substituter is then simply unused."""
    software_cache = software_cache_on(netrc, owner)
    try:
        content = render(public_key(paths, owner), software_cache)
        valid = True
    except (OSError, ValueError, UnicodeDecodeError):
        content, valid = render(None, software_cache), False
    try:
        info = os.lstat(include)
        current = include.read_text() if stat.S_ISREG(info.st_mode) else None
    except FileNotFoundError:
        current = None
    if current != content:
        fd, name = tempfile.mkstemp(dir=include.parent, prefix='.' + include.name + '.')
        try:
            with os.fdopen(fd, 'w') as stream:
                os.fchmod(stream.fileno(), 0o644)
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(name, include)
            sync_dir(include.parent)
        finally:
            Path(name).unlink(missing_ok=True)
        # Running builds keep their connection; new ones read the new trust.
        (restart or (lambda: subprocess.run(['systemctl', 'try-restart', 'nix-daemon.service'], check=True, timeout=60)))()
    if not valid:
        raise ValueError('Nest cache public key is invalid; its self-substituter stays untrusted')
    return current != content
