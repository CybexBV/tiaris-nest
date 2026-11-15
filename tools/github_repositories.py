#!/usr/bin/env python3
"""One GitHub repository may have more than one name.

The owner renames `CybexHQ/james` to `CybexHQ/tiaris-nest` and
`CybexHQ/development` to `CybexHQ/tiaris`. GitHub redirects the old names, but
after a rename its API and `GITHUB_REPOSITORY` report the new one, while
signed, immutable releases keep the URLs they were published under. Code that
compares repository names or GitHub URLs must therefore treat every name of a
repository as the same repository, before and after each rename, in any order.

The names live in `release/github-repositories.json` (also read by
`release/workstation-netboot.nix`). Workflow shell uses the command line:

    github_repositories.py same REPOSITORY|nest|tiaris REPOSITORY   # exit 0 when equal
    github_repositories.py url REPOSITORY URL   # URL, its repository spelled REPOSITORY
"""
from __future__ import annotations

import json
from pathlib import Path
import sys

_NAMES = json.loads((Path(__file__).resolve().parents[1] / 'release/github-repositories.json').read_text())

NEST = _NAMES['nest']['current']
NEST_NAMES = tuple(_NAMES['nest']['names'])
TIARIS = _NAMES['tiaris']['current']
TIARIS_NAMES = tuple(_NAMES['tiaris']['names'])
_GROUPS = (NEST_NAMES, TIARIS_NAMES)
GITHUB = 'https://github.com/'


def names(repository: object) -> tuple[str, ...]:
    """Every name of `repository`; an unknown repository has only its own."""
    if not isinstance(repository, str):
        return ()
    return next((group for group in _GROUPS if repository in group), (repository,))


def same_repository(left: object, right: object) -> bool:
    return isinstance(right, str) and right in names(left)


def _split(url: object) -> tuple[str, str] | None:
    """`https://github.com/OWNER/NAME/rest` → (`OWNER/NAME`, `/rest`)."""
    if not isinstance(url, str) or not url.startswith(GITHUB):
        return None
    owner, _, rest = url[len(GITHUB):].partition('/')
    name, slash, tail = rest.partition('/')
    if not owner or not name:
        return None
    return f'{owner}/{name}', slash + tail


def same_url(left: object, right: object) -> bool:
    """Equal text, or the same path under two names of one GitHub repository.

    Not a validator: two equal non-GitHub URLs are also "the same". Callers
    compare against a URL they built or trust."""
    if isinstance(left, str) and left == right:
        return True
    a, b = _split(left), _split(right)
    return a is not None and b is not None and a[1] == b[1] and same_repository(a[0], b[0])


def spelled(url: str, repository: str) -> str:
    """`url` with its GitHub repository spelled `repository` when they are the same
    repository; any other URL unchanged."""
    parts = _split(url)
    if parts is None or not same_repository(parts[0], repository):
        return url
    return GITHUB + repository + parts[1]


def git_remotes(repository: str) -> frozenset[str]:
    """The HTTPS and SSH `origin` URLs of every name of `repository`."""
    return frozenset(remote for name in names(repository)
                     for remote in (GITHUB + name, GITHUB + name + '.git', f'git@github.com:{name}.git'))


def main(arguments: list[str]) -> int:
    roles = {'nest': NEST, 'tiaris': TIARIS}
    if len(arguments) == 3 and arguments[0] == 'same':
        return 0 if same_repository(roles.get(arguments[1], arguments[1]), arguments[2]) else 1
    if len(arguments) == 3 and arguments[0] == 'url':
        print(spelled(arguments[2], arguments[1]))
        return 0
    print('\n'.join(__doc__.strip().splitlines()[-2:]), file=sys.stderr)
    return 2


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
