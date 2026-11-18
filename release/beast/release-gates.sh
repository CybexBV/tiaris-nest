#!/usr/bin/env bash
# The production release gates: installer and release contracts, the Rust
# production release gate and the pinned workstation netboot expressions.
#
# The release workflow has one runner, so separate gate jobs could only run one
# after another before the build. Instead the build job starts the gates from a
# clean checkout of the exact tag, builds beside them, and joins them before it
# signs anything: nothing is signed, sealed or published unless every gate
# passed in that same attempt.
#
#   release-gates.sh start DIR   check out HEAD into DIR/source and start every gate
#   release-gates.sh join DIR    wait for every gate, show its log, fail unless all passed
#   release-gates.sh stop DIR    end gates still running and remove DIR
#   release-gates.sh GATE        run one gate in the current checkout:
#                                contracts, rust, nix, bash-syntax or shellcheck
set -Eeuo pipefail

GATES=(contracts rust nix)

appliance_helpers() {
  rg -l '^#!.*(bash|/sh)$' nixos-appliance/runtime | sort
}

gate_bash_syntax() {
  local helper appliance
  mapfile -t appliance < <(appliance_helpers)
  for helper in release/beast/*.sh nixos-appliance/*.sh "${appliance[@]}"; do
    bash -n "$helper"
  done
}

gate_shellcheck() {
  local appliance
  mapfile -t appliance < <(appliance_helpers)
  shellcheck release/beast/*.sh nixos-appliance/*.sh "${appliance[@]}"
}

gate_contracts() {
  command -v cc
  command -v dnsmasq
  command -v rg
  command -v shellcheck
  gate_bash_syntax
  gate_shellcheck
  python3 -m py_compile nixos-appliance/*.py tools/pack-system-closure.py tools/system_closure.py
  python3 -B -m unittest discover -s nixos-appliance/tests -v
  python3 -B -m unittest discover -s tools/tests -v
}

gate_rust() {
  local tree
  cargo fmt --all --check
  cargo test --locked
  cargo clippy --all-targets --all-features -- -D warnings
  # Audit the dependencies before signing a production release.
  cargo audit --version
  tree="$(mktemp)"
  # Only the printed tree counts, as before: an inactive package prints nothing.
  { cargo tree -i sqlx-mysql 2>&1 || true; } | tee "$tree"
  grep -q "nothing to print" "$tree"
  rm -f -- "$tree"
  # RUSTSEC-2026-0459: bundled SQLite before 3.54 can expose stale memory
  # when a process opens a crafted database plus -wal file. The Nest opens
  # only its own root-owned database, and no released sqlx accepts the
  # patched libsqlite3-sys (>= 0.39). Accepted 2026-11-09; review by
  # 2027-02-01 (the shared CI adapter applies the same expiry).
  if [ "$(date -u +%F)" \> 2027-02-01 ]; then
    echo "The RUSTSEC-2026-0459 audit exception expired; review it" >&2
    exit 1
  fi
  cargo audit --ignore RUSTSEC-2023-0071 --ignore RUSTSEC-2026-0459
}

gate_nix() {
  local expression
  nix-instantiate --version
  nix-instantiate --parse release/workstation-netboot.nix >/dev/null
  nix-instantiate --parse release/release-tools.nix >/dev/null
  for expression in nixos-appliance/*.nix; do nix-instantiate --parse "$expression" >/dev/null; done
}

start() {
  local directory="$1" gate tries
  # A leftover from an earlier job on this runner: end its gates, start afresh.
  # Failing here instead would cost the tag, as a retry never rebuilds.
  if [ -e "$directory" ]; then
    echo "Replacing leftover release gates in $directory"
    stop "$directory"
  fi
  install -d -m 0700 "$directory"
  git worktree prune
  git worktree add --quiet --detach "$directory/source" HEAD
  test "$(git -C "$directory/source" rev-parse HEAD)" = "$(git rev-parse HEAD)"
  test -z "$(git -C "$directory/source" status --porcelain --untracked-files=all)"
  for gate in "${GATES[@]}"; do
    # Its own session, so stop can end the whole gate; no inherited step pipes,
    # so the starting step ends at once. The status file is written last.
    # shellcheck disable=SC2016 # Expanded by the gate's own shell.
    setsid bash -c 'cd "$1" && bash release/beast/release-gates.sh "$2"
      printf "%s\n" "$?" > "$3.partial" && mv -- "$3.partial" "$3"' \
      release-gate "$directory/source" "$gate" "$directory/$gate.status" \
      < /dev/null > "$directory/$gate.log" 2>&1 &
    printf '%s\n' "$!" > "$directory/$gate.pid"
    # Return only once the gate leads its own session: join and stop look for it.
    tries=0
    until running "$directory" "$gate" || [ -e "$directory/$gate.status" ]; do
      tries=$((tries + 1))
      if [ "$tries" -gt 100 ]; then
        echo "Release gate $gate did not start" >&2
        exit 1
      fi
      sleep 0.1
    done
    echo "Started release gate $gate"
  done
}

running() {
  local pid
  pid="$(cat -- "$1/$2.pid" 2>/dev/null)" || return 1
  [[ "$pid" =~ ^[1-9][0-9]*$ ]] || return 1
  # Only the gate's own session leader, never a later process with its PID.
  [ "$(ps -o sid= -p "$pid" 2>/dev/null | tr -d ' ')" = "$pid" ]
}

join() {
  local directory="$1" gate status failed=0
  for gate in "${GATES[@]}"; do
    while [ ! -e "$directory/$gate.status" ] && running "$directory" "$gate"; do
      sleep 2
    done
    echo "::group::Release gate $gate"
    cat -- "$directory/$gate.log" 2>/dev/null || true
    echo "::endgroup::"
    status="$(cat -- "$directory/$gate.status" 2>/dev/null || true)"
    if [ "$status" = 0 ]; then
      echo "Release gate $gate passed"
    else
      echo "::error::Release gate $gate failed (${status:-ended without a result})"
      failed=1
    fi
  done
  return "$failed"
}

stop() {
  local directory="$1" gate pid
  for gate in "${GATES[@]}"; do
    if [ ! -e "$directory/$gate.status" ] && running "$directory" "$gate"; then
      pid="$(cat -- "$directory/$gate.pid")"
      kill -TERM -- "-$pid" 2>/dev/null || true
    fi
  done
  if [ -e "$directory/source" ]; then
    git worktree remove --force "$directory/source" 2>/dev/null || true
  fi
  rm -rf -- "$directory"
  git worktree prune 2>/dev/null || true
}

case "${1:-}" in
  start | join | stop)
    [ "$#" -eq 2 ] || { echo "usage: $0 start|join|stop DIR" >&2; exit 2; }
    "$1" "$2"
    ;;
  contracts | rust | nix | bash-syntax | shellcheck)
    [ "$#" -eq 1 ] || { echo "usage: $0 GATE" >&2; exit 2; }
    "gate_${1//-/_}"
    ;;
  *)
    echo "usage: $0 start|join|stop DIR, or $0 contracts|rust|nix|bash-syntax|shellcheck" >&2
    exit 2
    ;;
esac
