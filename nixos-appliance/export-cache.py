#!/usr/bin/env python3
"""Produce an unsigned local binary cache without a daemon or private signing key."""
import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

ALPHABET = "0123456789abcdfghijklmnpqrsvwxyz"
# --long=27 uses a 128 MiB window (~256-384 MiB encoder RAM); skip it on small NARs
# and cap worker count by both CPU cores and available memory.
LONG_WINDOW_MIN_BYTES = 1024 * 1024
MEMORY_PER_WORKER_BYTES = 384 * 1024 * 1024
MAX_WORKERS = 16


def nix32(raw):
    number = int.from_bytes(raw, "little")
    return "".join(ALPHABET[(number >> (5 * n)) & 31] for n in reversed(range((len(raw) * 8 + 4) // 5)))


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def worker_count():
    raw_cores = os.environ.get("NIX_BUILD_CORES", "").strip()
    if raw_cores.isdigit() and int(raw_cores) > 0:
        cores = int(raw_cores)
    else:
        cores = os.cpu_count() or 1
    mem_limit = MAX_WORKERS
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemAvailable:"):
                avail_bytes = int(line.split()[1]) * 1024
                mem_limit = max(1, avail_bytes // MEMORY_PER_WORKER_BYTES)
                break
    except (OSError, ValueError):
        pass
    return max(1, min(cores, mem_limit, MAX_WORKERS))


def export_item(item, output):
    path = item["path"]
    nar_size = item["narSize"]
    store_hash = Path(path).name.split("-", 1)[0]
    archive = output / "nar" / (store_hash + ".nar.zst")
    zstd_cmd = ["zstd", "-q", "-T1", "-10"]
    if nar_size >= LONG_WINDOW_MIN_BYTES:
        zstd_cmd.append("--long=27")
    with archive.open("wb") as target:
        dump = subprocess.Popen(["nix-store", "--dump", path], stdout=subprocess.PIPE)
        compression = subprocess.run(zstd_cmd, stdin=dump.stdout, stdout=target)
        dump.stdout.close()
        if dump.wait() or compression.returncode:
            raise RuntimeError(f"NAR export failed for {path}")
    with archive.open("rb") as stream:
        file_hash = "sha256:" + nix32(hashlib.file_digest(stream, "sha256").digest())
    nar_hash = item["narHash"]
    if nar_hash.startswith("sha256-"):
        nar_hash = "sha256:" + nix32(base64.b64decode(nar_hash[7:]))
    references = sorted(item["references"])
    narinfo = store_hash + ".narinfo"
    (output / narinfo).write_text(
        f"StorePath: {path}\nURL: nar/{archive.name}\nCompression: zstd\n"
        f"FileHash: {file_hash}\nFileSize: {archive.stat().st_size}\n"
        f"NarHash: {nar_hash}\nNarSize: {nar_size}\n"
        f"References: {' '.join(Path(ref).name for ref in references)}\n")
    return {"path": path, "nar_hash": nar_hash, "nar_size": nar_size,
            "references": references, "narinfo": narinfo}


def main():
    graph_file, metadata_file, destination = sys.argv[1:]
    graph = json.loads(Path(graph_file).read_text())["closure"]
    metadata = json.loads(Path(metadata_file).read_text())
    output = Path(destination)
    (output / "nar").mkdir(parents=True)
    (output / "nix-cache-info").write_text("StoreDir: /nix/store\nWantMassQuery: 1\nPriority: 40\n")
    # Schedule largest NARs first to minimize tail latency, then sort rows by path for determinism.
    ordered = sorted(graph, key=lambda row: (-row["narSize"], row["path"]))
    workers = min(worker_count(), max(1, len(ordered)))
    if workers == 1:
        rows = [export_item(item, output) for item in ordered]
    else:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            rows = list(pool.map(lambda item: export_item(item, output), ordered))
    rows.sort(key=lambda row: row["path"])
    total = sum(row["nar_size"] for row in rows)
    if total > 32 * 1024 ** 3 or len(rows) * 2 + 3 > 65536:
        raise ValueError("system closure exceeds appliance limits")
    metadata.pop("manage_origin")
    metadata["schema"] = "tiaris.nest.system-closure.v1"
    metadata["store_paths"] = rows
    metadata["total_nar_bytes"] = total
    (output / "manifest.json").write_bytes(canonical(metadata))


if __name__ == "__main__":
    main()
