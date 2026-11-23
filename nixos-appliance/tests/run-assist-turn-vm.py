#!/usr/bin/env python3
"""Run the Nest TURN VM test inside beast-resource run."""

import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile

TEST = Path(__file__).resolve().with_name("assist-turn-vm.nix")
NODES = ("appliance", "peer")


def run_phase(command, work, env, deadline):
    process = subprocess.Popen(command, cwd=work, env=env, stdin=subprocess.DEVNULL,
                               start_new_session=True)
    try:
        status = process.wait(timeout=deadline)
        if status:
            raise RuntimeError(f"{Path(command[0]).name} exited {status}")
    finally:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()


def boot(preflight, work, arguments, report):
    work = Path(work)
    (work / "tmp").mkdir()
    (work / "out").mkdir()
    env = {**os.environ, "TMPDIR": str(work / "tmp"), "XDG_RUNTIME_DIR": str(work),
           "PYTHONUNBUFFERED": "1"}
    run_phase(["nix-build", str(TEST), *preflight.nix_args(arguments), "-A", "driver",
               "--out-link", str(work / "driver")], work, env, 3600)
    preflight.memory_gate(report)
    run_phase([str(work / "driver/bin/nixos-test-driver"), "--output_directory", str(work / "out")],
              work, env, 480)


def main():
    # Use the same preflight as the Manage repo's appliance and workstation tests.
    parser = argparse.ArgumentParser(description=__doc__, add_help=False)
    parser.add_argument("--preflight-dir", type=Path, required=True)
    inputs, _ = parser.parse_known_args()
    sys.path.insert(0, str(inputs.preflight_dir.resolve()))
    import vm_test_preflight as preflight

    parser.add_argument("-h", "--help", action="help")
    preflight.add_mode_arguments(parser)
    mode = preflight.mode_of(parser.parse_args())
    receipt = {"schema": "tiaris.nest.assist-turn-vm.v1", **preflight.receipt_fields(mode),
               "lease": os.environ.get("AGENT_RESOURCE_LEASE"), "host": os.uname().nodename,
               "nodes": NODES if preflight.boots(mode) else (), "preflight": {}}
    try:
        problems = preflight.host_problems(kvm=preflight.boots(mode), work_gib=4, store_gib=10)
        if problems:
            raise preflight.NotRun("\n".join(problems))
        arguments = {"smoke": mode == "smoke"}
        preflight.evaluate(TEST, arguments, mode, receipt["preflight"],
                           script=[TEST.with_name("assist-turn-fixture.py")])
        if preflight.boots(mode):
            with tempfile.TemporaryDirectory(prefix="turn.", dir=preflight.work_root()) as work:
                boot(preflight, work, arguments, receipt["preflight"])
        receipt["result"] = preflight.result_for(mode, True)
        exit_code = 0
    except preflight.NotRun as error:
        receipt.update(result="not_run", error=str(error))
        exit_code = 2
    except Exception as error:
        receipt.update(result="failed", error=str(error))
        exit_code = 1
    print("TURN_VM_RECEIPT " + json.dumps(receipt), flush=True)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
