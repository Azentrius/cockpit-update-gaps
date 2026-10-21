#!/usr/bin/python3 -IB
# SPDX-License-Identifier: Apache-2.0
"""Update Gaps, the Cockpit add-on: every check of this host, as JSON.

  gaps-scan.py                   the document on stdout (diagnosis; as any user)
  gaps-scan.py --output FILE [--status FILE]
                                 written atomically, mode 0644, with the
                                 status of the add-on (gapsstatus.py) beside it
                                 (update-gaps-scan.service, as root, no network)

Only reads: no `apt update`, no install, no restart, no network. The checks
are in gapscheck.py, the format in docs/INTERNALS.md. As root a lock in /run
keeps two scans apart (exit 75 while one runs). A scan that fails as a whole
leaves the previous file as it was (exit 1). With --output the previous file
gives every finding the time it was first seen.
"""

import argparse
import fcntl
import json
import os
import sys
import tempfile

# -I leaves the script's directory out of sys.path; the modules come from this
# root-owned directory only. No bytecode is written next to them (-B, and here
# for a call without it): the package owns every file in that directory.
sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
import gapscheck  # noqa: E402
import gapsstatus  # noqa: E402

LOCK = "/run/update-gaps-scan.lock"
PREVIOUS_MAX = 64 << 20


def previous(path):
    """The last document at path (this script wrote it), or None: missing,
    too large or not JSON. Only the times findings were first seen are taken
    from it."""
    try:
        with open(path, "rb") as f:
            data = f.read(PREVIOUS_MAX + 1)
        doc = json.loads(data.decode("utf-8")) if len(data) <= PREVIOUS_MAX else None
    except (OSError, ValueError):
        return None
    return doc if isinstance(doc, dict) else None


def write_atomic(path, doc):
    d = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(dir=d, prefix="." + os.path.basename(path) + "-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(doc, f, ensure_ascii=False, indent=1)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def lock():
    """The scan lock (root only); None without root. Exit 75 when taken."""
    if os.geteuid() != 0:
        return None
    fd = os.open(LOCK, os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0), 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd)
        print("another scan is running", file=sys.stderr)
        sys.exit(75)
    return fd


def main(argv):
    ap = argparse.ArgumentParser(description="Update Gaps: where this host misses updates")
    ap.add_argument("--output", metavar="FILE", help="write the document atomically (mode 0644)")
    ap.add_argument("--status", metavar="FILE", help="with --output: write the status of the add-on as well")
    args = ap.parse_args(argv)
    if args.status and not args.output:
        ap.error("--status needs --output")
    held = lock()
    try:
        doc = gapscheck.scan(previous=previous(args.output) if args.output else None)
    except Exception as e:  # noqa: BLE001 - the previous state file stays as it is
        print(f"scan failed: {type(e).__name__}: {e}", file=sys.stderr)
        return 1
    if args.output:
        write_atomic(args.output, doc)
        if args.status:
            write_atomic(args.status, gapsstatus.status_file(doc, gapsstatus.version()))
        states = {}
        for c in doc["checks"]:
            states[c["state"]] = states.get(c["state"], 0) + 1
        print(f"{len(doc['checks'])} checks in {doc['took_ms']} ms: "
              + ", ".join(f"{n} {s}" for s, n in sorted(states.items())) + f" -> {args.output}")
    else:
        json.dump(doc, sys.stdout, ensure_ascii=False, indent=1)
        sys.stdout.write("\n")
    if held is not None:
        os.close(held)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
