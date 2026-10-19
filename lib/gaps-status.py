#!/usr/bin/python3 -IB
# SPDX-License-Identifier: Apache-2.0
"""Update Gaps, the Cockpit add-on: its state in the status contract of the
Azentrius add-ons (schema 1), for the Status Board and other tools.

  gaps-status.py status [--lang en|de]

Reads /var/lib/update-gaps/status.json, which update-gaps-scan.service writes
after every scan. Needs no root, runs no command, uses no network and takes no
lock. Without the file the state is `none` with the reason. A language other
than German gets English. Exit 0 (findings are no error, `danger` included),
64 for a wrong call, 77 when the file exists but cannot be read.
"""

import json
import os
import re
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
import gapsstatus  # noqa: E402

STATUS = "/var/lib/update-gaps/status.json"
LANG_RE = re.compile(r"^[A-Za-z]{2,3}([_-][A-Za-z0-9]{2,8})?$")
USAGE = "usage: gaps-status.py status [--lang en|de]"


def language(argv):
    """The language of a valid call, None for anything else."""
    if argv[:1] != ["status"]:
        return None
    rest = argv[1:]
    if rest and len(rest) == 1 and rest[0].startswith("--lang="):
        rest = ["--lang", rest[0][len("--lang="):]]
    if not rest:
        return "en"
    if len(rest) != 2 or rest[0] != "--lang" or not LANG_RE.match(rest[1]):
        return None
    return "de" if rest[1].lower()[:2] == "de" else "en"


def load(path, lang, ver):
    try:
        with open(path, "rb") as f:
            data = f.read(1 << 20)
    except FileNotFoundError:
        return gapsstatus.none_document(lang, ver, "missing")
    try:
        status = json.loads(data.decode("utf-8"))
    except ValueError:
        return gapsstatus.none_document(lang, ver, "unreadable")
    if not isinstance(status, dict) or gapsstatus.problems(status):
        return gapsstatus.none_document(lang, ver, "unreadable")
    out = gapsstatus.localize(status, lang)
    out["version"] = ver
    return out


def main(argv, path=STATUS):
    lang = language(argv)
    if lang is None:
        print(USAGE, file=sys.stderr)
        return 64
    try:
        doc = load(path, lang, gapsstatus.version())
    except OSError as e:
        print(f"cannot read {path}: {e.strerror}", file=sys.stderr)
        return 77
    json.dump(doc, sys.stdout, ensure_ascii=False)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
