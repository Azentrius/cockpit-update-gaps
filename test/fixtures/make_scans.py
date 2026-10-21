#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""The state files (scan.json) of the recorded scenarios, as the helper
writes them: test/fixtures/scan-<scenario>.json, plus one of a user without
administrative access. The page tests and the preview read these, so the page
is always tested against what the helper really produces;
test/scan_test.py checks that they are current.

Beside them status-<scenario>.json: the status file the service writes for the
Status Board (gapsstatus.py), with a fixed version so a release leaves them as
they are.

    python3 test/fixtures/make_scans.py          write them
    python3 test/fixtures/make_scans.py --check  exit 1 if one differs
"""

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "lib"))
sys.path.insert(0, os.path.join(HERE, ".."))
import gapscheck  # noqa: E402
import gapsstatus  # noqa: E402
from fakesys import FakeSystem  # noqa: E402

SCANS = {
    "scan-noble-held.json": ("noble-held", {}),
    "scan-resolute-stale-lists.json": ("resolute-stale-lists", {}),
    "scan-resolute-nodesource.json": ("resolute-nodesource", {}),
    "scan-resolute-nodesource-user.json": ("resolute-nodesource", {"uid": 1000}),
    # With the network data of stage 2 (radar-<scenario>.json, written by make_radar.py).
    "scan-noble-held-radar.json": ("noble-held", {"radar": True}),
    "scan-resolute-nodesource-radar.json": ("resolute-nodesource", {"radar": True}),
    # The OVAL copy is there, its time is not (radar.json's oval_file lost), and today's download failed:
    # the radar writes data_fetched null, the age of the data is unknown.
    "scan-noble-held-radar-unknown.json": ("noble-held", {"radar": "unknown"}),
}
STATUS_VERSION = "0.1.0"


def scan(scenario, kw):
    kw = dict(kw)
    radar = kw.pop("radar", False)
    if radar:
        with open(os.path.join(HERE, f"radar-{scenario}.json"), encoding="utf-8") as f:
            text = f.read()
        if radar == "unknown":
            doc = json.loads(text)
            doc["services"]["oval"].update(state="partial", errors=["HTTP 503"], data_fetched=None)
            text = json.dumps(doc)
        kw["files"] = {gapscheck.RADAR: text}
    doc = gapscheck.scan(FakeSystem(scenario, **kw))
    doc["took_ms"] = 3300
    for c in doc["checks"]:
        c["took_ms"] = 0
    return doc


def files():
    """{file name: content} of every fixture this script writes."""
    out = {}
    for name, (scenario, kw) in SCANS.items():
        doc = scan(scenario, kw)
        out[name] = json.dumps(doc, ensure_ascii=False, indent=1) + "\n"
        if "uid" not in kw:
            status = gapsstatus.status_file(doc, STATUS_VERSION)
            out["status-" + name[len("scan-"):]] = json.dumps(status, ensure_ascii=False, indent=1) + "\n"
    return out


def main(argv):
    check = "--check" in argv
    bad = 0
    for name, text in files().items():
        path = os.path.join(HERE, name)
        if check:
            try:
                with open(path, encoding="utf-8", newline="") as f:
                    same = f.read() == text
            except OSError:
                same = False
            if not same:
                print(f"{name} is not current: python3 test/fixtures/make_scans.py", file=sys.stderr)
                bad = 1
        else:
            with open(path, "w", encoding="utf-8", newline="\n") as f:
                f.write(text)
            print(path)
    return bad


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
