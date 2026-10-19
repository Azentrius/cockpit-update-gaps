#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Builds a static preview of the page with the test fixtures.

    python3 tools/preview/build.py      -> tools/preview/out/update-gaps/index.html
    open tools/preview/out/update-gaps/index.html?lang=de&scenario=resolute-stale-lists

Cockpit's base1/cockpit.js is replaced by cockpit-stub.js, which answers the
page's file and spawn calls from test/fixtures/scan-*.json (what the helper
writes for the recorded hosts). Nothing touches a real server. The output
directory is generated and git-ignored.
"""
import json
import os
import shutil

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
FIX = os.path.join(REPO, "test", "fixtures")
OUT = os.path.join(HERE, "out")
NOW = "2026-10-19T21:00:00Z"

PO_STUB = """// Stand-in for Cockpit's base1/po.js: ?lang=de switches the session language.
const _l = new URLSearchParams(location.search).get("lang");
if (_l && _l !== "en") cockpit.locale({"": {"language": _l, "language-direction": "ltr"}});
"""


def main():
    scans = {}
    for name in sorted(os.listdir(FIX)):
        if name.startswith("scan-") and name.endswith(".json"):
            with open(os.path.join(FIX, name)) as f:
                scans[name[len("scan-"):-len(".json")]] = json.load(f)
    shutil.rmtree(OUT, ignore_errors=True)
    os.makedirs(os.path.join(OUT, "base1"))
    shutil.copytree(os.path.join(REPO, "plugin"), os.path.join(OUT, "update-gaps"))
    with open(os.path.join(HERE, "cockpit-stub.js")) as f:
        stub = f.read()
    stub = stub.replace("__FIXTURES__", json.dumps({"scans": scans}, ensure_ascii=False)).replace("__NOW__", json.dumps(NOW))
    with open(os.path.join(OUT, "base1", "cockpit.js"), "w") as f:
        f.write(stub)
    with open(os.path.join(OUT, "base1", "po.js"), "w") as f:
        f.write(PO_STUB)
    print("Preview:", os.path.join(OUT, "update-gaps", "index.html") + "?scenario=noble-held")


if __name__ == "__main__":
    main()
