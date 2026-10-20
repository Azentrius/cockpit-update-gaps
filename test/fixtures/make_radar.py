#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""The network data (radar.json) of the recorded scenarios, from real answers
of Canonical's CVE OVAL, Launchpad and GitHub: test/fixtures/radar-<scenario>.json.

Runs gaps-radar.py's radar() against the selection of each scenario (fakesys)
with the network, then fixes the times to the scenario's clock and drops the
ETags, so the files only change when the answers do. Needs network access;
the tests themselves never use the network.

    python3 test/fixtures/make_radar.py     fetch and write them (about 15 MB of downloads)
"""

import importlib.util
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
LIB = os.path.join(HERE, "..", "..", "lib")
sys.path.insert(0, LIB)
sys.path.insert(0, os.path.join(HERE, ".."))
from fakesys import FakeSystem  # noqa: E402

SCENARIOS = ("noble-held", "resolute-stale-lists", "resolute-nodesource")


def load_radar_module():
    spec = importlib.util.spec_from_file_location("gaps_radar", os.path.join(LIB, "gaps-radar.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def scrub(doc, now):
    doc["generated"] = now
    for svc in doc["services"].values():
        svc["fetched"] = now
        svc.pop("data_fetched", None)
    doc.pop("oval_file", None)
    for section in ("launchpad", "github"):
        for entry in (doc.get(section) or {}).values():
            entry["fetched"] = now
            entry.pop("etag", None)
    return doc


def main():
    mod = load_radar_module()
    with tempfile.TemporaryDirectory() as root:
        for scenario in SCENARIOS:
            fs = FakeSystem(scenario)
            # One OVAL download per release: scenarios of a release share a state directory.
            state = os.path.join(root, scenario.split("-")[0])
            os.makedirs(state, exist_ok=True)
            doc = scrub(mod.radar(system=fs, state_dir=state, sleep=lambda s: None), fs.meta["now"])
            path = os.path.join(HERE, f"radar-{scenario}.json")
            with open(path, "w", encoding="utf-8", newline="\n") as f:
                json.dump(doc, f, ensure_ascii=False, indent=1)
                f.write("\n")
            print(path, {k: v["state"] for k, v in doc["services"].items()}, os.path.getsize(path))


if __name__ == "__main__":
    main()
