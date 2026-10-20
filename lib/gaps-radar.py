#!/usr/bin/python3 -IB
# SPDX-License-Identifier: Apache-2.0
"""Update Gaps, the Cockpit add-on: the radar of stage 2, network data for
the scan.

  gaps-radar.py --output FILE     fetch, keep the last good answers, write
                                  FILE atomically (update-gaps-radar.service)
  gaps-radar.py --dry-run         print what it would ask about, fetch nothing

Runs as an unprivileged user (DynamicUser) with network access; it never
runs as root and never runs a command that changes the system. It reads the
package state (dpkg, apt-mark, apt-cache; readable by every user), asks the
sources in gapsradar.py about the selected source packages and writes
radar.json. A source that fails keeps its previous answers, marked stale.
The root scan (gaps-scan.py) reads that file as data only.
"""

import argparse
import bz2
import json
import os
import sys
import tempfile
import time
import urllib.parse
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
import gapscheck  # noqa: E402
import gapsradar as R  # noqa: E402

FORMAT = 1
PAUSE = 1.0             # seconds between two requests to the same service
LAUNCHPAD = ("https://api.launchpad.net/1.0/ubuntu/+archive/primary?ws.op=getPublishedSources"
             "&source_name={src}&exact_match=true&status=Published")
GITHUB = "https://api.github.com/repos/{repo}/releases?per_page=30"


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load(path):
    try:
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
        return doc if isinstance(doc, dict) and doc.get("format") == FORMAT else {}
    except (OSError, ValueError):
        return {}


def write_atomic(path, doc):
    d = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(dir=d, prefix="." + os.path.basename(path) + "-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
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


def collect(keys, old, ask, pause=PAUSE, sleep=time.sleep):
    """Ask `ask(key, previous)` for every key; on a failure keep the previous
    answer marked stale. Stops asking a service that asks to slow down.
    -> ({key: entry}, {state, fetched, error})."""
    out, errors, limited = {}, [], False
    for i, key in enumerate(keys):
        prev = old.get(key) if isinstance(old.get(key), dict) else None
        if limited:
            if prev:
                out[key] = dict(prev, stale=True)
            continue
        if i:
            sleep(pause)
        try:
            out[key] = ask(key, prev)
        except R.FetchError as e:
            errors.append(f"{key}: {e}")
            limited = e.limited
            if prev:
                out[key] = dict(prev, stale=True)
    state = "ok" if not errors else "error" if len(errors) == len(keys) or limited else "partial"
    return out, {"state": state, "fetched": now(), "errors": errors[:20], "limited": limited}


def ask_launchpad(opener=None):
    def ask(src, prev):
        doc, etag = R.fetch_json(LAUNCHPAD.format(src=urllib.parse.quote(src)),
                                 (prev or {}).get("etag"), opener)
        if doc is None and prev:
            return dict(prev, fetched=now(), stale=False)
        return {"fetched": now(), "etag": etag, "published": R.parse_launchpad(doc, src)}
    return ask


def ask_github(opener=None):
    def ask(repo, prev):
        doc, etag = R.fetch_json(GITHUB.format(repo=repo), (prev or {}).get("etag"), opener)
        if doc is None and prev:
            return dict(prev, fetched=now(), stale=False)
        return {"fetched": now(), "etag": etag, "releases": R.parse_releases(doc)}
    return ask


def oval(codename, sources, state_dir, old, opener=None):
    """Canonical's CVE OVAL of this release: downloaded with its ETag into the
    state directory (kept, so a new selection needs no new download), parsed
    for the selected source packages. -> (section, service state)."""
    path = os.path.join(state_dir, "cve.oval.xml.bz2")
    meta = old.get("oval_file") if isinstance(old.get("oval_file"), dict) else {}
    have = os.path.exists(path)
    fetched, error = meta.get("fetched"), None
    try:
        body, etag = R.fetch(R.OVAL_URL.format(codename=codename), meta.get("etag") if have else None,
                             opener, max_bytes=R.OVAL_MAX)
        if body is not None:
            tmp = path + ".part"
            with open(tmp, "wb") as f:
                f.write(body)
            os.replace(tmp, path)
            meta = {"etag": etag}
        fetched = now()
    except R.FetchError as e:
        error = str(e)
    if not os.path.exists(path):
        return {}, {"state": "error", "fetched": now(), "errors": [error or "no data"], "limited": False}, {}
    try:
        with bz2.open(path) as f:
            section = R.parse_oval(f, sources, codename)
    except (OSError, EOFError, ValueError, ET.ParseError) as e:
        return {}, {"state": "error", "fetched": now(), "errors": [f"OVAL: {type(e).__name__}"], "limited": False}, {}
    state = {"state": "partial" if error else "ok", "fetched": now(), "errors": [error] if error else [],
             "limited": False, "data_fetched": fetched}
    return section, state, dict(meta, fetched=fetched)


def radar(system=None, old=None, opener=None, sleep=time.sleep, state_dir=None):
    """Everything the radar knows -> the document of radar.json."""
    ctx = gapscheck.Context(system or gapscheck.System())
    sel = R.selection(ctx)
    old = old or {}
    ident = (ctx.osr.get("ID") or "").lower()
    doc = {"format": FORMAT, "generated": None, "distro": ident, "codename": ctx.codename or None,
           "selection": sel, "services": {}}
    if ident == "ubuntu" and ctx.codename and state_dir:
        doc["oval"], doc["services"]["oval"], doc["oval_file"] = oval(
            ctx.codename, list(sel["sources"]), state_dir, old, opener)
    if ident == "ubuntu":
        doc["launchpad"], doc["services"]["launchpad"] = collect(
            list(sel["sources"]), old.get("launchpad") or {}, ask_launchpad(opener), sleep=sleep)
    doc["github"], doc["services"]["github"] = collect(
        list(sel["upstream"]), old.get("github") or {}, ask_github(opener), sleep=sleep)
    doc["generated"] = now()
    return doc


def main(argv):
    ap = argparse.ArgumentParser(description="Update Gaps: network data for the scan")
    ap.add_argument("--output", metavar="FILE", help="write radar.json atomically (mode 0644)")
    ap.add_argument("--dry-run", action="store_true", help="print the selection, fetch nothing")
    args = ap.parse_args(argv)
    if os.geteuid() == 0:
        print("gaps-radar.py never runs as root (update-gaps-radar.service runs it unprivileged)", file=sys.stderr)
        return 77
    if args.dry_run:
        sel = R.selection(gapscheck.Context(gapscheck.System()))
        json.dump(sel, sys.stdout, indent=1)
        sys.stdout.write("\n")
        return 0
    if not args.output:
        ap.error("--output or --dry-run")
    doc = radar(old=load(args.output), state_dir=os.path.dirname(os.path.abspath(args.output)))
    write_atomic(args.output, doc)
    print(", ".join(f"{k} {v['state']}" for k, v in doc["services"].items()) + f" -> {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
