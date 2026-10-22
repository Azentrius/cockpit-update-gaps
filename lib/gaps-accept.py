#!/usr/bin/python3 -IB
# SPDX-License-Identifier: Apache-2.0
"""Update Gaps, the Cockpit add-on: acknowledge a finding, or take an
acknowledgement back.

  gaps-accept.py accept REF UNTIL    the reason (optional) on stdin
  gaps-accept.py unaccept REF

Run by gaps-ctl.sh (root), which the page calls. REF is the `ref` of a
finding in the last scan.json; UNTIL a day (YYYY-MM-DD) from today up to 90
days ahead. Writes only /var/lib/update-gaps/accepted.json (atomically, mode
0644); the next scan marks the finding, and the status leaves it out until
that day or until what it was acknowledged for changes. Changes nothing else.

Exit codes: 0 done, 64 wrong call, 65 no such finding in the last scan or a
day out of range, 77 not root.
"""

import fcntl
import json
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
import gapslib as L  # noqa: E402

STATE = "/var/lib/update-gaps/scan.json"
ACCEPTED = "/var/lib/update-gaps/accepted.json"
LOCK = "/run/update-gaps-accept.lock"
STATE_MAX = 64 << 20
REASON_READ = 4096


def say(de, en, err=False):
    print(de if os.environ.get("GAPS_LANG", "").startswith("de") else en, file=sys.stderr if err else sys.stdout)


def finding(doc, ref):
    """(check, finding) of `ref` in a scan.json, or (None, None)."""
    for c in doc.get("checks") or [] if isinstance(doc, dict) else []:
        spec = L.FINDING_KEYS.get(c.get("check")) if isinstance(c, dict) else None
        for f in (c.get(spec[0]) or []) if spec else []:
            if isinstance(f, dict) and L.finding_ref(c["check"], f) == ref:
                return c["check"], f
    return None, None


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


def read_text(path, limit):
    try:
        with open(path, "rb") as f:
            data = f.read(limit + 1)
    except FileNotFoundError:
        return ""
    if len(data) > limit:
        raise ValueError(f"{path} is larger than {limit} bytes")
    return data.decode("utf-8", "replace")


def main(argv, state=STATE, accepted=ACCEPTED, lock=LOCK, stdin=None, now=None, euid=None):
    verb = argv[0] if argv else ""
    if not ((verb == "accept" and len(argv) == 3) or (verb == "unaccept" and len(argv) == 2)) \
            or not L.REF_RE.match(argv[1]) or (verb == "accept" and not L.parse_day(argv[2])):
        say("Aufruf: gaps-accept.py accept REF JJJJ-MM-TT | unaccept REF",
            "usage: gaps-accept.py accept REF YYYY-MM-DD | unaccept REF", err=True)
        return 64
    if (os.geteuid() if euid is None else euid) != 0:
        say("Dafür wird administrativer Zugriff benötigt.", "This needs administrative access.", err=True)
        return 77
    now = now or datetime.now(timezone.utc)
    today = now.date()
    ref = argv[1]
    entry = None
    if verb == "accept":
        until = L.parse_day(argv[2])
        if not today <= until <= today + timedelta(days=L.ACK_MAX_DAYS):
            say(f"Das Datum muss zwischen heute und {L.ACK_MAX_DAYS} Tagen danach liegen.",
                f"The day must lie between today and {L.ACK_MAX_DAYS} days from now.", err=True)
            return 65
        try:
            check, f = finding(json.loads(read_text(state, STATE_MAX) or "{}"), ref)
        except ValueError:
            check, f = None, None
        if not check:
            say("Diesen Befund gibt es im letzten Stand nicht. Prüfen Sie erneut und versuchen Sie es dann noch einmal.",
                "This finding is not in the last state. Check again, then try once more.", err=True)
            return 65
        stream = stdin or sys.stdin
        # The page sends the reason; from a terminal there is none (no waiting for input).
        reason = L.clean_reason(stream.read(REASON_READ) if stream and not stream.isatty() else "")
        entry = {"ref": ref, "check": check, "label": L.finding_label(f), "pin": L.finding_pin(check, f),
                 "until": until.isoformat(), "reason": reason, "at": now.strftime("%Y-%m-%dT%H:%M:%SZ")}
    fd = os.open(lock, os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0), 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            kept = L.parse_accepted(read_text(accepted, L.ACK_MAX * 1024), today)
        except ValueError:
            kept = {}
        had = kept.pop(ref, None)
        if entry:
            kept[ref] = entry
        items = sorted(kept.values(), key=lambda e: (e["until"], e["ref"]))[-L.ACK_MAX:]
        write_atomic(accepted, {"format": 1, "accepted": items})
    finally:
        os.close(fd)
    if entry:
        label = entry["label"] or ref
        say(f"Quittiert bis {entry['until']}: {label}", f"Acknowledged until {entry['until']}: {label}")
    elif had:
        say("Quittung aufgehoben: " + (had["label"] or ref), "Acknowledgement taken back: " + (had["label"] or ref))
    else:
        say("Für diesen Befund gab es keine Quittung.", "There was no acknowledgement for this finding.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
