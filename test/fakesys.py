# SPDX-License-Identifier: Apache-2.0
"""A stand-in for gapscheck.System that answers from a recorded scenario in
test/fixtures/<scenario>/ (see import_capture.py): commands/*.txt for the
commands, meta.json for files, directories, stat data and the clock.

Nothing touches the machine the tests run on."""

import json
import os
import stat
import sys
from datetime import datetime, timezone
from types import SimpleNamespace

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "lib"))
import gapsproc  # noqa: E402

FIXTURES = os.path.join(HERE, "fixtures")

MODES = {"file": stat.S_IFREG, "dir": stat.S_IFDIR, "link": stat.S_IFLNK, "other": stat.S_IFIFO}


class FakeSystem:
    def __init__(self, scenario, uid=None, missing=(), results=None, files=None, now=None):
        self.dir = os.path.join(FIXTURES, scenario)
        with open(os.path.join(self.dir, "meta.json")) as f:
            self.meta = json.load(f)
        if files:
            self.meta["files"].update(files)
        self._uid = self.meta.get("uid", 0) if uid is None else uid
        self.missing = set(missing)
        self.results = dict(results or {})
        self._now = now or self.meta["now"]
        self.calls = []

    # -- commands
    def _key(self, argv):
        a = list(argv)
        if a[:2] == ["dpkg-query", "-W"]:
            return "dpkg-query-W"
        if a[:2] == ["dpkg-query", "-S"]:
            return "dpkg-query-S"
        if a == ["apt-cache", "policy"]:
            return "apt-cache-policy"
        if a[:2] == ["apt-cache", "policy"]:
            return "apt-cache-policy-installed"
        if a == ["apt-mark", "showhold"]:
            return "apt-mark-showhold"
        if a[:2] == ["apt-get", "-s"]:
            return "apt-get-s-dist-upgrade"
        if a[:2] == ["apt-get", "indextargets"]:
            return "indextargets-all" if "--no-release-info" in a else "indextargets"
        if a[:2] == ["apt-config", "dump"]:
            return "apt-config-dump"
        if a[:1] == ["pro"]:
            return "pro"
        if a[:1] == ["needrestart"]:
            return "needrestart"
        if a[:3] == ["systemctl", "show", "apt-daily.service"]:
            return "systemctl-show-apt-daily"
        if a[:3] == ["systemctl", "is-enabled", "apt-daily-upgrade.timer"]:
            return "systemctl-is-enabled-apt-daily-upgrade"
        if a[:3] == ["journalctl", "-u", "apt-daily.service"]:
            return "journalctl-apt-daily"
        raise AssertionError(f"unexpected command {argv}")

    def run(self, argv, limit=120):
        key = self._key(argv)
        self.calls.append(key)
        if key in self.results:
            return self.results[key]
        if key in self.missing or argv[0] in self.missing:
            return gapsproc.Result(None, missing=True)
        for ext in (".txt", ".json"):
            p = os.path.join(self.dir, "commands", key + ext)
            if os.path.exists(p):
                with open(p, encoding="utf-8") as f:
                    text = f.read()
                return gapsproc.Result(1 if key == "dpkg-query-S" else 0, text, "")
        return gapsproc.Result(None, missing=True)

    def run_unprivileged(self, argv, limit=120):
        self.unprivileged = getattr(self, "unprivileged", []) + [argv[0]]
        return self.run(argv, limit)

    # -- files
    def read_bytes(self, path, limit=4 << 20):
        text = self.meta["files"].get(path)
        return None if text is None else text.encode("utf-8")[:limit]

    def read(self, path, limit=4 << 20):
        data = self.read_bytes(path, limit)
        return None if data is None else data.decode("utf-8")

    def listdir(self, path):
        names = self.meta["dirs"].get(path)
        return None if names is None else sorted(names)

    def lstat(self, path):
        st = self.meta["stat"].get(path)
        if st is None:
            if path in self.meta["files"]:
                st = {"type": "file", "mtime": 1792400000, "mode": "644", "uid": 0}
            elif path in self.meta["dirs"]:
                st = {"type": "dir", "mtime": 1792400000, "mode": "755", "uid": 0}
            else:
                return None
        return SimpleNamespace(st_mode=MODES[st["type"]] | int(st.get("mode", "644"), 8),
                               st_mtime=float(st["mtime"]), st_uid=st.get("uid", 0))

    def readlink(self, path):
        return (self.meta["stat"].get(path) or {}).get("target")

    def head(self, path, n=128):
        st = self.meta["stat"].get(path) or {}
        if st.get("type") != "file":
            return None
        h = self.meta["heads"].get(path)
        return None if h is None else (h + "\n").encode("utf-8")[:n]

    def now(self):
        return datetime.strptime(self._now, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)

    def uid(self):
        return self._uid

    def kernel(self):
        return self.meta.get("kernel", "")
