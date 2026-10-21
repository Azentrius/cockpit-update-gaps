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

MIRROR = "https://mirror.hetzner.com/ubuntu/"
# Ubuntu rolled systemd 259.9 out in phases (10 %) on 2026-10-20, while other updates waited beside
# it; on the recorded Ubuntu 26.04 hosts Software Updates then failed with "Package id
# 'libnss-systemd;259.9-0ubuntu0.1;…' is not available as an update candidate". The scenario
# resolute-nodesource as it looks then: `apt-get -s` with systemd deferred and three updates
# (openssl from the security pocket), `apt-cache policy` with the new versions.
PHASED_SIMULATION = """Reading package lists...
Building dependency tree...
Reading state information...
Calculating upgrade...
The following upgrades have been deferred due to phasing:
  systemd
The following packages will be upgraded:
  openssl sudo ubuntu-pro-client
3 upgraded, 0 newly installed, 0 to remove and 1 not upgraded.
Inst openssl [3.5.5-1ubuntu3.7] (3.5.5-1ubuntu3.8 Ubuntu:26.04/resolute-updates, Ubuntu:26.04/resolute-security [amd64])
Inst sudo [1.9.17p2-1ubuntu3.2] (1.9.17p2-1ubuntu3.3 Ubuntu:26.04/resolute-updates [amd64])
Inst ubuntu-pro-client [37.2ubuntu0.1] (37.3ubuntu0.1 Ubuntu:26.04/resolute-updates [amd64])
Conf openssl (3.5.5-1ubuntu3.8 Ubuntu:26.04/resolute-updates, Ubuntu:26.04/resolute-security [amd64])
Conf sudo (1.9.17p2-1ubuntu3.3 Ubuntu:26.04/resolute-updates [amd64])
Conf ubuntu-pro-client (37.3ubuntu0.1 Ubuntu:26.04/resolute-updates [amd64])
"""
UPDATES = MIRROR + "packages resolute-updates/main amd64 Packages"
SECURITY = MIRROR + "security resolute-security/main amd64 Packages"
PHASED_VERSIONS = (("systemd", "259.9-0ubuntu0.1", [UPDATES], 10),
                   ("openssl", "3.5.5-1ubuntu3.8", [UPDATES, SECURITY], None),
                   ("sudo", "1.9.17p2-1ubuntu3.3", [UPDATES], None),
                   ("ubuntu-pro-client", "37.3ubuntu0.1", [UPDATES], None))


def with_version(policy, name, version, sources, phased=None):
    """`apt-cache policy` output with `version` of `name` as its candidate,
    above the installed one, from `sources` (and apt's note on a phased
    version)."""
    lines = policy.splitlines(keepends=True)
    i = lines.index(name + ":\n")
    lines[i + 2] = f"  Candidate: {version}\n"
    note = f" (phased {phased}%)" if phased is not None else ""
    lines[i + 4:i + 4] = [f"     {version} 500{note}\n"] + [f"        500 {s}\n" for s in sources]
    return "".join(lines)


def phased_results(scenario="resolute-nodesource"):
    """`results` for FakeSystem: the scenario during the rollout above."""
    with open(os.path.join(FIXTURES, scenario, "commands", "apt-cache-policy-installed.txt"), encoding="utf-8") as f:
        policy = f.read()
    for name, version, suites, phased in PHASED_VERSIONS:
        policy = with_version(policy, name, version, suites, phased)
    return {"apt-get-s-dist-upgrade": gapsproc.Result(0, PHASED_SIMULATION, ""),
            "apt-cache-policy-installed": gapsproc.Result(0, policy, "")}


class FakeSystem:
    def __init__(self, scenario, uid=None, missing=(), results=None, files=None, now=None, snapd=None):
        self.dir = os.path.join(FIXTURES, scenario)
        with open(os.path.join(self.dir, "meta.json")) as f:
            self.meta = json.load(f)
        if files:
            self.meta["files"].update(files)
        self._uid = self.meta.get("uid", 0) if uid is None else uid
        self.missing = set(missing)
        self.results = dict(results or {})
        self._now = now or self.meta["now"]
        self._snapd = snapd     # {API path: result}; None: snapd answers nothing
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
        if a[:2] == ["apt-cache", "policy"] and len(a) == 3 and a[2].endswith("-microcode"):
            return "apt-cache-policy-" + a[2]
        if a[:2] == ["apt-cache", "policy"]:
            return "apt-cache-policy-installed"
        if a == ["systemd-detect-virt"]:
            return "systemd-detect-virt"
        if a[:2] == ["fwupdmgr", "get-updates"]:
            return "fwupdmgr-get-updates"
        if a[:2] == ["fwupdmgr", "get-remotes"]:
            return "fwupdmgr-get-remotes"
        if a == ["systemctl", "is-enabled", "fwupd-refresh.timer"]:
            return "systemctl-is-enabled-fwupd-refresh"
        if a == ["apt-mark", "showhold"]:
            return "apt-mark-showhold"
        if a == ["apt-mark", "showmanual"]:
            return "apt-mark-showmanual"
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
                rc = 1 if key == "dpkg-query-S" else 0
                rcp = os.path.join(self.dir, "commands", key + ".rc")     # an exit code the capture recorded
                if os.path.exists(rcp):
                    with open(rcp, encoding="utf-8") as f:
                        rc = int(f.read().strip() or 0)
                return gapsproc.Result(rc, text, "")
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

    SNAPD_FILES = {"/v2/snaps": "snapd-snaps.json", "/v2/system-info": "snapd-system-info.json",
                   "/v2/changes?select=all": "snapd-changes.json"}

    def snapd(self, path, limit=20):
        """The answers of snapd: given to the constructor, or recorded by capture.sh."""
        self.calls.append("snapd " + path)
        if self._snapd is not None:
            if path not in self._snapd:
                raise ConnectionRefusedError(f"snapd: no answer for {path}")
            return self._snapd[path]
        p = os.path.join(self.dir, "commands", self.SNAPD_FILES.get(path, "-"))
        if not os.path.exists(p):
            raise ConnectionRefusedError(f"snapd: no answer for {path}")
        with open(p, encoding="utf-8") as f:
            return json.load(f).get("result")
