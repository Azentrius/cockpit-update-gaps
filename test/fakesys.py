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


def command_text(scenario, key):
    with open(os.path.join(FIXTURES, scenario, "commands", key + ".txt"), encoding="utf-8") as f:
        return f.read()


# The scenario noble-held after upkeep went wrong. /boot, a file system of its own, was nearly full
# when unattended-upgrades installed kernel 6.8.0-147 on 2026-10-19: its initramfs could not be
# written, dpkg stopped and left the kernel half configured, and two old kernels keep the room.
# And the keyring of GitHub CLI holds only the key that expired on 2026-09-06 (GitHub published
# the next one in April 2026; hosts that never fetched it stopped reading cli.github.com).
UPKEEP_UU_LOG = """2026-10-18 06:31:20,105 INFO Starting unattended upgrades script
2026-10-18 06:31:20,106 INFO Allowed origins are: o=Ubuntu,a=noble, o=Ubuntu,a=noble-security, o=UbuntuESMApps,a=noble-apps-security, o=UbuntuESM,a=noble-infra-security, o=Ubuntu,a=noble-updates
2026-10-18 06:31:21,861 INFO No packages found that can be upgraded unattended and no pending auto-removals
2026-10-19 06:20:58,105 INFO Starting unattended upgrades script
2026-10-19 06:20:58,106 INFO Allowed origins are: o=Ubuntu,a=noble, o=Ubuntu,a=noble-security, o=UbuntuESMApps,a=noble-apps-security, o=UbuntuESM,a=noble-infra-security, o=Ubuntu,a=noble-updates
2026-10-19 06:21:02,410 INFO Packages that will be upgraded: linux-generic linux-image-6.8.0-147-generic linux-image-generic linux-image-virtual
2026-10-19 06:21:02,411 INFO Writing dpkg log to /var/log/unattended-upgrades/unattended-upgrades-dpkg.log
2026-10-19 06:22:40,118 ERROR Installing the upgrades failed!
2026-10-19 06:22:40,119 ERROR error message: installArchives() failed
2026-10-19 06:22:40,119 ERROR dpkg returned an error! See /var/log/unattended-upgrades/unattended-upgrades-dpkg.log for details
2026-10-19 10:04:22,105 INFO Starting unattended upgrades script
"""
GITHUB_OLD_KEY = """pub:e:4096:1:23F3D4EA75716059:1662463626:1788612228::-:::sc::::::23::0:
uid:e::::1725540228::8112F49127753770F34E73A49614E0AFC050A705::GitHub CLI <opensource+cli@github.com>::::::::::0:
sub:e:4096:1:E5FAF19590714157:1662463626:1788612228:::::e::::::23:
"""

# Test keys as gpg shows them with their fingerprints (the fpr record after each key): A signs and
# expired on 2026-09-01, B signs without end; P only certifies, its subkey S signs until
# 2027-01-15 (1800000000).
FPR_A, FPR_B, FPR_P, FPR_S = ("A1" * 20, "B2" * 20, "C3" * 20, "D4" * 20)
TWO_KEYS = f"""pub:e:4096:1:{FPR_A[-16:]}:1662463626:1788220800::-:::sc::::::23::0:
fpr:::::::::{FPR_A}:
uid:e::::1662463626::0000000000000000000000000000000000000000::Old key <old@example.invalid>::::::::::0:
pub:-:4096:1:{FPR_B[-16:]}:1775559160:::-:::scSC::::::23::0:
fpr:::::::::{FPR_B}:
uid:-::::1775559160::1111111111111111111111111111111111111111::New key <new@example.invalid>::::::::::0:
"""
WITH_SUBKEY = f"""pub:-:4096:1:{FPR_P[-16:]}:1700000000:::-:::cSC::::::23::0:
fpr:::::::::{FPR_P}:
sub:-:4096:1:{FPR_S[-16:]}:1700000000:1800000000:::::s::::::23:
fpr:::::::::{FPR_S}:
"""


def upkeep(scenario="noble-held"):
    """Keyword arguments for FakeSystem: noble-held as described above."""
    boot = {"vmlinuz-6.8.0-136-generic": 14989704, "initrd.img-6.8.0-136-generic": 76012422,
            "vmlinuz-6.8.0-142-generic": 15030664, "initrd.img-6.8.0-142-generic": 76340119,
            "vmlinuz-6.8.0-146-generic": 15067528, "initrd.img-6.8.0-146-generic": 76568571,
            "vmlinuz-6.8.0-147-generic": 15083912}
    dq = command_text(scenario, "dpkg-query-W").replace(
        "linux-image-6.8.0-147-generic\t6.8.0-147.147\tlinux-signed\tii ", "linux-image-6.8.0-147-generic\t6.8.0-147.147\tlinux-signed\tiF ")
    return {"files": {"/var/log/unattended-upgrades/unattended-upgrades.log": UPKEEP_UU_LOG},
            "results": {"dpkg-query-W": gapsproc.Result(0, dq, ""),
                        "gpg-githubcli-archive-keyring.gpg": gapsproc.Result(0, GITHUB_OLD_KEY, "")},
            "meta": {"dirs": {"/boot": sorted(boot)},
                     "stat": dict({"/boot/" + n: {"type": "file", "mtime": 1792400000, "mode": "644", "uid": 0, "size": size}
                                   for n, size in boot.items()}, **{"/boot/initrd.img-6.8.0-147-generic": None}),
                     "statvfs": {"/boot": [29696 * 4096, 253107 * 4096]}}}


# What the administrator of noble-held acknowledged on 2026-10-19: Docker stays held until the
# maintenance window, and only the provider can fix tsa in the VM.
NOBLE_ACCEPTED = [
    ("held", name, "2026-11-01", "Docker is updated in the maintenance window on 2026-11-01")
    for name in ("containerd.io", "docker-buildx-plugin", "docker-ce", "docker-ce-cli", "docker-ce-rootless-extras",
                 "docker-compose-plugin")
] + [("cpu", "tsa", "2027-01-15", "Only Hetzner can fix it: microcode of the hypervisor")]


def accepted_files(scenario, entries, at="2026-10-19T08:00:00Z"):
    """`files` for FakeSystem: accepted.json as gaps-accept.py writes it,
    acknowledging the findings of the scenario's own scan named by (check,
    label, until, reason)."""
    import gapscheck
    import gapslib as L
    doc = gapscheck.scan(FakeSystem(scenario))
    found = {(c["check"], L.finding_label(f)): (c["check"], f) for c in doc["checks"] if c["check"] in L.FINDING_KEYS
             for f in c.get(L.FINDING_KEYS[c["check"]][0]) or []}
    items = []
    for check, label, until, reason in entries:
        check, f = found[(check, label)]
        items.append({"ref": L.finding_ref(check, f), "check": check, "label": label, "pin": L.finding_pin(check, f),
                      "until": until, "reason": reason, "at": at})
    return {gapscheck.ACCEPTED: json.dumps({"format": 1, "accepted": items}, indent=1)}


class FakeSystem:
    def __init__(self, scenario, uid=None, missing=(), results=None, files=None, now=None, snapd=None, meta=None):
        self.dir = os.path.join(FIXTURES, scenario)
        with open(os.path.join(self.dir, "meta.json")) as f:
            self.meta = json.load(f)
        if files:
            self.meta["files"].update(files)
        for section, values in (meta or {}).items():     # {section of meta.json: entries to set}
            self.meta.setdefault(section, {}).update(values)
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
        if a[:1] == ["gpg"]:     # the keyring it shows: gpg-<file name>, gpg-stdin for an inline key
            return "gpg-" + (os.path.basename(a[-1]) if a[-1].startswith("/") else "stdin")
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
        if a[:3] == ["systemctl", "show", "apt-daily-upgrade.service"]:
            return "systemctl-show-apt-daily-upgrade"
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

    def run_unprivileged(self, argv, limit=120, stdin=None):
        self.unprivileged = getattr(self, "unprivileged", []) + [argv[0]]
        if stdin is not None:
            self.stdin = getattr(self, "stdin", []) + [stdin]
        answer = self.results.get(self._key(argv))
        if callable(answer):        # an answer that depends on the input (keys from a sources file)
            self.calls.append(self._key(argv))
            return answer(stdin)
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
                               st_mtime=float(st["mtime"]), st_uid=st.get("uid", 0), st_size=int(st.get("size", 0)))

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

    def statvfs(self, path):
        """(free, size) in bytes from meta.json's "statvfs", or None (not recorded)."""
        v = (self.meta.get("statvfs") or {}).get(path)
        return tuple(v) if v else None

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
