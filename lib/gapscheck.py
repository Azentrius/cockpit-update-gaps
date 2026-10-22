# SPDX-License-Identifier: Apache-2.0
"""The checks of Update Gaps: where this host misses updates that Cockpit's
"Software Updates" does not show, and why.

Lives in /usr/lib/cockpit-update-gaps (root-owned); gaps-scan.py runs it,
normally inside update-gaps-scan.service (no network). Everything here only
reads: no `apt update`, no install, no restart. The commands are fixed lists
run through gapsproc (fixed PATH without /usr/local, C locale, time limits).

A check returns a dict with "check", "state" and its own fields (see
docs/INTERNALS.md). It never prints prose: the page has the texts in English
and German and addresses the findings by codes.

System is the only thing that touches the machine; the tests replace it with
recorded output of real hosts (test/fixtures/).
"""

import gzip
import http.client
import json
import os
import re
import socket
import stat
import time
from datetime import datetime, timezone

import gapslib as L
import gapsproc
import gapsradar as R

LIMIT = 120             # seconds per command
LISTS = "/var/lib/apt/lists"
PERIODIC = "/var/lib/apt/periodic"
OUTSIDE_DIRS = ("/usr/local/bin", "/usr/local/sbin")
OUTSIDE_GLOB = "/opt"   # /opt/*/bin
MAX_ITEMS = 300         # entries per list in the state file; the rest is counted
STALE_LISTS_H = 48      # package lists older than this are a finding
EOL_SOON_DAYS = 180
RADAR = "/var/lib/update-gaps-radar/radar.json"   # written by update-gaps-radar.service (DynamicUser)
RADAR_MAX = 8 << 20
RADAR_STALE_H = 72      # the radar runs daily; older data is called stale
POCKETS = ("Release", "Security", "Updates", "Backports")
VERSION_RE = re.compile(r"^[0-9][0-9A-Za-z.+~:-]{0,99}$")
PACKAGE_RE = re.compile(r"^[a-z0-9][a-z0-9+.-]{0,99}(:[a-z0-9][a-z0-9-]{0,19})?$")   # name[:arch]
SERIES_RE = re.compile(r"^[a-z]{2,20}$")
CPU_VULN = "/sys/devices/system/cpu/vulnerabilities"
DMI = "/sys/class/dmi/id"
MICROCODE_PKG = {"GenuineIntel": "intel-microcode", "AuthenticAMD": "amd64-microcode"}
FW_LIMIT = 60           # seconds for fwupdmgr (it may first start fwupd through D-Bus)
FW_METADATA_DAYS = 30   # fwupd's metadata older than this are a finding
SNAP_DIR = "/snap"
SNAPD_SOCKET = "/run/snapd.socket"
SNAPD_MAX = 8 << 20
SNAP_FAILED_DAYS = 7    # failed auto-refreshes in this time are a finding


class RadarError(Exception):
    """radar.json is there but not usable (too large, not JSON, other format)."""


class CommandError(Exception):
    """A command the check needs failed, ran out of time or is missing."""

    def __init__(self, argv, result):
        self.argv, self.result = list(argv), result
        tail = (result.err or result.out or "").strip().splitlines()[-3:]
        super().__init__(f"{argv[0]} exited {result.rc}: " + " | ".join(tail)[:300])


class System:
    """The real machine."""

    def run(self, argv, limit=LIMIT):
        return gapsproc.run(argv, limit)

    def run_unprivileged(self, argv, limit=LIMIT, stdin=None):
        return gapsproc.run_unprivileged(argv, limit, stdin)

    def read_bytes(self, path, limit=4 << 20):
        try:
            with open(path, "rb") as f:
                return f.read(limit)
        except OSError:
            return None

    def read(self, path, limit=4 << 20):
        data = self.read_bytes(path, limit)
        return None if data is None else data.decode("utf-8", "replace")

    def listdir(self, path):
        try:
            return sorted(os.listdir(path))
        except OSError:
            return None

    def lstat(self, path):
        try:
            return os.lstat(path)
        except OSError:
            return None

    def readlink(self, path):
        try:
            return os.readlink(path)
        except OSError:
            return None

    def head(self, path, n=128):
        """The first n bytes of a regular file, without following a link and
        without blocking on a FIFO or device; None for anything else."""
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0))
        except OSError:
            return None
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                return None
            return os.read(fd, n)
        except OSError:
            return None
        finally:
            os.close(fd)

    def now(self):
        return datetime.now(timezone.utc)

    def uid(self):
        return os.geteuid()

    def kernel(self):
        return os.uname().release

    def statvfs(self, path):
        """(free bytes for users, size in bytes) of the file system of path, or None."""
        try:
            s = os.statvfs(path)
        except OSError:
            return None
        return s.f_bavail * s.f_frsize, s.f_blocks * s.f_frsize

    def snapd(self, path, limit=20):
        """GET of snapd's REST API over its socket -> the "result" of the
        answer. Only called when snaps are installed: a request starts snapd
        through its socket otherwise."""
        class Conn(http.client.HTTPConnection):
            def connect(self):
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                s.settimeout(limit)
                s.connect(SNAPD_SOCKET)
                self.sock = s

        conn = Conn("localhost", timeout=limit)
        try:
            conn.request("GET", path, headers={"Accept": "application/json"})
            body = conn.getresponse().read(SNAPD_MAX)
        finally:
            conn.close()
        doc = json.loads(body.decode("utf-8", "replace"))
        if not isinstance(doc, dict) or doc.get("type") == "error":
            msg = ((doc.get("result") or {}).get("message") if isinstance(doc, dict) else None) or "error"
            raise ValueError(f"snapd {path}: {msg}"[:200])
        return doc.get("result")


class Context:
    """What several checks share, collected once and cached."""

    def __init__(self, system):
        self.sys = system
        self._cache = {}
        self.results = {}
        self.osr = L.parse_os_release(system.read("/etc/os-release") or "")
        self.root = system.uid() == 0
        self.now = system.now()

    def cmd(self, argv, limit=LIMIT, ok_codes=(0,)):
        r = self.sys.run(argv, limit)
        if r.missing or r.timeout or r.rc not in ok_codes:
            raise CommandError(argv, r)
        return r

    def _cached(self, key, fn):
        if key not in self._cache:
            try:
                self._cache[key] = (True, fn())
            except Exception as e:  # noqa: BLE001 - kept and raised again for every check that needs it
                self._cache[key] = (False, e)
        ok, value = self._cache[key]
        if not ok:
            raise value
        return value

    @property
    def codename(self):
        return self.osr.get("VERSION_CODENAME") or ""

    def installed(self):
        """{name: {version, source, status, arch, installed}} of dpkg."""
        return self._cached("dpkg", lambda: L.parse_dpkg_query(self.cmd(
            ["dpkg-query", "-W", "-f",
             "${binary:Package}\\t${Version}\\t${source:Package}\\t${db:Status-Abbrev}\\t${Architecture}\\n"]).out))

    def installed_names(self):
        return sorted(n for n, p in self.installed().items() if p["installed"])

    def sources(self):
        return self._cached("sources", lambda: L.parse_policy_sources(self.cmd(["apt-cache", "policy"]).out))

    def policy(self):
        """The version tables of every installed package (one call)."""
        def get():
            names = self.installed_names()
            if not names:
                return {}
            # Package names never start with "-" (Debian policy), so none is taken for an option.
            return L.parse_policy_packages(self.cmd(["apt-cache", "policy"] + names, limit=300).out)
        return self._cached("policy", get)

    def pkg(self, name):
        """The version table of an installed package. dpkg names Multi-Arch:
        same packages with their architecture (libc6:amd64), apt-cache policy
        without it for the native one (libc6)."""
        pol = self.policy()
        return pol.get(name) or pol.get(name.split(":")[0])

    def native_arch(self):
        def get():
            counts = {}
            for p in self.installed().values():
                if p["installed"] and p["arch"] not in ("", "all"):
                    counts[p["arch"]] = counts.get(p["arch"], 0) + 1
            return max(counts, key=counts.get) if counts else ""
        return self._cached("arch", get)

    def display(self, name):
        """libc6:amd64 -> libc6 on an amd64 host; foreign architectures stay."""
        base, sep, arch = name.partition(":")
        return base if sep and arch == self.native_arch() else name

    def held(self):
        return self._cached("held", lambda: sorted(set(self.cmd(["apt-mark", "showhold"]).out.split())))

    def simulation(self):
        """What `apt-get dist-upgrade` would do, simulated (no lock: it only reads)."""
        return self._cached("simulation", lambda: L.parse_dist_upgrade(
            self.cmd(["apt-get", "-s", "-o", "Debug::NoLocking=1", "dist-upgrade"]).out))

    def apt_config(self):
        return self._cached("apt-config", lambda: L.parse_apt_config(self.cmd(["apt-config", "dump"]).out))

    def indextargets(self, everything):
        key = "targets-all" if everything else "targets"
        argv = ["apt-get", "indextargets"] + (["--no-release-info"] if everything else [])
        return self._cached(key, lambda: L.parse_deb822(L.strip_credentials(self.cmd(argv).out)))

    def settings(self):
        def get():
            st = self.sys.lstat(L.SETTINGS_FILE)
            if st is None:
                return {"hide_outside": [], "file": None}
            if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
                raise L.SettingsError(f"{L.SETTINGS_FILE} must be a regular file of root, "
                                      "not writable by group or others")
            s = L.parse_settings(self.sys.read(L.SETTINGS_FILE) or "")
            s["file"] = L.SETTINGS_FILE
            return s
        return self._cached("settings", get)

    def radar(self):
        """radar.json of update-gaps-radar.service, or None when the radar is
        not set up. The file comes from an unprivileged service: it is read as
        data, size-limited, and every value used is checked where it is used."""
        def get():
            data = self.sys.read_bytes(RADAR, RADAR_MAX + 1)
            if data is None:
                return None
            if len(data) > RADAR_MAX:
                raise RadarError(f"{RADAR} is larger than {RADAR_MAX} bytes")
            try:
                doc = json.loads(data.decode("utf-8"))
            except ValueError as e:
                raise RadarError(f"{RADAR} is not JSON: {e}"[:200])
            if not isinstance(doc, dict) or doc.get("format") != 1:
                raise RadarError(f"{RADAR} has another format")
            return doc
        return self._cached("radar", get)

    def origin_of(self, key):
        """The release attributes and host of a source key."""
        src = self.sources().get(key) or {}
        return src.get("release") or {}, src.get("origin") or "", src.get("site") or ""


def _cap(items, n=MAX_ITEMS):
    items = list(items)
    return items[:n], max(0, len(items) - n)


def _origin_summary(ctx, key):
    rel, host, site = ctx.origin_of(key)
    return {"site": L.strip_credentials(site), "host": host, "o": rel.get("o", ""), "a": rel.get("a", ""),
            "n": rel.get("n", ""), "l": rel.get("l", ""), "c": rel.get("c", "")}


def newer_versions(pkg):
    """Versions in the table above the installed one that a source offers."""
    inst = pkg.get("installed")
    if not inst:
        return []
    return [v for v in pkg["versions"]
            if L.vercmp(v["version"], inst) > 0 and L.entry_sources(v)]


# ------------------------------------------------------------------ checks --

def check_updates(ctx):
    sim = ctx.simulation()
    sec = sum(1 for i in sim["inst"] if any(L.is_security_origin(o) for o in i["origins"]))
    out = {"count": len(sim["inst"]), "security": sec, "kept_back": sim["kept_back"],
           "phased": sim["phased"], "source": ["apt-get -s dist-upgrade"]}
    out["state"] = "found" if sim["inst"] else "none"
    return out


def _phased_version(pkg):
    """The version apt defers: the candidate when it is phased, else the
    newest phased version above the installed one."""
    inst = pkg.get("installed")
    phased = [v for v in pkg["versions"] if "phased" in v and (not inst or L.vercmp(v["version"], inst) > 0)]
    cand = next((v for v in phased if v["version"] == pkg.get("candidate")), None)
    return cand or (max(phased, key=lambda v: L.Version(v["version"])) if phased else None)


UU_LOG = "/var/log/unattended-upgrades/unattended-upgrades.log"
UU_OLD_H = 72           # the last run of unattended-upgrades older than this is a finding


def check_uu(ctx):
    """Whether the automatic updates really run: the last finished run in
    unattended-upgrades' log (and the one rotated before it), how it ended,
    what it kept back or left for a manual upgrade (a conffile prompt), and
    how apt-daily-upgrade.service last ended (a run that was killed writes
    no end). The configuration is `auto`'s; this is what came of it. The
    log has the host's local time, read as UTC (the servers run in UTC)."""
    p = ctx.installed().get("unattended-upgrades")
    if not (p and p["installed"]):
        return {"state": "skipped", "reason": "tool-missing", "tool": "unattended-upgrades"}
    texts = [ctx.sys.read(UU_LOG + ".1"), ctx.sys.read(UU_LOG)]
    run = L.parse_uu_log("\n".join(t for t in texts if t))
    off = any(f.get("kind") == "disabled" for f in (ctx.results.get("auto") or {}).get("findings") or [])
    findings = []
    if run is None:
        if not off:
            findings.append({"kind": "never", "log": any(t is not None for t in texts)})
    else:
        age_h = round((ctx.now.replace(tzinfo=None) - run["started"]).total_seconds() / 3600, 1)
        if age_h > UU_OLD_H and not off:
            findings.append({"kind": "old", "hours": int(age_h)})
        if run["outcome"] == "failed":
            findings.append({"kind": "failed", "lines": run["errors"]})
        if run["kept_back"]:
            findings.append({"kind": "kept-back", "packages": run["kept_back"]})
        if run["conffile"]:
            findings.append({"kind": "conffile", "packages": run["conffile"]})
    r = ctx.sys.run(["systemctl", "show", "apt-daily-upgrade.service", "-p", "Result"], 30)
    result = (r.out.strip().partition("=")[2] or None) if r.ok else None
    if result not in (None, "success"):
        findings.append({"kind": "service", "result": result[:40]})
    return {"state": "found" if findings else "none", "findings": findings, "off": off,
            "last_run": run["started"].strftime("%Y-%m-%dT%H:%M:%SZ") if run else None,
            "outcome": run["outcome"] if run else None, "upgraded": (run["packages"] if run else [])[:MAX_ITEMS],
            "service": result, "source": [UU_LOG, "systemctl show apt-daily-upgrade.service"]}


BOOT = "/boot"
BOOT_ROOM = 1.5         # free space /boot needs: this many times the largest kernel with its initrd
BOOT_KEEP = 2           # apt autoremove keeps the running kernel and the two newest


def check_boot(ctx):
    """Room in /boot for the next kernel, and old kernels there. When /boot
    is full, a kernel update stops halfway (its initrd cannot be written) and
    leaves dpkg with half-configured packages; Software Updates only reports
    that it failed."""
    kernels = sorted((n[len("vmlinuz-"):] for n in ctx.sys.listdir(BOOT) or [] if n.startswith("vmlinuz-")),
                     key=L.Version)
    if not kernels:
        return {"state": "skipped", "reason": "not-applicable"}     # no kernel of its own (a container)
    # The largest kernel with its initramfs, not the newest: when an update ran out of room, the
    # newest has none.
    size = 0
    for k in kernels:
        sts = [ctx.sys.lstat(f"{BOOT}/{f}") for f in (f"vmlinuz-{k}", f"initrd.img-{k}")]
        size = max(size, sum(st.st_size for st in sts if st is not None and stat.S_ISREG(st.st_mode)))
    need = int(size * BOOT_ROOM) or None
    fs = ctx.sys.statvfs(BOOT)
    findings = []
    if fs and need and fs[0] < need:
        findings.append({"kind": "space", "free": fs[0], "need": need})
    running = ctx.sys.kernel()
    old = [k for k in kernels[:-BOOT_KEEP] if k != running] if len(kernels) > BOOT_KEEP else []
    if old:
        findings.append({"kind": "old-kernels", "kernels": old})
    out = {"state": "found" if findings else "none", "findings": findings, "kernels": kernels, "running": running,
           "free": fs[0] if fs else None, "size": fs[1] if fs else None, "need": need,
           "source": [BOOT, "statvfs " + BOOT]}
    if not fs or not need:
        out["missing"] = ["boot-room"]          # the room could not be measured (no statvfs, no kernel there)
        if out["state"] == "none":
            out["state"] = "partial"
    return out


DPKG_UPDATES = "/var/lib/dpkg/updates"


def check_dpkg(ctx):
    """Packages dpkg left half done (unpacked, half-configured, triggers
    pending, reinstall required), and a dpkg run that was interrupted (its
    journal in /var/lib/dpkg/updates). Every later update fails on them,
    Software Updates included, with a message that does not say why."""
    findings = []
    if any(n.isdigit() for n in ctx.sys.listdir(DPKG_UPDATES) or []):
        findings.append({"kind": "interrupted"})
    for name, p in sorted(ctx.installed().items()):
        state = L.dpkg_problem(p["status"])
        if state:
            findings.append({"kind": "package", "package": ctx.display(name), "version": p["version"], "state": state})
    items, more = _cap(findings)
    out = {"state": "found" if findings else "none", "findings": items, "source": ["dpkg-query -W", DPKG_UPDATES]}
    if more:
        out["more"] = more
    return out


def check_phased(ctx):
    """Updates Ubuntu rolls out in phases that apt defers on this host for
    now ("deferred due to phasing"). Cockpit's Software Updates (PackageKit)
    lists them all the same and refuses them when it installs, and with them
    every other update of the same transaction. With the versions and the
    share of the rollout (`apt-cache policy`) and how apt's configuration
    treats phasing (`apt-config dump`, local)."""
    names = [n for n in ctx.simulation()["phased"] if PACKAGE_RE.match(n)]
    source = ["apt-get -s dist-upgrade"]
    try:
        include, setting = L.phasing_policy(ctx.apt_config())
        source.append("apt-config dump")
    except CommandError:
        include, setting = None, None           # not known: the page offers the setting as one way
    pol = bool(names)
    if names:
        try:
            ctx.policy()
            source.append("apt-cache policy")
        except CommandError:
            pol = False                         # the names are enough to say what fails
    packages = []
    for name in names:
        pkg = (ctx.pkg(name) if pol else None) or {"installed": None, "candidate": None, "versions": []}
        inst = pkg["installed"] if pkg["installed"] and VERSION_RE.match(pkg["installed"]) else None
        entry = _phased_version(pkg)
        version = entry["version"] if entry else pkg["candidate"]
        packages.append({"package": ctx.display(name), "installed": inst,
                         "version": version if version and version != inst and VERSION_RE.match(version) else None,
                         "percent": entry["phased"] if entry else None})
    items, more = _cap(packages)
    out = {"state": "found" if packages else "none", "packages": items, "include": include, "setting": setting,
           "source": source}
    if more:
        out["more"] = more
    return out


def check_held(ctx):
    held = ctx.held()
    log = _dpkg_log(ctx, held)
    findings = []
    for name in held:
        pkg = ctx.pkg(name)
        if not pkg or not pkg.get("installed"):
            continue
        newer = sorted(newer_versions(pkg), key=lambda v: L.Version(v["version"]), reverse=True)
        best = newer[0] if newer else None
        if best:
            keys = L.entry_sources(best)
            security = True if any(L.is_security_origin(ctx.origin_of(k)[0].get("a", "")) for v in newer
                                   for k in L.entry_sources(v)) else None
            if security is None and all(ctx.origin_of(k)[0].get("o") in ("Ubuntu", "Debian") for k in keys):
                security = False
            origin = _origin_summary(ctx, keys[0])
        else:
            security, origin = None, _origin_summary(ctx, (L.entry_sources(L.installed_entry(pkg)) or [""])[0])
        when = log.get(name.split(":")[0])
        findings.append({"package": ctx.display(name), "installed": pkg["installed"],
                         "candidate": best["version"] if best else None, "newer": len(newer),
                         "security": security, "origin": origin,
                         "installed_at": when[0] if when and when[1] == pkg["installed"] else None})
    return {"state": "found" if findings else "none", "findings": findings,
            "source": ["apt-mark showhold", "apt-cache policy"]}


def _dpkg_log(ctx, names):
    if not names:
        return {}
    want = {n.split(":")[0] for n in names}
    lines = []
    for f in sorted(n for n in (ctx.sys.listdir("/var/log") or []) if re.match(r"^dpkg\.log(\.\d+)?(\.gz)?$", n)):
        path = "/var/log/" + f
        if f.endswith(".gz"):
            text = _gunzip(ctx.sys.read_bytes(path, 32 << 20))
        else:
            text = ctx.sys.read(path, 32 << 20)
        for line in (text or "").splitlines():
            parts = line.split(" ", 4)
            if len(parts) > 3 and parts[2] in ("install", "upgrade") and parts[3].split(":")[0] in want:
                lines.append(line)
    return L.parse_dpkg_log(lines)


def _gunzip(data):
    if not data:
        return None
    try:
        return gzip.decompress(data).decode("utf-8", "replace")
    except (OSError, EOFError):
        return None


def check_pro(ctx):
    if (ctx.osr.get("ID") or "").lower() != "ubuntu":
        return {"state": "skipped", "reason": "not-applicable"}
    # Without root: as root pro insists on writing its log and lock, see gapsproc.run_unprivileged.
    r = ctx.sys.run_unprivileged(["pro", "security-status", "--format", "json"], LIMIT)
    if r.missing:
        return {"state": "skipped", "reason": "tool-missing", "tool": "pro"}
    if r.timeout or r.rc != 0:
        raise CommandError(["pro"], r)
    doc = json.loads(r.out)
    summary = doc.get("summary") or {}
    ua = summary.get("ua") or {}
    inst = ctx.installed()
    findings = []
    for p in doc.get("packages") or []:
        if not isinstance(p, dict) or p.get("status") == "upgrade_available":
            continue
        name = str(p.get("package") or "")
        findings.append({"package": name, "version": p.get("version"), "service": p.get("service_name"),
                         "status": p.get("status"),
                         "installed": (inst.get(name) or {}).get("version")})
    findings.sort(key=lambda f: (str(f["service"]), f["package"]))
    counts = {k[4:]: v for k, v in summary.items() if k.startswith("num_") and isinstance(v, int)}
    return {"state": "found" if findings else "none", "findings": findings,
            "attached": bool(ua.get("attached")), "services": list(ua.get("enabled_services") or []),
            "counts": counts, "source": ["pro security-status --format json"]}


def check_restart(ctx):
    out = {"source": [], "kernel": None, "microcode": None, "services": [], "reboot_required": None, "tool": None}
    missing = []
    r = ctx.sys.run(["needrestart", "-b", "-r", "l"], LIMIT)
    if r.missing:
        missing.append("needrestart")
    elif r.timeout or r.rc not in (0, 1, 2, 3):
        raise CommandError(["needrestart"], r)
    else:
        nr = L.parse_needrestart(r.out)
        out.update(kernel=nr["kernel"], microcode=nr["microcode"], services=nr["services"],
                   tool="needrestart " + (nr["version"] or "?"))
        out["source"].append("needrestart -b -r l")
        if not ctx.root:
            missing.append("services")
    if out["kernel"] is None:
        running = ctx.sys.kernel()
        kernels = [n[len("vmlinuz-"):] for n in (ctx.sys.listdir("/boot") or []) if n.startswith("vmlinuz-")]
        newest = max(kernels, key=L.Version) if kernels else None
        if newest:
            out["kernel"] = {"running": running, "expected": newest,
                             "state": 1 if newest == running else 3 if L.vercmp(newest, running) > 0 else 0}
            out["source"].append("uname -r, /boot")
    st = ctx.sys.lstat("/var/run/reboot-required")
    if st is not None:
        pkgs = (ctx.sys.read("/var/run/reboot-required.pkgs") or "").split()
        out["reboot_required"] = {"since": L.iso_ts(st.st_mtime), "packages": sorted(set(pkgs))}
        out["source"].append("/var/run/reboot-required")
    k = out["kernel"] or {}
    mc = out["microcode"] or {}
    pending = (k.get("state") in (2, 3)) or mc.get("state") == 2 or out["services"] or out["reboot_required"]
    out["state"] = "found" if pending else "none"
    if missing:
        out["missing"] = missing
        if out["state"] == "none":
            out["state"] = "partial"
    return out


def check_lists(ctx):
    every = ctx.indextargets(True)
    have = ctx.indextargets(False)
    conf = {}
    for rec in every:
        key = (rec.get("Site", ""), rec.get("Release", ""))
        conf.setdefault(key, rec.get("Sourcesentry", ""))
    with_release = {(r.get("Site", ""), r.get("Release", "")) for r in have}
    findings = []
    for (site, release), entry in sorted(conf.items()):
        if (site, release) not in with_release:
            findings.append({"kind": "missing", "site": site, "release": release, "entry": entry})
    # Index files that no configured source names any more (a source was moved or removed and
    # `apt update` has not run since; apt removes them on its next run).
    names = {os.path.basename(r.get("Filename", "")) for r in every}
    bases = set()
    for r in every:
        fn = os.path.basename(r.get("Filename", ""))
        if "_dists_" in fn:
            bases.add(fn.split("_dists_")[0] + "_dists_" + r.get("Release", "").replace("/", "_"))
    orphaned = {}
    for f in ctx.sys.listdir(LISTS) or []:
        if f in ("lock", "partial", "auxfiles"):
            continue
        plain = re.sub(r"\.(gz|xz|lz4|zst|bz2|lzma)$", "", f)
        if plain in names:
            continue
        m = re.match(r"^(.*_dists_.*)_(InRelease|Release|Release\.gpg)$", f)
        if m and m.group(1) in bases:
            continue
        host = f.split("_dists_")[0].replace("_", "/") if "_dists_" in f else f.split("_")[0]
        orphaned[host] = orphaned.get(host, 0) + 1
    for host, n in sorted(orphaned.items()):
        findings.append({"kind": "orphaned", "site": host, "files": n})
    last = None
    for path, src in ((PERIODIC + "/update-success-stamp", "update-success-stamp"),
                      (LISTS + "/partial", "lists-partial")):
        st = ctx.sys.lstat(path)
        if st is not None:
            last = {"ts": L.iso_ts(st.st_mtime), "src": src}
            break
    daily = _apt_daily(ctx)
    if last is None and daily.get("finished"):
        last = {"ts": daily["finished"], "src": "apt-daily"}
    if last:
        age_h = (ctx.now - datetime.strptime(last["ts"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
                 ).total_seconds() / 3600
        last["age_h"] = round(age_h, 1)
        if age_h > STALE_LISTS_H:
            findings.append({"kind": "old", "hours": int(age_h)})
    indexes = []
    for f in ctx.sys.listdir(LISTS) or []:
        if not (f.endswith("_InRelease") or f.endswith("_Release")):
            continue
        text = ctx.sys.read(LISTS + "/" + f, 1 << 16) or ""
        date = _field(text, "Date")
        until = _field(text, "Valid-Until")
        d, u = L.parse_release_date(date), L.parse_release_date(until)
        indexes.append({"file": f, "date": L.iso(d) if d else None, "valid_until": L.iso(u) if u else None})
        if u and u < ctx.now:
            findings.append({"kind": "expired", "file": f, "valid_until": L.iso(u)})
    if daily.get("result") not in (None, "success"):
        findings.append({"kind": "apt-daily", "result": daily["result"], "lines": daily.get("lines", [])})
    elif daily.get("lines"):
        findings.append({"kind": "apt-daily", "result": daily.get("result"), "lines": daily["lines"]})
    out = {"state": "found" if findings else "none", "findings": findings, "last_update": last,
           "apt_daily": {k: daily.get(k) for k in ("finished", "result")}, "indexes": indexes,
           "stale_after_h": STALE_LISTS_H,
           "source": ["apt-get indextargets", "/var/lib/apt/lists", "/var/lib/apt/periodic"]}
    if not ctx.root:
        out["missing"] = ["journal"]
        if out["state"] == "none":
            out["state"] = "partial"
    return out


KEYS_SOON_DAYS = 60     # a keyring whose last signing key expires within this many days is a finding
TRUSTED = "/etc/apt/trusted.gpg"
TRUSTED_D = "/etc/apt/trusted.gpg.d"
# Without --no-options: it would keep gpg from creating its home (a fresh one, see gapsproc.run_unprivileged).
# The fingerprints of subkeys, too, for the keys Signed-By selects (gpg 2.4 prints them anyway, 2.2 only so).
GPG_SHOW = ["gpg", "--batch", "--no-autostart", "--with-colons", "--with-subkey-fingerprint", "--show-keys"]


class _NoGpg(Exception):
    pass


def check_keys(ctx):
    """The keys apt checks the signatures of the enabled sources with, and
    when they expire. Once the last signing key of a source's keyring has
    expired, apt stops reading that source: its updates drop out of every
    list, Software Updates included, and only `apt update` warns. The
    keyrings are those of Signed-By, else apt's trusted ones, with only the
    keys Signed-By selects by fingerprint (sources.list(5)): sources that
    share a keyring file may select from it differently, so each selection
    is a keyring of its own. gpg reads them without root and imports
    nothing."""
    files = sorted({r.get("Sourcesentry", "").rpartition(":")[0] for r in ctx.indextargets(True)} - {""})
    rings, selected, inline, default_sites, unchecked, findings = {}, {}, {}, [], [], []
    for path in files:
        text = ctx.sys.read(path)
        if text is None:
            unchecked.append({"file": path, "reason": "unreadable"})
            continue
        for e in L.sources_keyrings(text, path.endswith(".sources")):
            sites = [L.strip_credentials(u) for u in e["uris"]]
            if e["inline"]:
                inline.setdefault((path, e["inline"]), []).extend(sites)
            elif e["select"]:
                selected.setdefault((tuple(e["keyrings"]), tuple(e["select"])), []).extend(sites)
            elif e["keyrings"]:
                for k in e["keyrings"]:
                    rings.setdefault(k, []).extend(sites)
            else:
                default_sites.extend(sites)
    trusted = []
    if default_sites or any(not paths for paths, _ in selected):
        trusted = [TRUSTED] if ctx.sys.lstat(TRUSTED) is not None else []
        trusted += [f"{TRUSTED_D}/{n}" for n in ctx.sys.listdir(TRUSTED_D) or [] if n.endswith((".gpg", ".asc"))]
    shown, keyrings = {}, []

    def show(path=None, key=None):
        """gpg's view of a keyring file (once per file) or of a key from a sources file."""
        if key is None and path in shown:
            return shown[path]
        r = ctx.sys.run_unprivileged(GPG_SHOW + ([] if key else [path]), 30, key.encode("utf-8") if key else None)
        if r.missing:
            raise _NoGpg()
        if key is None:
            shown[path] = r
        return r

    def judge(ring, until):
        ring["expires"] = "never" if until == "never" else L.iso(until)
        keyrings.append(ring)
        days = None if until == "never" else (until - ctx.now).total_seconds() / 86400
        if days is not None and days < 0:
            findings.append(dict(ring, kind="expired"))
        elif days is not None and days <= KEYS_SOON_DAYS:
            findings.append(dict(ring, kind="expires", days=int(days)))

    def whole(ring, path):
        """A keyring file with every key it holds."""
        if ctx.sys.lstat(path) is None:
            findings.append(dict(ring, kind="missing"))     # apt cannot check the source and leaves it out
            return
        r = show(path)
        until = None if r.timeout else L.keyring_expiry(r.out)
        if until is None:
            unchecked.append({"file": path, "reason": "no-key" if r.out.strip() else "unreadable"})
        else:
            judge(ring, until)

    def chosen(paths, select, sites):
        """The keys Signed-By selects by fingerprint, from its files or (none named) from apt's trusted
        ones: valid while one of them is."""
        base = dict({"select": list(select), "sources": sorted(set(sites))[:20]}, **({} if paths else {"default": True}))
        keys, read = [], False
        for path in paths or trusted:
            if paths and ctx.sys.lstat(path) is None:
                findings.append(dict(base, file=path, kind="missing"))
                continue
            r = show(path)
            if r.timeout or not r.out.strip():
                unchecked.append({"file": path, "reason": "unreadable"})
                continue
            read = True
            keys += [dict(k, file=path) for k in L.keyring_keys(r.out)]
        signing = [k for k in L.select_keys(keys, select) if k["sign"] and not k["revoked"]]
        if signing:
            # Named by the file of the selected key that lasts longest (the first of them on a tie).
            judge(dict(base, file=max(signing, key=lambda k: k["until"])["file"]), L.keys_expiry(signing))
        elif read or not (paths or trusted):
            unchecked.append({"file": paths[0] if paths else TRUSTED_D, "reason": "no-selected-key", "select": list(select)})

    def embedded(path, key, sites):
        """A key in a sources file itself (deb822 Signed-By), named by its fingerprints."""
        ring = {"file": path, "inline": True, "sources": sorted(set(sites))[:20]}
        r = show(key=key)
        keys = [] if r.timeout else L.keyring_keys(r.out)
        fprs = [k["fpr"] for k in keys if k["fpr"] and k["fpr"] == k["primary"]]
        if fprs:
            ring["fingerprints"] = fprs
        until = L.keys_expiry(keys)
        if until is None:
            unchecked.append({"file": path, "reason": "no-key" if r.out.strip() else "unreadable"})
        else:
            judge(ring, until)

    try:
        for path, sites in sorted(rings.items()):
            whole({"file": path, "sources": sorted(set(sites))[:20]}, path)
        for (paths, select), sites in sorted(selected.items()):
            chosen(paths, select, sites)
        for (path, key), sites in inline.items():
            embedded(path, key, sites)
        # Entries without Signed-By: apt trusts every key of its trusted keyrings for them.
        for path in trusted if default_sites else []:
            if path not in rings:
                whole({"file": path, "default": True, "sources": sorted(set(default_sites))[:20]}, path)
    except _NoGpg:
        return {"state": "skipped", "reason": "tool-missing", "tool": "gpg"}
    out = {"state": "found" if findings else "none", "findings": findings, "keyrings": keyrings,
           "soon_days": KEYS_SOON_DAYS, "source": ["apt-get indextargets", "Signed-By", "gpg --show-keys"]}
    unchecked = [u for i, u in enumerate(unchecked) if u not in unchecked[:i]]     # a file named twice, once
    if unchecked:
        out["unchecked"] = unchecked
        out["missing"] = ["keyrings"]
        if out["state"] == "none":
            out["state"] = "partial"
    return out


def _field(text, name):
    m = re.search(r"^" + re.escape(name) + r":\s*(.+)$", text, re.M)
    return m.group(1).strip() if m else None


APT_PROBLEM_RE = re.compile(r"^(W|E|Err):|\b(error|failed|could not|unable to|NO_PUBKEY|expired)\b", re.I)


def _apt_daily(ctx):
    """When apt-daily.service last ended, how, and the messages of its last
    run that did not come from systemd (apt's warnings and errors)."""
    out = {}
    r = ctx.sys.run(["systemctl", "show", "apt-daily.service", "-p", "Result", "-p", "ExecMainExitTimestamp"], 30)
    if r.ok:
        props = dict(line.split("=", 1) for line in r.out.splitlines() if "=" in line)
        out["result"] = props.get("Result") or None
        ts = (props.get("ExecMainExitTimestamp") or "").strip()
        if ts:
            try:
                dt = datetime.strptime(" ".join(ts.split()[1:3]), "%Y-%m-%d %H:%M:%S")
                out["finished"] = L.iso(dt.replace(tzinfo=timezone.utc)) if ts.endswith("UTC") else None
            except (ValueError, IndexError):
                pass
    if ctx.root:
        r = ctx.sys.run(["journalctl", "-u", "apt-daily.service", "--since", "-3d", "-o", "short-iso",
                         "--no-pager", "-q"], 60)
        if r.ok:
            lines = r.out.splitlines()
            start = max((i for i, ln in enumerate(lines) if "Starting apt-daily.service" in ln), default=None)
            if start is not None:
                msgs = []
                for ln in lines[start + 1:]:
                    if " systemd[1]: " in ln:
                        continue
                    msg = ln.split(": ", 1)[1] if ": " in ln else ln
                    if APT_PROBLEM_RE.search(msg):
                        msgs.append(L.strip_credentials(msg)[:300])
                out["lines"] = msgs[-20:]
    return out


def check_local(ctx):
    missing_lists = any(f.get("kind") == "missing" for f in
                        (ctx.results.get("lists") or {}).get("findings", []))
    findings = []
    inst = ctx.installed()
    for name in ctx.installed_names():
        entry = L.installed_entry(ctx.pkg(name))
        if entry is None or L.entry_sources(entry):
            continue
        findings.append({"package": ctx.display(name), "version": inst[name]["version"], "arch": inst[name]["arch"],
                         "cause": "lists-missing" if missing_lists else "no-source"})
    items, more = _cap(findings)
    out = {"state": "found" if findings else "none", "findings": items,
           "source": ["apt-cache policy", "dpkg-query"]}
    if more:
        out["more"] = more
    return out


def check_auto(ctx):
    inst = ctx.installed()
    conf = ctx.apt_config()
    did, code = L.distro_id(ctx.osr), ctx.codename
    allowed = [L.uu_expand(v, did, code) for v in conf.get("Unattended-Upgrade::Allowed-Origins", [])]
    patterns = [L.uu_expand(v, did, code) for v in conf.get("Unattended-Upgrade::Origins-Pattern", [])]
    blacklist = conf.get("Unattended-Upgrade::Package-Blacklist", [])
    matchers = [L.uu_allowed_to_pattern(a) for a in allowed] + [L.uu_pattern(p) for p in patterns]
    uu = (inst.get("unattended-upgrades") or {}).get("installed", False)
    periodic = {"update_lists": L.config_scalar(conf, "APT::Periodic::Update-Package-Lists"),
                "unattended": L.config_scalar(conf, "APT::Periodic::Unattended-Upgrade")}
    r = ctx.sys.run(["systemctl", "is-enabled", "apt-daily-upgrade.timer"], 30)
    timer = (r.out.strip().splitlines() or ["unknown"])[0] if not r.missing else "unknown"
    findings = []
    if not uu:
        findings.append({"kind": "disabled", "what": "not-installed"})
    elif periodic["unattended"] in (None, "0", "false", "no"):
        findings.append({"kind": "disabled", "what": "periodic-off"})
    elif timer not in ("enabled", "static", "alias", "indirect", "generated", "unknown"):
        findings.append({"kind": "disabled", "what": "timer-off", "timer": timer})

    seen = {}

    def covered(key):
        if key not in seen:
            rel, host, _ = ctx.origin_of(key)
            seen[key] = any(m and L.uu_match(m, rel, host) for m in matchers)
        return seen[key]

    groups = {}
    for name in ctx.installed_names():
        entry = L.installed_entry(ctx.pkg(name))
        keys = L.entry_sources(entry)
        if not keys or any(covered(k) for k in keys):
            continue
        o = _origin_summary(ctx, keys[0])
        g = groups.setdefault((o["site"], o["o"], o["a"]), dict(o, packages=[]))
        g["packages"].append(ctx.display(name))
    for _, g in sorted(groups.items()):
        g["packages"], more = _cap(g["packages"])
        if more:
            g["more"] = more
        findings.append(dict(kind="source", **g))
    for pat in blacklist:
        try:
            rx = re.compile(pat)
        except re.error:
            findings.append({"kind": "blacklist", "pattern": pat, "packages": [], "invalid": True})
            continue
        hits = [ctx.display(n) for n in ctx.installed_names() if rx.match(n.split(":")[0])]
        if hits:
            hits, more = _cap(hits)
            findings.append({"kind": "blacklist", "pattern": pat, "packages": hits, **({"more": more} if more else {})})
    held = ctx.held()
    if held:
        findings.append({"kind": "held", "packages": held})
    return {"state": "found" if findings else "none", "findings": findings, "installed": uu,
            "periodic": periodic, "timer": timer, "allowed": allowed, "patterns": patterns,
            "blacklist": blacklist, "source": ["apt-config dump", "apt-cache policy"]}


def check_backports(ctx):
    inst = ctx.installed()
    held = set(ctx.held())
    groups = {}
    for name in ctx.installed_names():
        if name in held or name.split(":")[0] in held:
            continue
        pkg = ctx.pkg(name)
        entry = L.installed_entry(pkg)
        if entry is None:
            continue
        if any(ctx.origin_of(k)[0].get("a", "").endswith("-backports") for k in L.entry_sources(entry)):
            continue
        if pkg.get("candidate") and L.vercmp(pkg["candidate"], pkg["installed"]) > 0:
            continue
        best = None
        for v in newer_versions(pkg):
            suites = [ctx.origin_of(k)[0].get("a", "") for k in L.entry_sources(v)]
            if any(s.endswith("-backports") for s in suites):
                if best is None or L.vercmp(v["version"], best[0]) > 0:
                    best = (v["version"], next(s for s in suites if s.endswith("-backports")))
        if not best:
            continue
        src = inst[name]["source"]
        g = groups.setdefault(src, {"source": src, "packages": [], "installed": pkg["installed"],
                                    "backport": best[0], "suite": best[1]})
        g["packages"].append(ctx.display(name))
    findings = [groups[k] for k in sorted(groups)]
    return {"state": "found" if findings else "none", "findings": findings,
            "source": ["apt-cache policy"]}


def check_outside(ctx):
    settings = ctx.settings()
    hide = settings["hide_outside"]
    dirs = list(OUTSIDE_DIRS)
    for d in ctx.sys.listdir(OUTSIDE_GLOB) or []:
        p = f"{OUTSIDE_GLOB}/{d}/bin"
        st = ctx.sys.lstat(p)
        if st is not None and stat.S_ISDIR(st.st_mode):
            dirs.append(p)
    entries = []
    for d in dirs:
        for n in ctx.sys.listdir(d) or []:
            entries.append(f"{d}/{n}")
    owned = _dpkg_owners(ctx, entries)
    out_dirs, hidden_paths = [], []
    for d in dirs:
        files = []
        for n in ctx.sys.listdir(d) or []:
            p = f"{d}/{n}"
            if p in owned:
                continue
            if L.hidden(p, hide):
                hidden_paths.append(p)
                continue
            st = ctx.sys.lstat(p)
            if st is None:
                continue
            files.append(_describe(ctx, p, n, st))
        if files:
            items, more = _cap(files)
            out_dirs.append({"dir": d, "files": items, **({"more": more} if more else {})})
    out = {"state": "found" if out_dirs else "none", "dirs": out_dirs, "hidden": len(hidden_paths),
           "hidden_paths": sorted(set(h for h in hide)), "settings": settings.get("file"),
           "source": ["/usr/local/bin", "/usr/local/sbin", "/opt/*/bin", "dpkg -S"]}
    return out


def _dpkg_owners(ctx, paths):
    if not paths:
        return set()
    r = ctx.sys.run(["dpkg-query", "-S"] + paths, 60)
    owned = set()
    for line in (r.out or "").splitlines():
        if ": " in line:
            for p in line.split(": ", 1)[1].split(", "):
                owned.add(p.strip())
    return owned


def _describe(ctx, path, name, st):
    entry = {"name": name, "mtime": L.iso_ts(st.st_mtime)}
    if stat.S_ISLNK(st.st_mode):
        entry["kind"] = "link"
        entry["target"] = ctx.sys.readlink(path)
        return entry
    if not stat.S_ISREG(st.st_mode):
        entry["kind"] = "other"
        return entry
    head = ctx.sys.head(path, 128) or b""
    if head.startswith(b"#!"):
        line = head[2:].split(b"\n", 1)[0].decode("utf-8", "replace").strip()
        words = line.split()
        interp = words[0] if words else ""
        if interp.endswith("/env") and len(words) > 1:
            interp = words[1]
        entry["kind"] = "script"
        entry["interpreter"] = os.path.basename(interp)[:40]
    elif head.startswith(b"\x7fELF"):
        entry["kind"] = "binary"
    else:
        entry["kind"] = "other"
    return entry


def check_eol(ctx):
    ident = (ctx.osr.get("ID") or "").lower()
    if ident not in ("ubuntu", "debian"):
        return {"state": "skipped", "reason": "not-applicable"}
    text = ctx.sys.read(f"/usr/share/distro-info/{ident}.csv")
    if text is None:
        return {"state": "skipped", "reason": "tool-missing", "tool": "distro-info-data"}
    rows = L.parse_distro_info(text)
    row = next((r for r in rows if (r.get("series") or "") == ctx.codename), None)
    if row is None:
        return {"state": "skipped", "reason": "unknown-release"}
    if ident == "ubuntu":
        std = L.parse_date(row.get("eol-server") or "") or L.parse_date(row.get("eol") or "")
        ext = L.parse_date(row.get("eol-esm") or "")
    else:
        std = L.parse_date(row.get("eol") or "")
        ext = L.parse_date(row.get("eol-lts") or "")
    today = ctx.now.date()
    out = {"release": row.get("version"), "codename": ctx.codename,
           "standard_until": std.isoformat() if std else None,
           "extended_until": ext.isoformat() if ext else None,
           "days_left": (std - today).days if std else None,
           "source": [f"/usr/share/distro-info/{ident}.csv"]}
    if std is None:
        out["state"] = "none"
    elif std < today:
        out["state"], out["kind"] = "found", "ended"
    elif (std - today).days <= EOL_SOON_DAYS:
        out["state"], out["kind"] = "found", "soon"
    else:
        out["state"] = "none"
    return out


# ------------------------------------------------------ stage 3: the machine --

def machine(ctx):
    """{"kind": metal|vm|container|unknown, "virt": what systemd-detect-virt
    printed}. A VM gets its microcode and firmware from the hypervisor."""
    def get():
        r = ctx.sys.run(["systemd-detect-virt"], 20)
        lines = (r.out or "").split()
        virt = lines[0] if lines and not (r.missing or r.timeout) and r.rc in (0, 1) else ""
        if not virt and any(ctx.sys.lstat(p) is not None for p in ("/.dockerenv", "/run/.containerenv")):
            virt = "container-other"      # a container without systemd (docker run, podman)
        return {"kind": L.machine_kind(virt), "virt": virt if L.VIRT_RE.match(virt) else None}
    return ctx._cached("machine", get)


def _dmi(ctx):
    out = {}
    for key in ("sys_vendor", "product_name", "board_vendor", "board_name", "bios_vendor", "bios_version", "bios_date"):
        v = L.dmi_value(ctx.sys.read(f"{DMI}/{key}", 256))
        if v:
            out[key] = v
    if "bios_date" in out:
        out["bios_date"] = L.dmi_date(out["bios_date"]) or out["bios_date"]
    return out


def _microcode_package(ctx, name):
    """The microcode package for this CPU: installed version and what the
    sources offer (None: no source has it; on Debian it is in the component
    non-free-firmware)."""
    p = ctx.installed().get(name)
    if p and p["installed"]:
        pol = ctx.pkg(name) or {}
        return {"name": name, "installed": p["version"], "candidate": pol.get("candidate")}
    r = ctx.sys.run(["apt-cache", "policy", name], LIMIT)
    if r.missing or r.timeout or r.rc != 0:
        return {"name": name, "installed": None, "candidate": None, "available": None}
    cand = (L.parse_policy_packages(r.out).get(name) or {}).get("candidate")
    return {"name": name, "installed": None, "candidate": cand, "available": bool(cand)}


def check_cpu(ctx):
    """What the kernel says about the CPU vulnerabilities it knows, quoted:
    vulnerable, only partly mitigated, unknown. In a VM a missing microcode
    is the provider's to fix; on a physical server the microcode package and
    the BIOS are this server's. Newer microcode waiting for a restart stays in
    `restart`."""
    m = machine(ctx)
    if m["kind"] == "container":
        return {"state": "skipped", "reason": "container", "virt": m["virt"]}
    names = ctx.sys.listdir(CPU_VULN)
    if names is None:
        return {"state": "skipped", "reason": "not-applicable"}
    findings, mitigated, unaffected = [], 0, 0
    for n in names:
        if not L.VULN_NAME_RE.match(n):
            continue
        text = L.clean_text(ctx.sys.read(f"{CPU_VULN}/{n}", 1024), 300)
        kind = L.classify_vulnerability(text)
        if kind == "not-affected":
            unaffected += 1
            continue
        if kind == "mitigated":
            mitigated += 1
            continue
        low = text.lower()
        hw = "microcode" in low or "hypervisor" in low
        findings.append({"name": n, "text": text, "kind": kind, "microcode": "microcode" in low,
                         "fix": "provider" if m["kind"] == "vm" and hw else "here"})
    out = {"machine": m["kind"], "virt": m["virt"],
           "cpu": L.parse_cpuinfo(ctx.sys.read("/proc/cpuinfo", 4 << 20)),
           "findings": findings, "mitigated": mitigated, "not_affected": unaffected,
           "mitigations_off": L.mitigations_off(ctx.sys.read("/proc/cmdline", 4096)),
           "source": [CPU_VULN, "/proc/cpuinfo", "/proc/cmdline", "systemd-detect-virt"]}
    if m["kind"] == "metal":
        out["firmware"] = _dmi(ctx)
        out["source"].append(DMI)
        pkg = MICROCODE_PKG.get(out["cpu"]["vendor"] or "")
        if pkg:
            out["microcode_package"] = _microcode_package(ctx, pkg)
            out["source"].append("apt-cache policy " + pkg)
    mc = (ctx.results.get("restart") or {}).get("microcode")
    out["microcode_pending"] = isinstance(mc, dict) and mc.get("state") == 2
    no_pkg = bool(out.get("microcode_package")) and not out["microcode_package"]["installed"]
    out["state"] = "found" if findings or out["mitigations_off"] or no_pkg else "none"
    return out


def check_firmware(ctx):
    """Firmware updates fwupd knows from its local metadata (fwupd fetches
    them itself, with fwupd-refresh.timer); nothing goes to the network here.
    Without fwupd the check says so: Cockpit has no page for firmware."""
    m = machine(ctx)
    if m["kind"] == "container":
        return {"state": "skipped", "reason": "container", "virt": m["virt"]}
    p = ctx.installed().get("fwupd")
    if not (p and p["installed"]):
        return {"state": "skipped", "reason": "tool-missing", "tool": "fwupd", "machine": m["kind"]}
    argv = ["fwupdmgr", "get-updates", "--json", "--no-unreported-check", "--no-metadata-check"]
    r = ctx.sys.run(argv, FW_LIMIT)
    if r.missing or r.timeout or r.rc not in (0, 2):
        raise CommandError(argv, r)
    updates = L.parse_fwupd_updates(r.out) if r.rc == 0 else []    # 2: nothing to update
    findings = [dict(kind="update", **u) for u in updates[:MAX_ITEMS]]
    rr = ctx.sys.run(["fwupdmgr", "get-remotes", "--json"], FW_LIMIT)
    remotes = []
    if not (rr.missing or rr.timeout) and rr.rc == 0:
        remotes = L.parse_fwupd_remotes(rr.out)
        download = [x for x in remotes if x["enabled"] and x["kind"] == "download"]
        if not download:
            findings.append({"kind": "no-remote"})
        for x in download:
            days = int((ctx.now.timestamp() - x["mtime"]) // 86400) if x["mtime"] else None
            x["age_days"] = days
            if days is not None and days > FW_METADATA_DAYS:
                findings.append({"kind": "metadata-old", "remote": x["id"], "days": days})
    t = ctx.sys.run(["systemctl", "is-enabled", "fwupd-refresh.timer"], 20)
    timer = (t.out or "").split()[0] if not (t.missing or t.timeout) and (t.out or "").split() else None
    if timer and timer not in ("enabled", "static", "indirect", "alias", "generated"):
        findings.append({"kind": "refresh-off", "timer": timer[:20]})
    return {"state": "found" if findings else "none", "findings": findings, "machine": m["kind"],
            "remotes": [{k: x.get(k) for k in ("id", "enabled", "kind", "age_days")} for x in remotes][:10],
            "timer": timer[:20] if timer else None,
            "source": ["fwupdmgr get-updates --json", "fwupdmgr get-remotes --json",
                       "systemctl is-enabled fwupd-refresh.timer"]}


def installed_snaps(ctx):
    """The snaps in /snap (a folder with a current revision)."""
    out = []
    for n in ctx.sys.listdir(SNAP_DIR) or []:
        if n != "bin" and L.SNAP_NAME_RE.match(n) and ctx.sys.lstat(f"{SNAP_DIR}/{n}/current") is not None:
            out.append(n)
    return out


def _series_eol(ctx):
    """{series: (release, end of standard support, end of ESM)} of Ubuntu."""
    rows = L.parse_distro_info(ctx.sys.read("/usr/share/distro-info/ubuntu.csv") or "")
    return {r.get("series") or "": (r.get("version") or "", L.parse_date(r.get("eol-server") or "") or
                                    L.parse_date(r.get("eol") or ""), L.parse_date(r.get("eol-esm") or ""))
            for r in rows}


def _until(dt):
    """A hold until a time snapd calls forever (year 2200 and later) -> None."""
    return None if dt.year >= 2200 else L.iso(dt)


def check_snaps(ctx):
    """Why snaps are not refreshed: held (one snap or all), refreshes failing
    or put off while an app runs, a base whose Ubuntu release is out of
    support. snapd refreshes by itself several times a day, so a newer
    version in the Store is no gap. Without snaps snapd is not asked at all
    (a request would start it through its socket)."""
    snapd = ctx.sys.lstat("/usr/bin/snap") is not None
    names = installed_snaps(ctx)
    if not names:
        return {"state": "none", "snapd": snapd, "installed": 0, "source": [SNAP_DIR]}
    snaps = ctx.sys.snapd("/v2/snaps") or []
    info = ctx.sys.snapd("/v2/system-info") or {}
    changes = ctx.sys.snapd("/v2/changes?select=all") or []
    now, today = ctx.now, ctx.now.date()
    eol = _series_eol(ctx)
    findings, listed = [], []
    for s in snaps if isinstance(snaps, list) else []:
        if not isinstance(s, dict) or not L.SNAP_NAME_RE.match(str(s.get("name") or "")):
            continue
        name, kind = s["name"], s.get("type") if isinstance(s.get("type"), str) else "app"
        base = s.get("base") if isinstance(s.get("base"), str) else ("core" if kind == "app" else None)
        listed.append({"name": name, "version": L.clean_text(str(s.get("version") or ""), 40),
                       "channel": L.clean_text(str(s.get("tracking-channel") or s.get("channel") or ""), 60),
                       "type": kind[:20], "base": base})
        hold = L.parse_rfc3339(s.get("hold"))
        if hold and hold > now:
            findings.append({"kind": "held", "snap": name, "until": _until(hold)})
        inhibit = s.get("refresh-inhibit") if isinstance(s.get("refresh-inhibit"), dict) else None
        if inhibit:
            proceed = L.parse_rfc3339(inhibit.get("proceed-time"))
            findings.append({"kind": "inhibited", "snap": name, "until": L.iso(proceed) if proceed else None})
        series = L.SNAP_BASES.get(base or "")
        if kind == "app" and series in eol:
            release, std, esm = eol[series]
            if std and std < today:
                findings.append({"kind": "old-base", "snap": name, "base": base, "release": release,
                                 "ended": std.isoformat(), "esm_until": esm.isoformat() if esm else None})
    refresh = info.get("refresh") if isinstance(info, dict) and isinstance(info.get("refresh"), dict) else {}
    hold = L.parse_rfc3339(refresh.get("hold"))
    if hold and hold > now:
        findings.append({"kind": "refresh-held", "until": _until(hold)})
    failed = []
    for ch in changes if isinstance(changes, list) else []:
        if not isinstance(ch, dict) or ch.get("kind") != "auto-refresh" or ch.get("status") != "Error":
            continue
        when = L.parse_rfc3339(ch.get("spawn-time"))
        if when and (now - when).days < SNAP_FAILED_DAYS:
            failed.append({"kind": "refresh-failed", "id": L.clean_text(str(ch.get("id") or ""), 12),
                           "when": L.iso(when), "summary": L.clean_text(str(ch.get("summary") or ""), 200),
                           "error": L.clean_text(str(ch.get("err") or ""), 300)})
    findings += sorted(failed, key=lambda f: f["when"], reverse=True)[:5]
    return {"state": "found" if findings else "none", "snapd": snapd, "installed": len(names),
            "snaps": listed[:MAX_ITEMS], "findings": findings,
            "source": ["snapd REST API (" + SNAPD_SOCKET + ")", "/usr/share/distro-info/ubuntu.csv"]}


# ----------------------------------------------------------------- stage 2 --

def _utc(value):
    """A time of radar.json (2026-10-20T12:00:00Z) -> aware datetime or None."""
    if not isinstance(value, str):
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _data_time(ctx, doc, service, svc):
    """(when the data a stage-2 check uses were last fetched successfully,
    whether radar.json says so). radar.json itself is written on every run,
    also when every request failed and the last answers are kept, so its
    `generated` says nothing about the data. The OVAL: its last good download
    (or 304), `services.oval.data_fetched`, null when a copy has no known
    time. Launchpad and GitHub: the oldest answer of the scan's selection (an
    answer keeps its `fetched` when a later request fails)."""
    if service == "oval":
        if "data_fetched" not in svc:
            return None, False
        return _utc(svc.get("data_fetched")), True
    section = doc.get(service) if isinstance(doc.get(service), dict) else {}
    keys = R.selection(ctx)["sources" if service == "launchpad" else "upstream"]
    times = [_utc(section[k].get("fetched")) for k in keys if isinstance(section.get(k), dict)]
    times = [t for t in times if t]
    return (min(times), True) if times else (None, False)


def _radar(ctx, service):
    """(radar doc, fields every stage-2 check reports) or (None, the check's
    result when there are no usable network data). `data_at` and `age_h` are
    the age of the data (see _data_time); `generated` is the radar's last run.
    radar.json without the times (older radars, the recorded fixtures) counts
    from `generated`."""
    doc = ctx.radar()
    if doc is None:
        return None, {"state": "skipped", "reason": "radar-off"}
    ident = (ctx.osr.get("ID") or "").lower()
    if doc.get("distro") != ident or doc.get("codename") != (ctx.codename or None):
        return None, {"state": "skipped", "reason": "radar-other-release"}
    generated = _utc(doc.get("generated"))
    services = doc.get("services") if isinstance(doc.get("services"), dict) else {}
    svc = services.get(service) if isinstance(services.get(service), dict) else {}
    data_at, known = _data_time(ctx, doc, service, svc)
    if not known:
        data_at = generated
    age_h = round((ctx.now - data_at).total_seconds() / 3600, 1) if data_at else None
    errors = [L.strip_credentials(L.clean_text(e, 200)) for e in (svc.get("errors") or [])[:3] if isinstance(e, str)]
    meta = {"radar": {"generated": L.iso(generated) if generated else None,
                      "data_at": L.iso(data_at) if data_at else None, "age_h": age_h,
                      "stale": age_h is None or age_h > RADAR_STALE_H,
                      "service": svc.get("state") if svc.get("state") in ("ok", "partial", "error") else None,
                      "limited": svc.get("limited") is True, "errors": errors}}
    return doc, meta


def _partial_if_old(out):
    """Nothing found in old network data, or in data of unknown age, is not
    "nothing found"."""
    if out["radar"]["stale"] and out["state"] == "none":
        out["state"] = "partial"
        out["missing"] = out.get("missing", []) + ["radar-old" if out["radar"]["age_h"] is not None else "radar-unknown"]
    return out


def _with_unverified(ctx, out):
    """Packages the selection could not assign to the distribution (see
    gapsradar.origins) are named; without other findings the check is
    partial."""
    out["unverified"] = sorted(R.selection(ctx).get("unverified") or {})[:MAX_ITEMS]
    if out["unverified"] and out["state"] == "none":
        out["state"] = "partial"
        out["missing"] = out.get("missing", []) + ["radar-origin"]
    return out


def _answer(doc, section, key):
    entries = doc.get(section)
    entry = entries.get(key) if isinstance(entries, dict) else None
    return entry if isinstance(entry, dict) else None


def _installed_version(ctx, packages):
    for name in packages:
        pkg = ctx.pkg(name)
        if pkg and pkg.get("installed"):
            return pkg["installed"], pkg.get("candidate")
    return None, None


def _series_order(ctx):
    text = ctx.sys.read("/usr/share/distro-info/ubuntu.csv")
    rows = L.parse_distro_info(text) if text else []
    return [(r.get("series") or "", r.get("version") or "") for r in rows]


def _partial_if_unchecked(out, unchecked):
    out["unchecked"] = unchecked[:MAX_ITEMS]
    if unchecked and out["state"] == "none":
        out["state"] = "partial"
        out["missing"] = ["radar-entries"]
    return out


def check_newer(ctx):
    """Newer versions of the selected Ubuntu source packages: for this release
    in a pocket the sources here do not offer, or in a later release."""
    if (ctx.osr.get("ID") or "").lower() != "ubuntu":
        return {"state": "skipped", "reason": "not-applicable"}
    doc, meta = _radar(ctx, "launchpad")
    if doc is None:
        return meta
    order = _series_order(ctx)
    names = [s for s, _ in order]
    own = names.index(ctx.codename) if ctx.codename in names else None
    release_of = dict(order)

    def later(series):
        if series not in names:
            return True                       # distro-info knows every past release
        return own is not None and names.index(series) > own

    findings, unchecked = [], []
    for src, packages in R.selection(ctx)["sources"].items():
        entry = _answer(doc, "launchpad", src)
        if entry is None or not isinstance(entry.get("published"), list):
            unchecked.append(src)
            continue
        inst, cand = _installed_version(ctx, packages)
        if not inst:
            continue
        mine, newer = [], []
        for p in entry["published"]:
            if not isinstance(p, dict):
                continue
            v, series, pocket = p.get("version"), p.get("series"), p.get("pocket")
            if not (isinstance(v, str) and VERSION_RE.match(v) and isinstance(series, str)
                    and SERIES_RE.match(series)):
                continue
            if pocket not in POCKETS or L.vercmp(v, inst) <= 0:
                continue
            if series == ctx.codename:
                if not cand or L.vercmp(v, cand) > 0:
                    mine.append({"version": v, "pocket": pocket})
            elif later(series):
                newer.append({"series": series, "release": release_of.get(series) or None, "version": v})
        if mine or newer:
            findings.append({"source": src, "packages": packages, "installed": inst,
                             "here": max(mine, key=lambda x: (L.Version(x["version"]), x["pocket"] == "Security"))
                             if mine else None,
                             "later": max(newer, key=lambda x: L.Version(x["version"])) if newer else None,
                             "stale": entry.get("stale") is True})
    items, more = _cap(findings)
    out = {"state": "found" if findings else "none", "findings": items,
           "source": ["api.launchpad.net (radar)", "apt-cache policy", "/usr/share/distro-info/ubuntu.csv"],
           **meta}
    if more:
        out["more"] = more
    return _partial_if_old(_with_unverified(ctx, _partial_if_unchecked(out, unchecked)))


CVE_KEYS = ("id", "priority", "cvss", "public", "description", "status", "version")


def _cve(c):
    """One CVE entry of radar.json, checked; None when it does not fit."""
    if not isinstance(c, dict) or not (isinstance(c.get("id"), str) and R.CVE_RE.match(c["id"])):
        return None
    out = {k: c.get(k) for k in CVE_KEYS if isinstance(c.get(k), str)}
    if out.get("priority") not in R.PRIORITIES:
        out["priority"] = "untriaged"
    if "version" in out and not VERSION_RE.match(out["version"]):
        return None
    out["description"] = out.get("description", "")[:300]
    return out


def check_cve(ctx):
    """CVEs Ubuntu lists for the selected source packages of this release:
    open ones (may need fixing, deferred, pending), and fixed ones whose fix
    is newer than the installed version (Canonical's CVE OVAL)."""
    if (ctx.osr.get("ID") or "").lower() != "ubuntu":
        return {"state": "skipped", "reason": "not-applicable"}
    doc, meta = _radar(ctx, "oval")
    if doc is None:
        return meta
    if not isinstance(doc.get("oval"), dict):
        return dict(meta, state="skipped", reason="radar-no-data")
    if meta["radar"]["service"] == "error" and not doc["oval"]:
        # The download failed and there is no copy (or it was unreadable): nothing could be checked. An empty
        # section after a good download is a real "nothing found" and goes on below.
        return dict(meta, state="error", reason="radar-fetch", error=(meta["radar"]["errors"] or ["no data"])[0])
    findings, counts = [], {p: 0 for p in R.PRIORITIES}
    for src, packages in R.selection(ctx)["sources"].items():
        entry = _answer(doc, "oval", src) or {}
        inst, cand = _installed_version(ctx, packages)
        if not inst:
            continue
        open_ = [c for c in map(_cve, entry.get("open") or []) if c][:MAX_ITEMS]
        newer = []
        for c in map(_cve, entry.get("fixed") or []):
            if c and c.get("version") and L.vercmp(c["version"], inst) > 0:
                c["offered"] = bool(cand) and L.vercmp(cand, c["version"]) >= 0
                c["pro"] = "esm" in c["version"]
                newer.append(c)
        if not open_ and not newer:
            continue
        for c in open_ + newer:
            counts[c["priority"]] += 1
        findings.append({"source": src, "packages": packages, "installed": inst,
                         "open": open_, "fixed_newer": newer[:MAX_ITEMS]})
    out = {"state": "found" if findings else "none", "findings": findings,
           "counts": {k: v for k, v in counts.items() if v},
           "selected": len(R.selection(ctx)["sources"]),
           "source": ["security-metadata.canonical.com CVE OVAL (radar)", "dpkg-query"], **meta}
    return _partial_if_old(_with_unverified(ctx, out))


def check_upstream(ctx):
    """Upstream releases newer than the installed version, with the CVE and
    GHSA ids their notes name (GitHub, for the projects in gapsradar.UPSTREAM)."""
    doc, meta = _radar(ctx, "github")
    if doc is None:
        return meta
    findings, unchecked = [], []
    for repo, packages in R.selection(ctx)["upstream"].items():
        entry = _answer(doc, "github", repo)
        if entry is None or not isinstance(entry.get("releases"), list):
            unchecked.append(repo)
            continue
        inst, _ = _installed_version(ctx, packages)
        if not inst:
            continue
        up = R.upstream_version(inst)
        newer = []
        for r in entry["releases"]:
            if not isinstance(r, dict):
                continue
            v = r.get("version")
            if not (isinstance(v, str) and VERSION_RE.match(v)) or L.vercmp(v, up) <= 0:
                continue
            fixes = [f for f in (r.get("fixes") or []) if isinstance(f, str) and R.FIX_ID_RE.fullmatch(f)]
            newer.append({"version": v, "fixes": fixes,
                          "published": r.get("published") if isinstance(r.get("published"), str) else None})
        if not newer:
            continue
        newest = max(newer, key=lambda x: L.Version(x["version"]))
        fixes = sorted({f for r in newer for f in r["fixes"]})
        finding = {"repo": repo, "packages": packages, "installed": inst, "upstream": up,
                   "newest": newest["version"], "newest_published": (newest["published"] or "")[:10] or None,
                   "releases": len(newer), "fixes": fixes[:50],
                   "distribution": R.from_distribution(ctx, packages[0]), "stale": entry.get("stale") is True}
        if len(fixes) > 50:
            finding["fixes_more"] = len(fixes) - 50
        findings.append(finding)
    out = {"state": "found" if findings else "none", "findings": findings,
           "source": ["api.github.com releases (radar)", "dpkg-query"], **meta}
    return _partial_if_old(_partial_if_unchecked(out, unchecked))


CHECKS = (
    ("updates", check_updates),
    ("phased", check_phased),
    ("dpkg", check_dpkg),
    ("boot", check_boot),
    ("held", check_held),
    ("pro", check_pro),
    ("restart", check_restart),
    ("cpu", check_cpu),
    ("firmware", check_firmware),
    ("snaps", check_snaps),
    ("lists", check_lists),
    ("keys", check_keys),
    ("local", check_local),
    ("auto", check_auto),
    ("uu", check_uu),
    ("backports", check_backports),
    ("outside", check_outside),
    ("eol", check_eol),
    ("cve", check_cve),
    ("upstream", check_upstream),
    ("newer", check_newer),
)


def run_check(ctx, name, fn):
    t = time.monotonic()
    try:
        res = fn(ctx)
    except CommandError as e:
        r = e.result
        if r.missing:
            res = {"state": "skipped", "reason": "tool-missing", "tool": e.argv[0]}
        elif r.timeout:
            res = {"state": "timeout", "limit_s": LIMIT, "command": " ".join(e.argv[:3])}
        else:
            res = {"state": "error", "error": L.strip_credentials(str(e))[:400]}
    except RadarError as e:
        res = {"state": "error", "reason": "radar", "error": str(e)[:400]}
    except L.SettingsError as e:
        res = {"state": "error", "reason": "settings", "error": str(e)[:400]}
    except Exception as e:  # noqa: BLE001 - one broken check must not hide the others
        res = {"state": "error", "error": f"{type(e).__name__}: {e}"[:400]}
    res = {"check": name, **res}
    res["took_ms"] = int((time.monotonic() - t) * 1000)
    ctx.results[name] = res
    return res


# The checks whose findings carry `since` and can be acknowledged, with the list they are in and the
# fields that name a finding (gapslib.FINDING_KEYS).
SINCE = L.FINDING_KEYS
SINCE_RE = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
ACCEPTED = "/var/lib/update-gaps/accepted.json"     # written by gaps-accept.py (root) from the page
ACCEPTED_MAX = 1 << 20


def _since_entries(doc):
    for c in (doc or {}).get("checks") or []:
        if isinstance(c, dict) and c.get("check") in SINCE:
            for f in c.get(SINCE[c["check"]][0]) or []:
                if isinstance(f, dict):
                    yield c["check"], f


def mark_since(doc, previous):
    """Every finding of the checks in SINCE gets `since`, when a scan saw it
    first: carried over from `previous` (the last scan.json, read as data),
    else the time of this scan."""
    before = {(check, L.finding_key(check, f)): f["since"] for check, f in _since_entries(previous)
              if isinstance(f.get("since"), str) and SINCE_RE.match(f["since"])}
    for check, f in _since_entries(doc):
        f["since"] = min(before.get((check, L.finding_key(check, f)), doc["generated"]), doc["generated"])


def mark_accepted(doc, accepted, today):
    """Every finding of the checks in SINCE gets its `ref`; one an
    administrator acknowledged (`accepted`, from accepted.json) gets
    `accepted`: `until`, `reason`, `at`, and `expired` once the day has
    passed or `changed` when what it was acknowledged for changed (its pin).
    Only an acknowledgement without either counts: the status leaves such a
    finding out, the page marks it. A check counts its own in `accepted`."""
    for check, f in _since_entries(doc):
        f["ref"] = ref = L.finding_ref(check, f)
        e = accepted.get(ref)
        if not e:
            continue
        a = {"until": e["until"], "reason": e["reason"], "at": e["at"]}
        if L.parse_day(e["until"]) < today:
            a["expired"] = True
        elif e["pin"] != L.finding_pin(check, f):
            a["changed"] = True
        f["accepted"] = a
    for c in doc["checks"]:
        n = sum(1 for f in c.get(SINCE[c["check"]][0]) or [] if isinstance(f, dict)
                and isinstance(f.get("accepted"), dict) and not f["accepted"].get("expired")
                and not f["accepted"].get("changed")) if c.get("check") in SINCE else 0
        if n:
            c["accepted"] = n


def read_accepted(system, today):
    """The acknowledgements, or {} when there are none or the file does not
    hold up (it never stops a scan)."""
    try:
        data = system.read_bytes(ACCEPTED, ACCEPTED_MAX + 1)
        if data is None or len(data) > ACCEPTED_MAX:
            return {}
        return L.parse_accepted(data.decode("utf-8", "replace"), today)
    except Exception:  # noqa: BLE001 - a broken file means no acknowledgement, not a broken scan
        return {}


def scan(system=None, only=None, previous=None):
    """Every check (or those named in `only`) -> the document of scan.json.
    `previous` is the last one, for the time each finding was first seen;
    the acknowledgements come from accepted.json."""
    system = system or System()
    t = time.monotonic()
    ctx = Context(system)
    pm = "apt" if system.lstat("/usr/bin/apt-get") is not None else None
    doc = {"format": 1, "generated": None, "root": ctx.root, "pm": pm,
           "os": {"id": ctx.osr.get("ID"), "version_id": ctx.osr.get("VERSION_ID"),
                  "codename": ctx.codename or None, "name": ctx.osr.get("PRETTY_NAME")},
           "checks": []}
    st = system.lstat("/var/lib/dpkg/status")
    doc["dpkg_status_mtime"] = L.iso_ts(st.st_mtime) if st else None
    for name, fn in CHECKS:
        if only and name not in only:
            continue
        if pm != "apt":
            doc["checks"].append({"check": name, "state": "skipped", "reason": "unsupported-os", "took_ms": 0})
            continue
        doc["checks"].append(run_check(ctx, name, fn))
    doc["generated"] = L.iso(system.now())
    mark_since(doc, previous)
    today = system.now().date()
    mark_accepted(doc, read_accepted(system, today), today)
    doc["took_ms"] = int((time.monotonic() - t) * 1000)
    return doc
