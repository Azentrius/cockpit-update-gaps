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
import json
import os
import re
import stat
import time
from datetime import datetime, timezone

import gapslib as L
import gapsproc

LIMIT = 120             # seconds per command
LISTS = "/var/lib/apt/lists"
PERIODIC = "/var/lib/apt/periodic"
OUTSIDE_DIRS = ("/usr/local/bin", "/usr/local/sbin")
OUTSIDE_GLOB = "/opt"   # /opt/*/bin
MAX_ITEMS = 300         # entries per list in the state file; the rest is counted
STALE_LISTS_H = 48      # package lists older than this are a finding
EOL_SOON_DAYS = 180


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

    def run_unprivileged(self, argv, limit=LIMIT):
        return gapsproc.run_unprivileged(argv, limit)

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
    sim = L.parse_dist_upgrade(ctx.cmd(["apt-get", "-s", "-o", "Debug::NoLocking=1", "dist-upgrade"]).out)
    sec = sum(1 for i in sim["inst"] if any(L.is_security_origin(o) for o in i["origins"]))
    out = {"count": len(sim["inst"]), "security": sec, "kept_back": sim["kept_back"],
           "phased": sim["phased"], "source": ["apt-get -s dist-upgrade"]}
    out["state"] = "found" if sim["inst"] else "none"
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
    conf = L.parse_apt_config(ctx.cmd(["apt-config", "dump"]).out)
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


CHECKS = (
    ("updates", check_updates),
    ("held", check_held),
    ("pro", check_pro),
    ("restart", check_restart),
    ("lists", check_lists),
    ("local", check_local),
    ("auto", check_auto),
    ("backports", check_backports),
    ("outside", check_outside),
    ("eol", check_eol),
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
    except L.SettingsError as e:
        res = {"state": "error", "reason": "settings", "error": str(e)[:400]}
    except Exception as e:  # noqa: BLE001 - one broken check must not hide the others
        res = {"state": "error", "error": f"{type(e).__name__}: {e}"[:400]}
    res = {"check": name, **res}
    res["took_ms"] = int((time.monotonic() - t) * 1000)
    ctx.results[name] = res
    return res


def scan(system=None, only=None):
    """Every check (or those named in `only`) -> the document of scan.json."""
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
    doc["took_ms"] = int((time.monotonic() - t) * 1000)
    return doc
