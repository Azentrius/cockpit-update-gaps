# SPDX-License-Identifier: Apache-2.0
"""Parsers and pure logic for Update Gaps, the Cockpit add-on.

Lives in /usr/lib/cockpit-update-gaps (root-owned). Standard library only, no
side effects on import, nothing here runs a command: gapscheck.py collects
the output of the fixed commands and hands it to these functions, so the
tests can feed them recorded output from real systems.

Every parser reads the C locale's output (gapsproc runs commands with
LC_ALL=C) and tolerates lines it does not know: a newer apt that prints one
more field must not break the page.
"""

import csv
import fnmatch
import io
import re
from datetime import date, datetime, timezone

# ---------------------------------------------------------------- general --

CRED_RE = re.compile(r"([a-z][a-z0-9+.-]*://)[^/@\s]+@", re.I)


def strip_credentials(text):
    """https://user:secret@host/path -> https://***@host/path. Package
    sources may carry a login in their URI; nothing of it may reach the
    state file, which every local user can read."""
    return CRED_RE.sub(r"\1***@", text or "")


def iso(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def iso_ts(ts):
    return iso(datetime.fromtimestamp(ts, timezone.utc))


def parse_os_release(text):
    """/etc/os-release -> {key: value} (quotes removed)."""
    out = {}
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        out[key.strip()] = value
    return out


# --------------------------------------------------- Debian version order --

def _order(c):
    if not c:
        return 0
    if c.isdigit():
        return 0
    if c.isalpha() and c.isascii():
        return ord(c)
    if c == "~":
        return -1
    return ord(c) + 256


def _verrevcmp(a, b):
    """dpkg's verrevcmp: the upstream or revision part of two versions."""
    i = j = 0
    la, lb = len(a), len(b)
    while i < la or j < lb:
        first_diff = 0
        while (i < la and not a[i].isdigit()) or (j < lb and not b[j].isdigit()):
            ac = _order(a[i] if i < la and not a[i].isdigit() else "")
            bc = _order(b[j] if j < lb and not b[j].isdigit() else "")
            if ac != bc:
                return ac - bc
            i += 1
            j += 1
        while i < la and a[i] == "0":
            i += 1
        while j < lb and b[j] == "0":
            j += 1
        while i < la and j < lb and a[i].isdigit() and b[j].isdigit():
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < la and a[i].isdigit():
            return 1
        if j < lb and b[j].isdigit():
            return -1
        if first_diff:
            return first_diff
    return 0


def _split_version(v):
    v = v.strip()
    epoch = 0
    if ":" in v:
        e, _, rest = v.partition(":")
        if e.isdigit():
            epoch, v = int(e), rest
    if "-" in v:
        upstream, _, revision = v.rpartition("-")
    else:
        upstream, revision = v, ""
    return epoch, upstream, revision


def vercmp(a, b):
    """Compare two Debian versions as dpkg does: < 0, 0 or > 0."""
    ea, ua, ra = _split_version(a)
    eb, ub, rb = _split_version(b)
    if ea != eb:
        return ea - eb
    return _verrevcmp(ua, ub) or _verrevcmp(ra, rb)


class Version:
    """Sort key for Debian versions (sorted(..., key=Version))."""
    __slots__ = ("v",)

    def __init__(self, v):
        self.v = v

    def __lt__(self, other):
        return vercmp(self.v, other.v) < 0

    def __eq__(self, other):
        return vercmp(self.v, other.v) == 0


# ----------------------------------------------------------- apt-cache --

DPKG_STATUS = "/var/lib/dpkg/status"


def parse_release(text):
    """'v=24.04,o=Ubuntu,a=noble-updates,...' -> dict. Values may contain
    commas only in labels like 'Docker CE'; apt does not escape them, so a
    part without '=' continues the value before it."""
    out, last = {}, None
    for part in (text or "").split(","):
        if "=" in part:
            k, _, v = part.partition("=")
            out[k.strip()] = v
            last = k.strip()
        elif last:
            out[last] += "," + part
    return out


def source_parts(key):
    """'https://host/path noble-updates/main amd64 Packages' ->
    (site, suite, component). Flat sources ('./') have no component."""
    words = key.split()
    if not words:
        return "", "", ""
    site = words[0]
    suite, comp = "", ""
    if len(words) > 1:
        dist = words[1]
        if "/" in dist and not dist.startswith("./") and dist != "/":
            suite, _, comp = dist.rpartition("/")
        else:
            suite = dist
    return site, suite, comp


def parse_policy_sources(text):
    """`apt-cache policy` without arguments -> {source key: source}. A source
    key is the text after the priority ('https://… noble/main amd64
    Packages', or '/var/lib/dpkg/status'), the same text the version tables
    of `apt-cache policy <package>` name."""
    sources = {}
    cur = None
    for line in (text or "").splitlines():
        if line.startswith("Pinned packages:"):
            break
        m = re.match(r"^ *(-?\d+) (\S.*?)\s*$", line)
        if m and not line.startswith("     "):
            key = strip_credentials(m.group(2))
            site, suite, comp = source_parts(key)
            cur = {"key": key, "priority": int(m.group(1)), "site": site, "suite": suite,
                   "component": comp, "release": {}, "origin": ""}
            sources[key] = cur
            continue
        s = line.strip()
        if cur is None:
            continue
        if s.startswith("release "):
            cur["release"] = parse_release(s[len("release "):])
        elif s.startswith("origin "):
            cur["origin"] = s[len("origin "):].strip()
    return sources


def parse_policy_packages(text):
    """`apt-cache policy <pkg> …` -> {name: {"installed", "candidate",
    "versions": [{"version", "priority", "current", "sources": [(prio, key)]}]}}.
    "installed" and "candidate" are None for "(none)"."""
    pkgs = {}
    cur = ver = None
    for line in (text or "").splitlines():
        if not line.strip():
            continue
        if not line.startswith(" ") and line.endswith(":"):
            cur = {"installed": None, "candidate": None, "versions": []}
            pkgs[line[:-1]] = cur
            ver = None
            continue
        if cur is None:
            continue
        s = line.strip()
        if s.startswith("Installed:"):
            v = s.split(":", 1)[1].strip()
            cur["installed"] = None if v == "(none)" else v
        elif s.startswith("Candidate:"):
            v = s.split(":", 1)[1].strip()
            cur["candidate"] = None if v == "(none)" else v
        elif s.startswith("Version table:"):
            continue
        elif line.startswith(" *** ") or (line.startswith("     ") and not line.startswith("      ")):
            m = re.match(r"^(\S+) (-?\d+)", s[4:] if s.startswith("*** ") else s)
            if not m:
                continue
            ver = {"version": m.group(1), "priority": int(m.group(2)),
                   "current": s.startswith("*** "), "sources": []}
            cur["versions"].append(ver)
        elif line.startswith("        ") and ver is not None:
            m = re.match(r"^(-?\d+) (\S.*?)\s*$", s)
            if m:
                ver["sources"].append((int(m.group(1)), strip_credentials(m.group(2))))
    return pkgs


def installed_entry(pkg):
    """The version table entry of the installed version, or None."""
    if not pkg or not pkg.get("installed"):
        return None
    for v in pkg["versions"]:
        if v["current"] or v["version"] == pkg["installed"]:
            return v
    return None


def entry_sources(entry):
    """The source keys of a version table entry, without dpkg's status file."""
    return [k for _, k in (entry or {}).get("sources", []) if k != DPKG_STATUS]


# ------------------------------------------------------- apt-get -s output --

INST_RE = re.compile(r"^Inst (\S+) (?:\[([^\]]*)\] )?\((\S+) (.*?)(?: \[[^\]]*\])?\)")
SUMMARY_RE = re.compile(r"^(\d+) upgraded, (\d+) newly installed, (\d+) to remove and (\d+) not upgraded")


def parse_dist_upgrade(text):
    """`apt-get -s dist-upgrade` -> {"inst": [{package, from, to, origins}],
    "kept_back": [...], "phased": [...], "summary": {...}}."""
    out = {"inst": [], "kept_back": [], "phased": [], "summary": None}
    section = None
    for line in (text or "").splitlines():
        m = INST_RE.match(line)
        if m:
            out["inst"].append({"package": m.group(1), "from": m.group(2), "to": m.group(3),
                                "origins": [o.strip() for o in m.group(4).split(",") if o.strip()]})
            section = None
            continue
        if line.startswith("The following packages have been kept back"):
            section = "kept_back"
            continue
        if line.startswith("The following upgrades have been deferred due to phasing"):
            section = "phased"
            continue
        if line.startswith(" ") and section:
            out[section].extend(line.split())
            continue
        section = None
        m = SUMMARY_RE.match(line)
        if m:
            out["summary"] = {"upgraded": int(m.group(1)), "new": int(m.group(2)),
                              "remove": int(m.group(3)), "not_upgraded": int(m.group(4))}
    return out


SECURITY_RE = re.compile(r"-security\b", re.I)


def is_security_origin(origin):
    """An origin of an Inst line or a suite from a security pocket:
    Ubuntu:24.04/noble-security, Debian-Security:13/stable-security,
    noble-security, trixie-security."""
    return bool(SECURITY_RE.search(origin or ""))


# ------------------------------------------------------------ needrestart --

def parse_needrestart(text):
    """`needrestart -b -r l` -> {"version", "kernel": {running, expected,
    state}, "microcode": {state, running, expected} or None, "services": [],
    "containers": [], "sessions": int}."""
    out = {"version": None, "kernel": None, "microcode": None, "services": [],
           "containers": [], "sessions": 0}
    k, uc = {}, {}
    for line in (text or "").splitlines():
        key, sep, value = line.partition(":")
        if not sep or not key.startswith("NEEDRESTART-"):
            continue
        key, value = key[len("NEEDRESTART-"):], value.strip()
        if key == "VER":
            out["version"] = value
        elif key == "KCUR":
            k["running"] = value
        elif key == "KEXP":
            k["expected"] = value
        elif key == "KSTA":
            k["state"] = int(value) if value.isdigit() else None
        elif key == "UCSTA":
            uc["state"] = int(value) if value.isdigit() else None
        elif key == "UCCUR":
            uc["running"] = value
        elif key == "UCEXP":
            uc["expected"] = value
        elif key == "SVC":
            out["services"].append(value)
        elif key == "CONT":
            out["containers"].append(value)
        elif key == "SESS":
            out["sessions"] += 1
    if k:
        out["kernel"] = {"running": k.get("running"), "expected": k.get("expected"),
                         "state": k.get("state")}
    if uc:
        out["microcode"] = {"state": uc.get("state"), "running": uc.get("running"),
                            "expected": uc.get("expected")}
    return out


# ------------------------------------------------------------- deb822 etc --

def parse_deb822(text):
    """Records separated by blank lines -> [{field: value}] (continuation
    lines joined with a newline)."""
    recs, cur, last = [], {}, None
    for line in (text or "").splitlines():
        if not line.strip():
            if cur:
                recs.append(cur)
            cur, last = {}, None
            continue
        if line[0] in " \t" and last:
            cur[last] += "\n" + line.strip()
            continue
        key, sep, value = line.partition(":")
        if sep:
            last = key.strip()
            cur[last] = value.strip()
    if cur:
        recs.append(cur)
    return recs


APT_CONF_RE = re.compile(r'^(\S+?)(::)? "(.*)";\s*$')


def parse_apt_config(text):
    """`apt-config dump` lines -> {key: [values]}. A list's own line
    (`Key "";`) adds nothing, its items (`Key:: "value";`) add one value
    each; a scalar is a list of one."""
    out = {}
    for line in (text or "").splitlines():
        m = APT_CONF_RE.match(line.strip())
        if not m:
            continue
        key, item, value = m.group(1), m.group(2), m.group(3)
        value = value.replace('\\"', '"')
        lst = out.setdefault(key, [])
        if item or value:
            lst.append(value)
    return out


def config_scalar(conf, key, default=None):
    values = conf.get(key)
    return values[-1] if values else default


# --------------------------------------------------- unattended-upgrades --

UU_KEYS = {"o": "o", "origin": "o", "l": "l", "label": "l", "a": "a", "archive": "a",
           "suite": "a", "n": "n", "codename": "n", "c": "c", "component": "c", "site": "site"}


def uu_expand(value, distro_id, codename):
    return value.replace("${distro_id}", distro_id).replace("${distro_codename}", codename)


def _split_unescaped(text, sep):
    parts, cur, i = [], "", 0
    while i < len(text):
        c = text[i]
        if c == "\\" and i + 1 < len(text) and text[i + 1] == sep:
            cur += sep
            i += 2
            continue
        if c == sep:
            parts.append(cur)
            cur = ""
        else:
            cur += c
        i += 1
    parts.append(cur)
    return parts


def uu_allowed_to_pattern(entry):
    """Allowed-Origins 'origin:archive' -> {"o": …, "a": …} (as
    unattended-upgrades turns it into a pattern)."""
    parts = _split_unescaped(entry, ":")
    if len(parts) < 2:
        return {"o": entry}
    return {"o": parts[0], "a": ":".join(parts[1:])}


def uu_pattern(entry):
    """Origins-Pattern 'origin=Debian,codename=trixie,label=Debian-Security'
    -> {"o": …, "n": …, "l": …}; None if a key is not one unattended-upgrades
    knows."""
    out = {}
    for part in _split_unescaped(entry, ","):
        if not part.strip():
            continue
        key, sep, value = part.partition("=")
        key = UU_KEYS.get(key.strip())
        if not sep or key is None:
            return None
        out[key] = value
    return out


def uu_match(pattern, release, site):
    """Does a source (its release attributes and origin host) match one
    pattern? Values are matched like unattended-upgrades does, with shell
    wildcards."""
    if not pattern:
        return False
    for key, want in pattern.items():
        have = site if key == "site" else release.get(key, "")
        if not fnmatch.fnmatchcase(have or "", want):
            return False
    return True


def distro_id(osr):
    """What unattended-upgrades calls ${distro_id} (lsb_release -i)."""
    ident = (osr.get("ID") or "").lower()
    if ident == "ubuntu":
        return "Ubuntu"
    if ident == "debian":
        return "Debian"
    name = osr.get("NAME") or ident
    return name.split()[0] if name else ""


# ------------------------------------------------------------ dpkg things --

def parse_dpkg_query(text):
    """`dpkg-query -W -f '${binary:Package}\\t${Version}\\t${source:Package}\\t
    ${db:Status-Abbrev}\\t${Architecture}\\n'` -> {name: {version, source,
    status, arch, installed}}."""
    out = {}
    for line in (text or "").splitlines():
        f = line.split("\t")
        if len(f) < 4 or not f[0]:
            continue
        status = f[3]
        out[f[0]] = {"version": f[1], "source": f[2] or f[0].split(":")[0], "status": status.strip(),
                     "arch": f[4] if len(f) > 4 else "",
                     "installed": len(status) >= 2 and status[1] == "i" and status[0] in "ih"}
    return out


DPKG_LOG_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2}) (install|upgrade) (\S+?)(?::\S+)? (\S+) (\S+)\s*$")


def parse_dpkg_log(lines):
    """dpkg.log lines -> {package: (iso time, version)} of the latest install
    or upgrade of each package (the local time of the log, as written)."""
    out = {}
    for line in lines:
        m = DPKG_LOG_RE.match(line.strip())
        if not m:
            continue
        when = m.group(1) + "T" + m.group(2)
        pkg, to = m.group(4), m.group(6)
        if pkg not in out or out[pkg][0] <= when:
            out[pkg] = (when, to)
    return out


def parse_distro_info(text):
    """/usr/share/distro-info/{ubuntu,debian}.csv -> [row dicts]."""
    try:
        return list(csv.DictReader(io.StringIO(text or "")))
    except csv.Error:
        return []


def parse_date(s):
    try:
        return date.fromisoformat((s or "").strip())
    except ValueError:
        return None


RFC2822 = ("%a, %d %b %Y %H:%M:%S %Z", "%a, %d %b %Y %H:%M:%S %z")


def parse_release_date(s):
    """The Date: or Valid-Until: of a Release file ('Sun, 18 Oct 2026 23:54:18
    UTC', also with a one-digit hour) -> aware datetime or None."""
    s = re.sub(r"\s+", " ", (s or "").strip())
    if not s:
        return None
    s = re.sub(r" (\d):", r" 0\1:", s)
    for fmt in RFC2822:
        try:
            dt = datetime.strptime(s, fmt)
        except ValueError:
            continue
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    return None


# --------------------------------------------------------------- settings --

SETTINGS_FILE = "/etc/update-gaps.conf"
SETTINGS_KEYS = ("HIDE_OUTSIDE",)
SAFE_PATH_RE = re.compile(r"^/[A-Za-z0-9._@+/-]{0,1023}$")


class SettingsError(Exception):
    pass


def parse_settings(text):
    """/etc/update-gaps.conf -> {"hide_outside": [paths]}. KEY=VALUE lines,
    '#' comments. An unknown key or a value that is not an absolute plain
    path raises SettingsError: nothing is hidden on a guess."""
    out = {"hide_outside": []}
    for n, raw in enumerate((text or "").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if not sep or key not in SETTINGS_KEYS:
            raise SettingsError(f"line {n}: unknown setting {key!r}")
        if not SAFE_PATH_RE.match(value) or "/../" in value + "/" or "/./" in value + "/":
            raise SettingsError(f"line {n}: {key} needs an absolute path")
        path = value.rstrip("/") or "/"
        out["hide_outside"].append(path)
    return out


def hidden(path, hide):
    """Is path one of the hidden paths or below one?"""
    for h in hide:
        if path == h or path.startswith(h.rstrip("/") + "/"):
            return True
    return False
