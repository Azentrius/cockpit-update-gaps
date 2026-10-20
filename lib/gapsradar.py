# SPDX-License-Identifier: Apache-2.0
"""Stage 2 of Update Gaps: which packages the radar asks about, how it
fetches, and how the answers are read.

Lives in /usr/lib/cockpit-update-gaps (root-owned). Standard library only,
no side effects on import. gaps-radar.py runs this as an unprivileged user
(update-gaps-radar.service, DynamicUser) with network access; nothing here
runs as root, and the root scan only reads the radar's file as data.

Asked about are, only when installed (decision 6 of the concept):
  1. a fixed list of programs that are exposed or hold data (FIXED),
  2. packages installed by hand from Ubuntu's universe and multiverse,
     which come without a security commitment,
  3. upstream projects on GitHub of packages in UPSTREAM.
What leaves the host: the names of source packages and the release
codename (decision 7), never versions or host names.
"""

import json
import re
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET

import gapslib as L

# Binary packages; the radar asks about their source packages.
FIXED = ("cockpit", "cockpit-bridge", "openssh-server", "sudo", "docker.io", "docker-ce", "containerd",
         "containerd.io", "runc", "restic", "skopeo", "nginx", "caddy", "wireguard-tools")
UNSUPPORTED_COMPONENTS = ("universe", "multiverse")
# Binary package -> GitHub repository whose releases name the fixes.
UPSTREAM = {
    "cockpit": "cockpit-project/cockpit",
    "cockpit-bridge": "cockpit-project/cockpit",
    "docker-ce": "moby/moby",
    "docker.io": "moby/moby",
    "containerd.io": "containerd/containerd",
    "containerd": "containerd/containerd",
    "runc": "opencontainers/runc",
    "docker-compose-plugin": "docker/compose",
    "docker-compose-v2": "docker/compose",
    "restic": "restic/restic",
}
SOURCE_RE = re.compile(r"^[a-z0-9][a-z0-9+.-]{0,99}$")
REPO_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
FIX_ID_RE = re.compile(r"\b(CVE-\d{4}-\d{4,7}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})\b")
USER_AGENT = "update-gaps-radar (+https://github.com/Azentrius/cockpit-update-gaps)"
TIMEOUT = 30
MAX_BYTES = 8 << 20


# ------------------------------------------------------------- selection --

def selection(ctx):
    """{"sources": {source: [binary, ...]}, "upstream": {repo: [binary, ...]}}
    for this host, from dpkg, apt-mark and apt-cache (all readable without
    root). ctx is a gapscheck.Context; the result is computed once per ctx."""
    return ctx._cached("radar-selection", lambda: _selection(ctx))


def _selection(ctx):
    inst = ctx.installed()
    names = ctx.installed_names()
    manual = set(ctx.cmd(["apt-mark", "showmanual"]).out.split())
    sources, upstream = {}, {}

    def add(name):
        src = (inst.get(name) or {}).get("source") or name.split(":")[0]
        if SOURCE_RE.match(src):
            sources.setdefault(src, set()).add(ctx.display(name))

    for name in names:
        base = name.split(":")[0]
        if base in FIXED and from_distribution(ctx, name):
            add(name)
        elif (name in manual or base in manual) and _component(ctx, name) in UNSUPPORTED_COMPONENTS:
            add(name)
        repo = UPSTREAM.get(base)
        if repo:
            upstream.setdefault(repo, set()).add(ctx.display(name))
    return {"sources": {k: sorted(v) for k, v in sorted(sources.items())},
            "upstream": {k: sorted(v) for k, v in sorted(upstream.items())}}


def _origins(ctx, name):
    entry = L.installed_entry(ctx.pkg(name))
    return [ctx.origin_of(k)[0] for k in L.entry_sources(entry)] if entry else []


def from_distribution(ctx, name):
    return any(r.get("o") in ("Ubuntu", "Debian") for r in _origins(ctx, name))


def _component(ctx, name):
    for r in _origins(ctx, name):
        if r.get("o") == "Ubuntu":
            return r.get("c")
    return None


# ----------------------------------------------------------------- fetch --

class FetchError(Exception):
    """A source did not answer usably; `limited` when it asked to slow down."""

    def __init__(self, message, limited=False):
        super().__init__(message)
        self.limited = limited


def fetch(url, etag=None, opener=None, max_bytes=MAX_BYTES):
    """GET url -> (body bytes or None when unchanged, etag). Never follows a
    redirect to another scheme than https, never reads more than max_bytes."""
    if not url.startswith("https://"):
        raise FetchError("only https")
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if etag:
        headers["If-None-Match"] = etag
    req = urllib.request.Request(url, headers=headers)
    try:
        with (opener or urllib.request.urlopen)(req, timeout=TIMEOUT) as resp:
            if not resp.geturl().startswith("https://"):
                raise FetchError("redirected away from https")
            body = resp.read(max_bytes + 1)
            if len(body) > max_bytes:
                raise FetchError(f"answer larger than {max_bytes} bytes")
            return body, resp.headers.get("ETag")
    except urllib.error.HTTPError as e:
        try:
            e.close()               # the answer's body; Python 3.8 fails here when there is none
        except Exception:  # noqa: BLE001
            pass
        if e.code == 304:
            return None, etag
        if e.code in (403, 429):
            raise FetchError(f"HTTP {e.code}", limited=True)
        raise FetchError(f"HTTP {e.code}")
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise FetchError(type(e).__name__ + ": " + str(getattr(e, "reason", e))[:200])


def fetch_json(url, etag=None, opener=None, max_bytes=MAX_BYTES):
    body, tag = fetch(url, etag, opener, max_bytes)
    if body is None:
        return None, tag
    try:
        return json.loads(body.decode("utf-8")), tag
    except ValueError as e:
        raise FetchError(f"not JSON: {e}")


# --------------------------------------------------------------- answers --

def upstream_version(version):
    """The upstream part of a Debian version: no epoch, no revision, no
    repack suffix. 5:29.8.0-1~ubuntu.24.04~noble -> 29.8.0,
    1:9.6p1-3ubuntu13.5 -> 9.6p1, 1.13.3+ds1-2ubuntu0.24.04.3 -> 1.13.3."""
    v = version.split(":", 1)[1] if ":" in version else version
    if "-" in v:
        v = v.rsplit("-", 1)[0]
    return re.split(r"\+(?:dfsg|ds|really|repack)|~(?:bpo|ubuntu|deb)", v)[0]


def tag_version(tag):
    """cockpit 369, moby docker-v29.9.1, containerd v2.4.2 -> 369, 29.9.1, 2.4.2."""
    t = re.sub(r"^(docker-)?v(?=\d)", "", tag.strip())
    return t if re.match(r"^\d[0-9A-Za-z.+~-]{0,40}$", t) else None


def parse_launchpad(doc, source):
    """getPublishedSources -> [{series, pocket, version, published}] of the
    source package (other names that match are left out)."""
    out = []
    for e in (doc or {}).get("entries") or []:
        if not isinstance(e, dict) or e.get("source_package_name") != source or e.get("status") != "Published":
            continue
        series = str(e.get("distro_series_link") or "").rstrip("/").rsplit("/", 1)[-1]
        out.append({"series": series, "pocket": str(e.get("pocket") or ""),
                    "version": str(e.get("source_package_version") or ""),
                    "published": (e.get("date_published") or "")[:19] or None})
    return out


OVAL_NS = "{http://oval.mitre.org/XMLSchema/oval-definitions-5}"
OVAL_URL = "https://security-metadata.canonical.com/oval/com.ubuntu.{codename}.cve.oval.xml.bz2"
OVAL_MAX = 32 << 20
CRITERION_RE = re.compile(r"^([a-z0-9][a-z0-9+.-]{0,99}) source package in ([a-z]+), (.*)$")
FIXED_RE = re.compile(r"has been fixed \(note: '([^']{1,100})'\)")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
PRIORITIES = ("critical", "high", "medium", "low", "negligible", "untriaged")
MAX_CVES = 300          # per source package and status


class _NoDoctype:
    """A byte stream that refuses a document type declaration: OVAL has none,
    and without one no entity can be declared (no entity expansion)."""

    def __init__(self, raw):
        self.raw, self.head = raw, b""

    def read(self, n=-1):
        data = self.raw.read(n)
        if len(self.head) < 65536:
            self.head += data[:65536]
            if b"<!DOCTYPE" in self.head or b"<!ENTITY" in self.head:
                raise ValueError("document type declaration in OVAL data")
        return data


def parse_oval(stream, sources, codename):
    """Canonical's CVE OVAL of one release (a decompressed byte stream) ->
    {source: {"open": [cve], "fixed": [cve with "version"]}} for the given
    source packages only. A cve is {id, priority, cvss, public, description}."""
    sources = set(sources)
    out = {}
    for _event, el in ET.iterparse(_NoDoctype(stream), events=("end",)):
        if el.tag != OVAL_NS + "definition":
            continue
        if el.get("class") == "vulnerability":
            _definition(el, sources, codename, out)
        el.clear()
    for entry in out.values():
        for k in ("open", "fixed"):
            # Most severe first, newest first within a priority.
            entry[k].sort(key=lambda c: c["public"] or "", reverse=True)
            entry[k].sort(key=lambda c: PRIORITIES.index(c["priority"]))
            entry[k] = entry[k][:MAX_CVES]
    return out


def _definition(el, sources, codename, out):
    meta = el.find(OVAL_NS + "metadata")
    if meta is None:
        return
    ref = meta.find(OVAL_NS + "reference")
    cid = ref.get("ref_id") if ref is not None else None
    if not cid or not CVE_RE.match(cid):
        return
    cve = meta.find(f"{OVAL_NS}advisory/{OVAL_NS}cve")
    priority = (cve.get("priority") if cve is not None else None) or \
        (meta.findtext(f"{OVAL_NS}advisory/{OVAL_NS}severity") or "untriaged").lower()
    cvss = cve.get("cvss_score") if cve is not None else None
    public = (meta.findtext(f"{OVAL_NS}advisory/{OVAL_NS}public_date") or "")[:10] or None
    desc = re.sub(r"\s+", " ", meta.findtext(OVAL_NS + "description") or "").strip()
    for crit in el.iter(OVAL_NS + "criterion"):
        m = CRITERION_RE.match(crit.get("comment") or "")
        if not m or m.group(1) not in sources or m.group(2) != codename:
            continue
        item = {"id": cid, "priority": priority if priority in PRIORITIES else "untriaged",
                "cvss": cvss if cvss and re.match(r"^\d{1,2}(\.\d)?$", cvss) else None,
                "public": public, "description": desc[:300]}
        entry = out.setdefault(m.group(1), {"open": [], "fixed": []})
        fixed = FIXED_RE.search(m.group(3))
        if fixed:
            entry["fixed"].append(dict(item, version=fixed.group(1)))
        elif "need fixing" in m.group(3) or "defer" in m.group(3) or "pending" in m.group(3):
            entry["open"].append(dict(item, status=_open_status(m.group(3))))


def _open_status(text):
    if "defer" in text:
        return "deferred"
    if "pending" in text:
        return "pending"
    return "needs-fixing"


def parse_releases(doc):
    """GitHub releases -> [{tag, version, published, fixes}] without drafts
    and pre-releases; fixes are the CVE and GHSA ids named in the notes."""
    out = []
    for r in doc if isinstance(doc, list) else []:
        if not isinstance(r, dict) or r.get("draft") or r.get("prerelease"):
            continue
        tag = str(r.get("tag_name") or "")
        v = tag_version(tag)
        if not v:
            continue
        out.append({"tag": tag[:60], "version": v, "published": (r.get("published_at") or "")[:19] or None,
                    "fixes": sorted(set(FIX_ID_RE.findall(str(r.get("body") or ""))))[:50]})
    return out
