# SPDX-License-Identifier: Apache-2.0
"""The status contract of the Azentrius add-ons (schema 1) for Update Gaps: a
short summary of scan.json in the user's language, which the Status Board and
other tools read through `gaps-status.py status --lang en|de`.

Lives in /usr/lib/cockpit-update-gaps (root-owned). Standard library only,
no side effects on import, nothing here runs a command.

The scan writes status.json next to scan.json: the English document plus the
German texts under "i18n" (a field readers of schema 1 ignore), so one file
serves both languages and the status verb needs neither root nor the scan.
Only numbers, states, package, service, kernel and keyring file names: no
addresses, no user names, no paths.

States follow the status language of the design system: none, ok, info,
warning, danger. The add-on's state is the worst of danger, warning and info;
without any of them ok when an item is ok, else none.
"""

import os
import re
from datetime import datetime, timezone

SCHEMA = 1
ADDON = "update-gaps"
LABEL = "Update Gaps"
STALE_AFTER = 86400     # seconds; the page, too, calls a state older than 24 hours old
RADAR_STALE_AFTER = 72 * 3600   # the network data (daily): old after 72 hours, as gapscheck.RADAR_STALE_H
KEYS_WARN_DAYS = 14     # a key that expires sooner is a warning, later (up to gapscheck.KEYS_SOON_DAYS) info
# Checks that have an item only with a finding: nothing to say when all is well.
QUIET = ("firmware", "snaps", "dpkg", "boot", "keys", "uu")
# Checks found only through their findings: once every finding is acknowledged, nothing is left.
ACK_ONLY = ("dpkg", "boot", "held", "pro", "lists", "keys", "uu", "firmware", "snaps")
ORDER = {"none": 0, "ok": 1, "info": 2, "warning": 3, "danger": 4}
ID_RE = re.compile(r"^[a-z0-9-]{1,40}$")
LINK_RE = re.compile(r"^#/[A-Za-z0-9/_-]{0,80}$")
TIME_RE = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
MAX_NAMES = 6
MAX_DETAIL = 200        # the Status Board cuts a detail there; cut it at a word boundary first
# The version lives in the page (const VERSION in gaps.js): next to lib/ in a checkout, else installed.
PAGE_JS = (os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "plugin", "gaps.js"),
           "/usr/share/cockpit/update-gaps/gaps.js")

T = {
    "en": {
        "summary.missing": "Not checked yet.",
        "summary.unsupported": "Only Debian and Ubuntu are checked.",
        "summary.unreadable": "The state of Update Gaps could not be read.",
        "summary.failed": "No check ran through.",
        "summary.ok": "No findings in the areas checked.",
        "summary.found": {"one": "Findings in {n} area: {list}.", "other": "Findings in {n} areas: {list}."},
        "missing.title": "Not checked yet",
        "missing.detail": "Open Update Gaps with administrative access, or set up its regular check.",
        "unsupported.title": "System not supported",
        "unsupported.detail": "Update Gaps checks Debian and Ubuntu (apt).",
        "unreadable.title": "State not readable",
        "unreadable.detail": "Run the check again in Update Gaps.",
        "updates.title": "Regular updates",
        "cve.title": "Security issues not fixed yet",
        "cve.open": {"one": "{n} open: {names}", "other": "{n} open: {names}"},
        "cve.missing": {"one": "{n} fix not offered here", "other": "{n} fixes not offered here"},
        "cve.fetch": "Canonical's list of security issues could not be fetched",
        "cve.unknown": "the age of the network data is unknown",
        "summary.radarUnknown": "The age of the network data is unknown.",
        "updates.sec": {"one": "{n} from a security source", "other": "{n} from a security source"},
        "held.title": "Held packages",
        "held.newer": "newer versions for {names}",
        "held.none": "held, nothing newer: {names}",
        "pro.title": "Fixes only with Ubuntu Pro",
        "restart.title": "Restart",
        "restart.kernel": "kernel {expected} installed, {running} running",
        "restart.microcode": "newer microcode",
        "restart.flag": "requested by {names}",
        "restart.flag.plain": "requested by a package",
        "restart.services": {"one": "{n} service on old libraries: {names}",
                             "other": "{n} services on old libraries: {names}"},
        "lists.title": "Package lists",
        "lists.missing": {"one": "{n} source without lists", "other": "{n} sources without lists"},
        "lists.old": "older than {hours} hours",
        "lists.old.days": "older than {days} days",
        "lists.expired": "a Release file has expired",
        "lists.apt-daily": "apt-daily reported problems",
        "lists.orphaned": "left-over lists",
        "eol.title": "Support of the release",
        "eol.until": "standard support until {date}",
        "eol.soon": "standard support ends on {date}",
        "eol.ended": "standard support ended on {date}",
        "cpu.title": "CPU vulnerabilities",
        "cpu.provider": "only the provider can fix it (virtual machine)",
        "cpu.off": "protection switched off: {names}",
        "cpu.package": "{name} is not installed",
        "firmware.title": "Firmware",
        "firmware.updates": {"one": "{n} update: {names}", "other": "{n} updates: {names}"},
        "firmware.metadata": "the metadata of fwupd are {days} days old",
        "firmware.refresh": "fwupd-refresh.timer is off",
        "firmware.remote": "no download source enabled in fwupd",
        "snaps.title": "Snaps",
        "snaps.held": "held: {names}",
        "snaps.allheld": "refreshes held for every snap",
        "snaps.inhibited": "refresh put off: {names}",
        "snaps.failed": {"one": "{n} failed refresh", "other": "{n} failed refreshes"},
        "snaps.base": "base out of support: {names}",
        "dpkg.title": "Packages left half done",
        "dpkg.interrupted": "a run of dpkg was interrupted",
        "dpkg.packages": {"one": "{n} package left half done: {names}", "other": "{n} packages left half done: {names}"},
        "boot.title": "Room in /boot",
        "boot.space": "{free} free, the next kernel update needs about {need}",
        "boot.old": {"one": "{n} old kernel", "other": "{n} old kernels"},
        "keys.title": "Signing keys of the sources",
        "keys.expired": "expired: {names}",
        "keys.expires": "expires on {date}: {names}",
        "keys.missing": "keyring missing: {names}",
        "uu.title": "Runs of the automatic updates",
        "uu.never": "no finished run in its log",
        "uu.old": "last finished run {days} days ago",
        "uu.failed": "the last run failed",
        "uu.service": "apt-daily-upgrade.service ended with {result}",
        "uu.kept": "kept back: {names}",
        "uu.conffile": "left for an upgrade by hand: {names}",
        "acked": {"one": "{n} acknowledged", "other": "{n} acknowledged"},
        "partly": "partly checked",
        "failed": "check failed",
        "skipped": "not checked",
    },
    "de": {
        "summary.missing": "Noch nicht geprüft.",
        "summary.unsupported": "Geprüft werden nur Debian und Ubuntu.",
        "summary.unreadable": "Der Stand von Update Gaps ließ sich nicht lesen.",
        "summary.failed": "Keine Prüfung lief durch.",
        "summary.ok": "In den geprüften Bereichen nichts gefunden.",
        "summary.found": {"one": "Befunde in {n} Bereich: {list}.", "other": "Befunde in {n} Bereichen: {list}."},
        "missing.title": "Noch nicht geprüft",
        "missing.detail": "Öffnen Sie Update Gaps mit administrativem Zugriff, oder richten Sie die regelmäßige "
                          "Prüfung ein.",
        "unsupported.title": "System nicht unterstützt",
        "unsupported.detail": "Update Gaps prüft Debian und Ubuntu (apt).",
        "unreadable.title": "Stand nicht lesbar",
        "unreadable.detail": "Prüfen Sie in Update Gaps erneut.",
        "updates.title": "Reguläre Updates",
        "cve.title": "Noch nicht behobene Sicherheitslücken",
        "cve.open": {"one": "{n} offen: {names}", "other": "{n} offen: {names}"},
        "cve.missing": {"one": "{n} Fix hier nicht angeboten", "other": "{n} Fixes hier nicht angeboten"},
        "cve.fetch": "Canonicals Liste der Sicherheitslücken ließ sich nicht holen",
        "cve.unknown": "das Alter der Netzdaten ist unbekannt",
        "summary.radarUnknown": "Das Alter der Netzdaten ist unbekannt.",
        "updates.sec": {"one": "{n} aus einer Sicherheitsquelle", "other": "{n} aus einer Sicherheitsquelle"},
        "held.title": "Gehaltene Pakete",
        "held.newer": "neuere Versionen für {names}",
        "held.none": "gehalten, nichts Neueres: {names}",
        "pro.title": "Fixes nur mit Ubuntu Pro",
        "restart.title": "Neustart",
        "restart.kernel": "Kernel {expected} installiert, {running} läuft",
        "restart.microcode": "neuerer Microcode",
        "restart.flag": "angefordert von {names}",
        "restart.flag.plain": "von einem Paket angefordert",
        "restart.services": {"one": "{n} Dienst mit alten Bibliotheken: {names}",
                             "other": "{n} Dienste mit alten Bibliotheken: {names}"},
        "lists.title": "Paketlisten",
        "lists.missing": {"one": "{n} Quelle ohne Listen", "other": "{n} Quellen ohne Listen"},
        "lists.old": "älter als {hours} Stunden",
        "lists.old.days": "älter als {days} Tage",
        "lists.expired": "eine Release-Datei ist abgelaufen",
        "lists.apt-daily": "apt-daily meldete Probleme",
        "lists.orphaned": "liegengebliebene Listen",
        "eol.title": "Unterstützung der Version",
        "eol.until": "Standard-Unterstützung bis {date}",
        "eol.soon": "Standard-Unterstützung endet am {date}",
        "eol.ended": "Standard-Unterstützung endete am {date}",
        "cpu.title": "CPU-Schwachstellen",
        "cpu.provider": "beheben kann es nur der Anbieter (virtuelle Maschine)",
        "cpu.off": "Schutz abgeschaltet: {names}",
        "cpu.package": "{name} ist nicht installiert",
        "firmware.title": "Firmware",
        "firmware.updates": {"one": "{n} Update: {names}", "other": "{n} Updates: {names}"},
        "firmware.metadata": "die Metadaten von fwupd sind {days} Tage alt",
        "firmware.refresh": "fwupd-refresh.timer ist aus",
        "firmware.remote": "in fwupd ist keine Download-Quelle aktiv",
        "snaps.title": "Snaps",
        "snaps.held": "zurückgehalten: {names}",
        "snaps.allheld": "Aktualisierungen für alle Snaps zurückgehalten",
        "snaps.inhibited": "Aktualisierung aufgeschoben: {names}",
        "snaps.failed": {"one": "{n} fehlgeschlagene Aktualisierung", "other": "{n} fehlgeschlagene Aktualisierungen"},
        "snaps.base": "Basis ohne Unterstützung: {names}",
        "dpkg.title": "Halb fertige Pakete",
        "dpkg.interrupted": "ein Lauf von dpkg wurde unterbrochen",
        "dpkg.packages": {"one": "{n} Paket halb fertig: {names}", "other": "{n} Pakete halb fertig: {names}"},
        "boot.title": "Platz in /boot",
        "boot.space": "{free} frei, das nächste Kernel-Update braucht etwa {need}",
        "boot.old": {"one": "{n} alter Kernel", "other": "{n} alte Kernel"},
        "keys.title": "Signaturschlüssel der Quellen",
        "keys.expired": "abgelaufen: {names}",
        "keys.expires": "läuft am {date} ab: {names}",
        "keys.missing": "Schlüsselbund fehlt: {names}",
        "uu.title": "Läufe der automatischen Updates",
        "uu.never": "kein abgeschlossener Lauf in seinem Log",
        "uu.old": "letzter abgeschlossener Lauf vor {days} Tagen",
        "uu.failed": "der letzte Lauf schlug fehl",
        "uu.service": "apt-daily-upgrade.service endete mit {result}",
        "uu.kept": "zurückgehalten: {names}",
        "uu.conffile": "für ein Update von Hand liegen gelassen: {names}",
        "acked": {"one": "{n} quittiert", "other": "{n} quittiert"},
        "partly": "teilweise geprüft",
        "failed": "Prüfung fehlgeschlagen",
        "skipped": "nicht geprüft",
    },
}


def t(lang, key, **kw):
    s = T[lang][key]
    if isinstance(s, dict):
        s = s["one"] if kw.get("n") == 1 else s["other"]
    return s.format(**kw)


def version():
    """The add-on's version, from const VERSION in the page's gaps.js."""
    for p in PAGE_JS:
        try:
            with open(p, encoding="utf-8") as f:
                m = re.search(r'^\s*const VERSION = "([0-9A-Za-z.+~-]{1,40})";', f.read(1 << 20), re.M)
        except OSError:
            continue
        if m:
            return m.group(1)
    return "unknown"


def radar_age_unknown(check):
    """Whether the network data a stage-2 check used have no known time. A
    scan.json of 0.4.2 and later then has `radar.data_at: null` (a copy
    without its time, after a failed download). One of 0.4.1 and older has no
    `data_at` at all: its radar's run stands in, as it did then."""
    radar = check.get("radar") if isinstance(check, dict) else None
    if not isinstance(radar, dict) or "data_at" not in radar:
        return False
    when = radar.get("data_at")
    return not (isinstance(when, str) and TIME_RE.match(when))


def overall(items):
    """The add-on's state from its items (contract 2.3)."""
    worst = max((ORDER.get(i.get("state"), 0) for i in items), default=0)
    if worst >= ORDER["info"]:
        return next(k for k, v in ORDER.items() if v == worst)
    return "ok" if any(i.get("state") == "ok" for i in items) else "none"


def _names(names, n=MAX_NAMES):
    names = [str(x) for x in names]
    more = len(names) - n
    return ", ".join(names[:n]) + (f" (+{more})" if more > 0 else "")


def _clip(text):
    if len(text) <= MAX_DETAIL:
        return text
    cut = text[:MAX_DETAIL - 2]
    at = max(cut.rfind(", "), cut.rfind("; "), cut.rfind(" "))
    return (cut[:at] if at > 0 else cut).rstrip(",; ") + " …"


def _kernel(k):
    return re.sub(r"-generic$", "", str(k or "?"))


def is_acked(f):
    """Whether a finding is acknowledged on the page and the acknowledgement
    still holds (not ended, the finding not changed since)."""
    a = f.get("accepted") if isinstance(f, dict) else None
    return isinstance(a, dict) and not a.get("expired") and not a.get("changed")


def without_acked(c):
    """A check with its acknowledged findings left out, and how many those
    were. They do not count for the status; the page still shows them."""
    f = c.get("findings")
    if not isinstance(f, list):
        return c, 0
    open_ = [x for x in f if not is_acked(x)]
    if len(open_) == len(f):
        return c, 0
    c = dict(c, findings=open_)
    if not open_ and c.get("state") == "found" and c.get("check") in ACK_ONLY:
        c["state"] = "none"
    return c, len(f) - len(open_)


def _size(n, lang):
    """Bytes as MB or GB, with the decimal comma in German."""
    if not isinstance(n, int):
        return "?"
    text = f"{n / 1e9:.1f} GB" if n >= 1e9 else f"{round(n / 1e6)} MB"
    return text.replace(".", ",") if lang == "de" else text



def items_of(doc, lang):
    """The items of a scan, most important first: unfixed security issues,
    packages dpkg left half done, held packages, restart, room in /boot, CPU
    vulnerabilities, Pro, package lists, signing keys, runs of the automatic
    updates, support of the release, firmware, snaps, regular updates. A
    check that does not apply here (not Ubuntu, no apt, a container) has no
    item, nor do the QUIET ones without a finding; one that did not run is
    `none`. A CPU vulnerability only the provider of a VM can fix is info,
    not a warning. Findings acknowledged on the page (until a day, unchanged
    since) do not count; the detail says how many there are."""
    checks = {c.get("check"): c for c in doc.get("checks") or [] if isinstance(c, dict)}
    at = doc.get("generated")
    out = []

    def item(cid, state, value=None, detail=None, link=True):
        i = {"id": cid, "state": state, "title": t(lang, cid + ".title")}
        if value is not None:
            i["value"] = str(value)
        if detail:
            i["detail"] = _clip(detail)
        if link:
            i["link"] = "#/" + cid
        i["checked_at"] = at
        i["stale_after"] = STALE_AFTER
        radar = (checks.get(cid) or {}).get("radar")
        if cid == "cve" and isinstance(radar, dict):
            # Network data: as old as their last good fetch, not as the local scan that read them, so a new
            # scan never makes old data look new to the Status Board.
            if radar_age_unknown(checks.get(cid)):
                # No time of the data is known, and none is made up: the contract makes both fields
                # optional; the item counts as out of date through its state (cve()) and its texts.
                del i["checked_at"], i["stale_after"]
                return i
            when = radar.get("data_at") if "data_at" in radar else radar.get("generated")   # 0.4.1: generated
            if isinstance(when, str) and TIME_RE.match(when):
                i["checked_at"] = when
            i["stale_after"] = RADAR_STALE_AFTER
        return i

    def held(c):
        f = c.get("findings") or []
        newer = [x.get("package") for x in f if x.get("newer")]
        rest = [x.get("package") for x in f if not x.get("newer")]
        parts = ([t(lang, "held.newer", names=_names(newer))] if newer else []) + \
                ([t(lang, "held.none", names=_names(rest))] if rest else [])
        return item("held", "warning" if newer else "ok", len(newer), "; ".join(parts))

    def restart(c):
        parts = []
        k = c.get("kernel") or {}
        if k.get("state") in (2, 3):
            parts.append(t(lang, "restart.kernel", expected=_kernel(k.get("expected")), running=_kernel(k.get("running"))))
        if (c.get("microcode") or {}).get("state") == 2:
            parts.append(t(lang, "restart.microcode"))
        flag = c.get("reboot_required")
        if flag:
            pk = flag.get("packages") or []
            parts.append(t(lang, "restart.flag", names=_names(pk)) if pk else t(lang, "restart.flag.plain"))
        svc = c.get("services") or []
        if svc:
            parts.append(t(lang, "restart.services", n=len(svc), names=_names(svc, 2)))
        return item("restart", "warning" if c.get("state") == "found" else "ok", detail="; ".join(parts))

    def pro(c):
        f = c.get("findings") or []
        return item("pro", "info" if f else "ok", len(f), _names(sorted({str(x.get("package")) for x in f})))

    def lists(c):
        f = c.get("findings") or []
        kinds = [x.get("kind") for x in f]
        parts = []
        if "missing" in kinds:
            parts.append(t(lang, "lists.missing", n=kinds.count("missing")))
        for x in f:
            if x.get("kind") == "old":
                hours = int(x.get("hours") or 0)
                parts.append(t(lang, "lists.old", hours=hours) if hours < 72 else
                             t(lang, "lists.old.days", days=hours // 24))
        for k in ("expired", "apt-daily", "orphaned"):
            if k in kinds:
                parts.append(t(lang, "lists." + k))
        severe = any(k in kinds for k in ("missing", "old", "expired")) or any(
            x.get("kind") == "apt-daily" and x.get("result") not in (None, "success") for x in f)
        return item("lists", "warning" if severe else "info" if f else "ok", detail="; ".join(parts))

    def eol(c):
        until = c.get("standard_until")
        if c.get("kind") == "ended":
            return item("eol", "danger", detail=t(lang, "eol.ended", date=until))
        if c.get("kind") == "soon":
            return item("eol", "warning", c.get("days_left"), t(lang, "eol.soon", date=until))
        return item("eol", "ok", detail=t(lang, "eol.until", date=until) if until else None)

    def updates(c):
        n, sec = int(c.get("count") or 0), int(c.get("security") or 0)
        return item("updates", "info" if n else "ok", n, t(lang, "updates.sec", n=sec) if sec else None, link=False)

    def cve(c):
        f = c.get("findings") or []
        opened = [x for e in f for x in (e.get("open") or [])]
        missing = [x for e in f for x in (e.get("fixed_newer") or []) if not x.get("offered") and not x.get("pro")]
        prios = {x.get("priority") for x in opened}
        state = "danger" if "critical" in prios else "warning" if "high" in prios or missing else "info" if opened else "ok"
        per = [f"{e.get('source')} ({len(e.get('open'))})"
               for e in sorted(f, key=lambda e: -len(e.get("open") or [])) if e.get("open")]
        parts = ([t(lang, "cve.open", n=len(opened), names=_names(per))] if opened else []) + \
                ([t(lang, "cve.missing", n=len(missing))] if missing else [])
        if radar_age_unknown(c):
            # Data of unknown age count as out of date, which the contract makes at least a warning; a
            # danger stays a danger.
            parts.insert(0, t(lang, "cve.unknown"))
            if ORDER[state] < ORDER["warning"]:
                state = "warning"
        return item("cve", state, len(opened), "; ".join(parts))

    def cpu(c):
        f = c.get("findings") or []
        off = c.get("mitigations_off") or []
        pkg = c.get("microcode_package") or {}
        no_pkg = bool(pkg) and not pkg.get("installed")
        here = off or no_pkg or any(x.get("fix") != "provider" for x in f)
        parts = [_names([x.get("name") for x in f])] if f else []
        if f and not here:
            parts.append(t(lang, "cpu.provider"))
        if off:
            parts.append(t(lang, "cpu.off", names=_names(off)))
        if no_pkg:
            parts.append(t(lang, "cpu.package", name=pkg.get("name")))
        return item("cpu", "warning" if here else "info" if f else "ok", len(f), "; ".join(parts))

    def firmware(c):
        f = c.get("findings") or []
        ups = [x for x in f if x.get("kind") == "update"]
        parts = [t(lang, "firmware.updates", n=len(ups), names=_names([x.get("device") for x in ups], 3))] if ups else []
        for x in f:
            if x.get("kind") == "metadata-old":
                parts.append(t(lang, "firmware.metadata", days=x.get("days")))
            elif x.get("kind") == "refresh-off":
                parts.append(t(lang, "firmware.refresh"))
            elif x.get("kind") == "no-remote":
                parts.append(t(lang, "firmware.remote"))
        return item("firmware", "warning" if ups else "info", len(ups), "; ".join(parts))

    def snaps(c):
        f = c.get("findings") or []
        by = {}
        for x in f:
            by.setdefault(x.get("kind"), []).append(x)
        parts = []
        if by.get("refresh-held"):
            parts.append(t(lang, "snaps.allheld"))
        if by.get("held"):
            parts.append(t(lang, "snaps.held", names=_names([x.get("snap") for x in by["held"]])))
        if by.get("inhibited"):
            parts.append(t(lang, "snaps.inhibited", names=_names([x.get("snap") for x in by["inhibited"]])))
        if by.get("refresh-failed"):
            parts.append(t(lang, "snaps.failed", n=len(by["refresh-failed"])))
        if by.get("old-base"):
            parts.append(t(lang, "snaps.base", names=_names([f"{x.get('snap')} ({x.get('base')})" for x in by["old-base"]])))
        return item("snaps", "warning" if by.get("refresh-failed") else "info", len(f), "; ".join(parts))

    def dpkg(c):
        f = c.get("findings") or []
        pk = [x.get("package") for x in f if x.get("kind") == "package"]
        n = len(pk) + int(c.get("more") or 0)
        parts = [t(lang, "dpkg.interrupted")] if any(x.get("kind") == "interrupted" for x in f) else []
        if pk:
            parts.append(t(lang, "dpkg.packages", n=n, names=_names(pk)))
        return item("dpkg", "warning", n, "; ".join(parts))

    def boot(c):
        f = {x.get("kind"): x for x in c.get("findings") or []}
        parts = []
        if "space" in f:
            parts.append(t(lang, "boot.space", free=_size(f["space"].get("free"), lang),
                           need=_size(f["space"].get("need"), lang)))
        old = (f.get("old-kernels") or {}).get("kernels") or []
        if old:
            parts.append(t(lang, "boot.old", n=len(old)))
        return item("boot", "warning" if "space" in f else "info", detail="; ".join(parts))

    def keys(c):
        by = {}
        for x in c.get("findings") or []:
            by.setdefault(x.get("kind"), []).append(x)

        def rings(xs):          # the keyrings' file names (no paths)
            return _names(sorted({os.path.basename(str(x.get("file") or "?")) for x in xs}))
        parts = []
        if by.get("missing"):
            parts.append(t(lang, "keys.missing", names=rings(by["missing"])))
        if by.get("expired"):
            parts.append(t(lang, "keys.expired", names=rings(by["expired"])))
        for x in sorted(by.get("expires") or [], key=lambda x: str(x.get("expires"))):
            parts.append(t(lang, "keys.expires", date=str(x.get("expires") or "?")[:10], names=rings([x])))
        soon = any(int(x.get("days") or 0) < KEYS_WARN_DAYS for x in by.get("expires") or [])
        severe = by.get("missing") or by.get("expired") or soon
        return item("keys", "warning" if severe else "info", sum(len(v) for v in by.values()), "; ".join(parts))

    def uu(c):
        f = {x.get("kind"): x for x in c.get("findings") or []}
        parts = []
        if "never" in f:
            parts.append(t(lang, "uu.never"))
        if "old" in f:
            parts.append(t(lang, "uu.old", days=int(f["old"].get("hours") or 0) // 24))
        if "failed" in f:
            parts.append(t(lang, "uu.failed"))
        if "service" in f:
            parts.append(t(lang, "uu.service", result=f["service"].get("result")))
        if "kept-back" in f:
            parts.append(t(lang, "uu.kept", names=_names(f["kept-back"].get("packages") or [])))
        if "conffile" in f:
            parts.append(t(lang, "uu.conffile", names=_names(f["conffile"].get("packages") or [])))
        severe = any(k in f for k in ("never", "old", "failed", "service"))
        return item("uu", "warning" if severe else "info", detail="; ".join(parts))

    for cid, fn in (("cve", cve), ("dpkg", dpkg), ("held", held), ("restart", restart), ("boot", boot), ("cpu", cpu),
                    ("pro", pro), ("lists", lists), ("keys", keys), ("uu", uu), ("eol", eol), ("firmware", firmware),
                    ("snaps", snaps), ("updates", updates)):
        c = checks.get(cid)
        if not c:
            continue
        c, acked = without_acked(c)
        st = c.get("state")
        if st == "skipped" and c.get("reason") in ("not-applicable", "unsupported-os", "radar-off", "container"):
            continue
        if cid in QUIET and (st in ("none", "skipped") or (st == "partial" and not c.get("findings")
                                                              and cid not in ("firmware", "snaps"))):
            continue          # an item only when there is something to see
        if st in ("error", "timeout", "skipped"):
            if cid == "cve" and c.get("reason") == "radar-fetch":
                why = "cve.fetch"       # the network data could not be fetched: no CVE check at all
            else:
                why = "skipped" if st == "skipped" else "failed"
            out.append(item(cid, "none", detail=t(lang, why), link=cid != "updates"))
            continue
        i = fn(c)
        if acked:
            i["detail"] = _clip("; ".join(x for x in (i.get("detail"), t(lang, "acked", n=acked)) if x))
        if st == "partial":
            i["detail"] = "; ".join(x for x in (i.get("detail"), t(lang, "partly")) if x)
        out.append(i)
    return out


def document(doc, lang, ver):
    """The status document (schema 1) of a scan.json, in one language."""
    if doc.get("pm") != "apt":
        return none_document(lang, ver, "unsupported", doc.get("generated"))
    items = items_of(doc, lang)
    state = overall(items)
    found = [i for i in items if ORDER[i["state"]] >= ORDER["info"]]
    if found:
        summary = t(lang, "summary.found", n=len(found), list=", ".join(i["title"] for i in found))
    else:
        summary = t(lang, "summary.ok" if state == "ok" else "summary.failed")
    cve = next((c for c in doc.get("checks") or [] if isinstance(c, dict) and c.get("check") == "cve"), None)
    if cve and cve.get("state") in ("found", "none", "partial") and radar_age_unknown(cve):
        # First, so the 200 characters the board and the menu keep never cut it off.
        summary = t(lang, "summary.radarUnknown") + " " + summary
    return {"schema": SCHEMA, "addon": ADDON, "label": LABEL, "version": ver,
            "checked_at": doc.get("generated"), "state": state, "summary": summary, "items": items}


def none_document(lang, ver, why, checked_at=None):
    """State none with the reason: `missing` (no state yet), `unsupported`,
    `unreadable`."""
    at = checked_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    item = {"id": "scan", "state": "none", "title": t(lang, why + ".title"), "detail": t(lang, why + ".detail"),
            "checked_at": at, "stale_after": STALE_AFTER}
    return {"schema": SCHEMA, "addon": ADDON, "label": LABEL, "version": ver, "checked_at": at,
            "state": "none", "summary": t(lang, "summary." + why), "items": [item]}


def status_file(doc, ver):
    """What the scan writes to status.json: the English document, with the
    German texts under "i18n" for gaps-status.py."""
    en = document(doc, "en", ver)
    de = document(doc, "de", ver)
    en["i18n"] = {"de": {"summary": de["summary"],
                         "items": {i["id"]: {k: i[k] for k in ("title", "detail") if k in i} for i in de["items"]}}}
    return en


def localize(status, lang):
    """A status.json in the language asked for, without "i18n"."""
    out = {k: v for k, v in status.items() if k != "i18n"}
    tr = (status.get("i18n") or {}).get(lang) if lang != "en" else None
    if isinstance(tr, dict):
        if isinstance(tr.get("summary"), str):
            out["summary"] = tr["summary"]
        texts = tr.get("items") if isinstance(tr.get("items"), dict) else {}
        out["items"] = []
        for i in status.get("items") or []:
            i = dict(i)
            for k, v in (texts.get(i.get("id")) or {}).items():
                if k in ("title", "detail") and isinstance(v, str):
                    i[k] = v
            out["items"].append(i)
    return out


def problems(status):
    """What breaks the contract in a status document (empty when nothing)."""
    out = []
    for key in ("schema", "addon", "label", "version", "checked_at", "state", "summary", "items"):
        if key not in status:
            out.append("missing " + key)
    if status.get("schema") != SCHEMA:
        out.append("schema " + repr(status.get("schema")))
    if status.get("state") not in ORDER:
        out.append("state " + repr(status.get("state")))
    items = status.get("items")
    if not isinstance(items, list):
        return out + ["items is not a list"]
    for i in items:
        if not isinstance(i, dict):
            out.append("an item is not an object")
            continue
        if not ID_RE.match(str(i.get("id", ""))):
            out.append("id " + repr(i.get("id")))
        if i.get("state") not in ORDER:
            out.append("state of " + repr(i.get("id")))
        if "link" in i and not LINK_RE.match(str(i["link"])):
            out.append("link " + repr(i["link"]))
        # Both optional (contract): an item of data without a known time has neither.
        if ("checked_at" in i and not (isinstance(i["checked_at"], str) and TIME_RE.match(i["checked_at"]))) or \
                ("stale_after" in i and not (isinstance(i["stale_after"], int) and i["stale_after"] >= 1)):
            out.append("time of " + repr(i.get("id")))
        for k in ("title", "value", "detail"):
            if k in i and not isinstance(i[k], str):
                out.append(k + " of " + repr(i.get("id")))
    if status.get("state") in ORDER and status.get("state") != overall(items):
        out.append("state does not follow the items")
    return out
