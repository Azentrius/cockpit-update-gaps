# Internals: interfaces, formats, flows

Reference for everyone working on the code. The helpers are the **only** bridge between the browser
and root. Whoever changes a format changes helper, page, fixtures (`test/fixtures/`), tests and this
document together; the page tolerates fields it does not know and checks without a renderer.

## Paths

| Path | Content | Owner / mode |
|---|---|---|
| `/usr/share/cockpit/update-gaps/` | the page (package `cockpit-update-gaps`) | root, 644 |
| `/usr/lib/cockpit-update-gaps/` | helpers: `gaps-scan.py`, `gaps-ctl.sh`, `gaps-status.py` (755), `gapscheck.py`, `gapslib.py`, `gapsproc.py`, `gapsstatus.py` (644) | root |
| `/usr/lib/systemd/system/update-gaps-scan.{service,timer}` | the scan and its timer (every 6 h, `*-*-* 00/6:37:00`); the timer is off until `gaps-ctl.sh install timer` | root, 644 |
| `/var/lib/update-gaps/scan.json` | the state, written atomically by the service (`StateDirectory`) | root, 644 (folder 755) |
| `/var/lib/update-gaps/status.json` | the add-on's status for the Status Board, written atomically by the service after `scan.json` | root, 644 |
| `/usr/lib/systemd/system/update-gaps-radar.{service,timer}` | the radar of stage 2 and its daily timer; off until `gaps-ctl.sh install radar` | root, 644 |
| `/var/lib/update-gaps-radar/radar.json` | the network data, written atomically by the radar (`DynamicUser`; the link points to `/var/lib/private/update-gaps-radar`, which only root can enter) | dynamic user, 644 |
| `/var/lib/update-gaps-radar/cve.oval.xml.bz2` | Canonical's CVE OVAL of the release as downloaded (kept for its ETag and to read again without a download) | dynamic user, 644 |
| `/etc/update-gaps.conf` | settings (optional, see below) | root, not writable by others |
| `/run/update-gaps-scan.lock` | `flock` lock of a scan as root (exit 75 while one runs) | root |

## Calls from the page

| What | Call | Kind | Output |
|---|---|---|---|
| the state | `cockpit.file("/var/lib/update-gaps/scan.json", { syntax: JSON })`, watched | read, no root | `scan.json`, below |
| status | `gaps-ctl.sh status`, `superuser: "try"` | read | one JSON object, below |
| “Refresh” | `gaps-ctl.sh scan`, `superuser: "require"` | runs the service, waits | text, two languages |
| the regular check | `gaps-ctl.sh install timer` / `remove timer`, `superuser: "require"`, through the dialog | changes the add-on's timer | text, two languages, live |

`GAPS_LANG=de|en` (environment) selects the language of `gaps-ctl.sh`'s messages; `gaps-scan.py`
prints no prose. Without administrative access “Refresh” only reads the state again. A fresh
install without a state checks once by itself when an administrator opens the page.

### `gaps-ctl.sh status`

```json
{"root": true, "timer": "active|inactive|missing", "next": "2026-10-20T00:37:00Z", "running": false,
 "state_file": true, "dpkg_status_mtime": "2026-10-19T18:42:30Z", "settings": "/etc/update-gaps.conf"}
```

- `root`: the helper ran as root, i.e. the user has administrative access in Cockpit.
- `timer`: `missing` without systemd or without the unit; `next` is `null` unless active.
- `dpkg_status_mtime`: when packages last changed; later than `scan.json`'s `generated` makes the page
  say that software changed after the last check.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | ok (`gaps-scan.py`: also with findings and with single checks in `error` or `timeout`) |
| 1 | unexpected error (`gaps-scan.py`: the previous state file stays as it was); `gaps-ctl.sh scan`: the service failed |
| 2 | not possible: the service or timer is missing |
| 64 | wrong call |
| 75 | a scan is running already |
| 77 | no root rights (`gaps-ctl.sh scan`, `radar`, `install`/`remove timer`/`radar`); `gaps-status.py`: `status.json` exists but cannot be read; `gaps-radar.py`: started as root (it never runs as root) |

## `scan.json`

```json
{"format": 1, "generated": "2026-10-19T20:55:00Z", "took_ms": 3300, "root": true, "pm": "apt",
 "dpkg_status_mtime": "2026-10-19T18:42:30Z",
 "os": {"id": "ubuntu", "version_id": "24.04", "codename": "noble", "name": "Ubuntu 24.04.5 LTS"},
 "checks": [{"check": "updates", "state": "none", "took_ms": 640, "source": ["apt-get -s dist-upgrade"], …}, …]}
```

- `format`: 1. A page that knows a lower format says so and shows what it can.
- `pm`: `apt`, or `null` on a system without `/usr/bin/apt-get`; then every check is `skipped` with
  `reason: "unsupported-os"` and nothing runs.
- `checks`: always in this order: `updates`, `held`, `pro`, `restart`, `lists`, `local`, `auto`,
  `backports`, `outside`, `eol`. Each has `check`, `state`, `took_ms` and, when it ran, `source`
  (the commands and files, for the page's “Source” line).

`state`:

| Value | Meaning | Further fields |
|---|---|---|
| `found` | checked, with findings | the check's own |
| `none` | checked, nothing found (never “safe”) | the check's own |
| `partial` | checked in part, nothing found in that part | `missing`: `services`, `needrestart`, `journal` |
| `skipped` | not checked | `reason`: `needs-root`, `tool-missing` (+ `tool`), `not-applicable`, `unsupported-os`, `unknown-release` |
| `timeout` | a command ran longer than its limit | `limit_s`, `command` |
| `error` | the check failed | `error` (short, credentials removed); `reason: "settings"` for `/etc/update-gaps.conf` |

A failing command breaks only the checks that need it (`apt-cache policy` of the installed packages:
`held`, `local`, `auto`, `backports`).

### The checks

**`updates`** (`apt-get -s -o Debug::NoLocking=1 dist-upgrade`): `count` (`Inst` lines), `security`
(those with a `-security` origin), `kept_back[]`, `phased[]` (“deferred due to phasing”). `found`
when `count` > 0; the page shows it in the overview, not as a card.

**`held`** (`apt-mark showhold`, `apt-cache policy`, `/var/log/dpkg.log*`): `findings[]`:

```json
{"package": "docker-ce", "installed": "5:29.8.0-1~ubuntu.24.04~noble", "candidate": "5:29.9.1-1~ubuntu.24.04~noble",
 "newer": 4, "security": null, "installed_at": "2026-09-08T13:48:10",
 "origin": {"site": "https://download.docker.com/linux/ubuntu", "host": "download.docker.com",
            "o": "Docker", "a": "noble", "n": "", "l": "Docker CE", "c": "stable"}}
```

`candidate` is the newest version a source offers above the installed one (`null`: nothing newer,
`newer` 0). `security`: `true` when a newer version comes from a `-security` suite, `false` when all
come from Ubuntu or Debian without one, `null` when nobody can tell locally (third-party sources).
`installed_at`: the last `install`/`upgrade` of that version in dpkg's log (local time as logged).

**`pro`** (`pro security-status --format json`; Ubuntu only, otherwise `skipped`/`not-applicable`):
`attached`, `services[]` (enabled), `counts` (the `num_*` of the summary without the prefix),
`findings[]`: `package`, `installed`, `version` (the fix), `service` (`esm-apps`, `esm-infra`),
`status` (`pending_attach`, `pending_enable`, others as Pro names them). Packages with
`upgrade_available` are regular updates and left out.

**`restart`** (`needrestart -b -r l`, `/var/run/reboot-required{,.pkgs}`, else `uname -r` against
`/boot/vmlinuz-*`): `kernel` (`running`, `expected`, `state` as needrestart: 0 unknown, 1 current,
2 ABI-compatible update, 3 newer version), `microcode` (`state`, `running`, `expected`, or `null`),
`services[]`, `reboot_required` (`since`, `packages[]`, or `null`), `tool` (`needrestart 3.11`).
`found` when the kernel state is 2 or 3, microcode 2, a service is listed or the flag is set.
Without needrestart `missing: ["needrestart"]`; without root `missing: ["services"]` (needrestart
sees only the user's processes).

**`lists`** (`apt-get indextargets` with and without `--no-release-info`, `/var/lib/apt/lists`,
`/var/lib/apt/periodic/update-success-stamp`, the mtime of `/var/lib/apt/lists/partial`,
`systemctl show apt-daily.service`, `journalctl -u apt-daily.service`): `last_update` (`ts`, `src`:
`update-success-stamp`, `lists-partial` or `apt-daily`, `age_h`), `apt_daily` (`finished`, `result`),
`indexes[]` (`file`, `date`, `valid_until` of every Release file), `stale_after_h` (48),
`findings[]`:

| `kind` | Fields | Meaning |
|---|---|---|
| `missing` | `site`, `release`, `entry` (file:line of the source) | a configured source has no Release file yet |
| `orphaned` | `site` (from the file name), `files` | list files no configured source names (apt removes them on its next run) |
| `old` | `hours` | the last successful update is older than 48 hours |
| `expired` | `file`, `valid_until` | a Release file's `Valid-Until` has passed |
| `apt-daily` | `result`, `lines[]` | the last run of `apt-daily.service` did not end with `success`, or printed warnings or errors (`W:`, `E:`, `Err:`, …) |

Without root the journal is not read: `missing: ["journal"]`.

**`local`** (`apt-cache policy`, `dpkg-query`): `findings[]`: `package`, `version`, `arch`, `cause`
(`no-source`, or `lists-missing` when `lists` found a source without lists in the same scan), at most
300, the rest in `more`.

**`auto`** (`apt-config dump`, `systemctl is-enabled apt-daily-upgrade.timer`, the origins from
`apt-cache policy`): `installed` (unattended-upgrades), `periodic` (`update_lists`, `unattended`),
`timer`, `allowed[]` and `patterns[]` (with `${distro_id}` and `${distro_codename}` filled in),
`blacklist[]`, `findings[]`:

| `kind` | Fields |
|---|---|
| `disabled` | `what`: `not-installed`, `periodic-off`, `timer-off` (+ `timer`) |
| `source` | a source none of whose installed packages is covered: `site`, `host`, `o`, `a`, `n`, `l`, `c`, `packages[]` (+ `more`) |
| `blacklist` | `pattern`, `packages[]` it keeps out (`re.match` on the name), or `invalid: true` |
| `held` | `packages[]` |

Matching follows unattended-upgrades: `Allowed-Origins` `origin:archive` and `Origins-Pattern`
`key=value,…` (keys `o`/`origin`, `a`/`archive`/`suite`, `n`/`codename`, `l`/`label`,
`c`/`component`, `site`), shell wildcards, `\:` and `\,` escaped.

**`backports`** (`apt-cache policy`): packages installed from the release (not held) for which a
`-backports` suite has a higher version and the candidate is not higher already; `findings[]` per
source package: `source`, `packages[]`, `installed`, `backport`, `suite`.

**`outside`** (`/usr/local/bin`, `/usr/local/sbin`, `/opt/*/bin`, `dpkg-query -S`): `dirs[]` (`dir`,
`files[]`: `name`, `mtime`, `kind` `script` (+ `interpreter`), `binary`, `link` (+ `target`) or
`other`; at most 300 per folder, the rest in `more`), `hidden` (entries hidden by the settings),
`hidden_paths[]`, `settings` (the file, or `null`). Only the first 128 bytes of a regular file are
read (no link followed, no FIFO opened) to tell a script from a program.

**`eol`** (`/usr/share/distro-info/{ubuntu,debian}.csv`): `release`, `codename`,
`standard_until` (Ubuntu: `eol-server`, else `eol`), `extended_until` (Ubuntu `eol-esm`, Debian
`eol-lts`), `days_left`; `found` with `kind` `soon` (180 days or less) or `ended`.

## `status.json` and `gaps-status.py status` (status contract)

The status format all Azentrius add-ons share (schema 1), for the Status Board and other tools. The
service writes `/var/lib/update-gaps/status.json` after `scan.json` (`gaps-scan.py --status FILE`);
the verb only reads it:

| Call | Kind | Output |
|---|---|---|
| `gaps-status.py status --lang en\|de`, `superuser: "try"` | read: no root, no network, no lock, no command | one JSON object, exit 0 |

`manifest.json` names the command:
`"azentrius": {"status": ["/usr/lib/cockpit-update-gaps/gaps-status.py", "status"]}`. `--lang`
takes a language tag (`de`, `de-DE`, `de_AT`, `fr`): German for `de…`, English for every other.
Anything else is a wrong call (64); a file that exists but cannot be read is 77. Without the file the
state is `none` (“Not checked yet”), a broken file gives `none` (“State not readable”), both with
exit 0, as does every finding, `danger` included.

```json
{"schema": 1, "addon": "update-gaps", "label": "Update Gaps", "version": "0.1.0",
 "checked_at": "2026-10-19T20:55:00Z", "state": "warning",
 "summary": "Findings in 3 areas: Held packages, Restart, Fixes only with Ubuntu Pro.",
 "items": [{"id": "held", "state": "warning", "title": "Held packages", "value": "6",
            "detail": "newer versions for containerd.io, docker-buildx-plugin, …", "link": "#/held",
            "checked_at": "2026-10-19T20:55:00Z", "stale_after": 86400}, …]}
```

The items, in this order. A check that does not apply here (`pro` outside Ubuntu, every check
without apt) has no item; one that was skipped, failed or ran out of time is `none` with “not
checked” or “check failed”; a partial check adds “partly checked” to its detail.

| `id` | `ok` | `info` | `warning` | `danger` | `value` |
|---|---|---|---|---|---|
| `held` | nothing held, or held without a newer version | | a held package has a newer version | | packages with a newer version |
| `restart` | nothing pending | | kernel, microcode, services on old libraries or the reboot flag | | |
| `pro` | no fix only with Ubuntu Pro | fixes only with Ubuntu Pro | | | packages |
| `lists` | no finding | only left-over lists or messages of apt-daily | a source without lists, lists older than 48 hours, an expired Release file, apt-daily failed | | |
| `eol` | standard support continues | | ends within 180 days | ended | days left |
| `updates` | none | regular updates (no link: Software Updates shows them) | | | updates |

The add-on's state is the worst of `danger`, `warning` and `info`; without any of them `ok` when an
item is `ok`, else `none`. `stale_after` is 24 hours, as on the page; `link` is `#/<id>` and opens
the page at that card. Texts hold only numbers, states and names of packages, services and kernels
(at most 6 names, services 2, then `(+n)`; a detail longer than 200 characters, where the Status Board cuts it, ends at a word with ` …`): no addresses, URLs, user names or paths.

The file holds the English document plus the German texts under `i18n.de` (`summary`,
`items.<id>.title` and `.detail`), a field readers of schema 1 ignore. The verb returns the document
in the language asked for, without `i18n`, with the version of the installed page (`const VERSION`
in `gaps.js`). Examples from the recorded hosts: `test/fixtures/status-*.json`.

## Stage 2: the network data (radar)

Off until an administrator sets it up on the page (`gaps-ctl.sh install radar`: enables
`update-gaps-radar.timer`, fetches once, scans). `gaps-ctl.sh radar` fetches and scans now,
`gaps-ctl.sh remove radar` disables the timer; the data stay and count as old after 72 hours.
`gaps-ctl.sh status` adds `radar` (`active`, `inactive`, `missing`), `radar_next`, `radar_running`
and `radar_file` (the time of `radar.json`; only as root, since the file is below
`/var/lib/private`).

**The radar** (`gaps-radar.py`, `gapsradar.py`) runs as `update-gaps-radar.service`:
`DynamicUser=yes`, no capabilities, `ProtectSystem=strict`, a system call filter,
`RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX` (`systemd-analyze security` exposure 1.1). It
refuses to run as root. It reads the package state (dpkg, `apt-mark showmanual`, `apt-cache
policy`; readable by every user), works out the selection and asks, over HTTPS with a User-Agent,
ETags, a 30-second limit and a size limit:

| Service | Request | What leaves the server |
|---|---|---|
| security-metadata.canonical.com | `/oval/com.ubuntu.<codename>.cve.oval.xml.bz2` once a day (304 when unchanged), parsed as a stream; a `DOCTYPE` or `ENTITY` is refused | the release name |
| api.launchpad.net | `getPublishedSources` per selected source package, one second apart | the names of the selected source packages |
| api.github.com | `releases?per_page=30` per project of a fixed list, only when installed | which of those projects are installed |

Together with the server's IP address; no versions, no host names, no accounts. A request that
fails keeps the source's previous answers with `stale: true`; a `403` or `429` ends the requests
to that service for this run.

**Selected** are the source packages of a fixed list of binary packages when they come from the
distribution (`cockpit`, `cockpit-bridge`, `openssh-server`, `sudo`, `docker.io`, `docker-ce`,
`containerd`, `containerd.io`, `runc`, `restic`, `skopeo`, `nginx`, `caddy`, `wireguard-tools`)
and packages installed by hand from Ubuntu's universe and multiverse (no security commitment);
upstream projects: `cockpit-project/cockpit`, `moby/moby`, `containerd/containerd`,
`opencontainers/runc`, `docker/compose`, `restic/restic`.

```json
{"format": 1, "generated": "2026-10-20T09:36:28Z", "distro": "ubuntu", "codename": "resolute",
 "selection": {"sources": {"cockpit": ["cockpit"]}, "upstream": {"cockpit-project/cockpit": ["cockpit"]}},
 "services": {"oval": {"state": "ok", "fetched": "…", "errors": [], "limited": false}, "launchpad": {…}, "github": {…}},
 "oval": {"cockpit": {"open": [{"id": "CVE-2026-4631", "priority": "medium", "cvss": "9.8", "public": "2026-04-07",
                                "description": "…", "status": "needs-fixing"}],
                      "fixed": [{"id": "…", "version": "1:10.2p1-2ubuntu3.2", …}]}},
 "launchpad": {"cockpit": {"fetched": "…", "published": [{"series": "noble", "pocket": "Backports", "version": "362-1~bpo24.04.1", "published": "…"}]}},
 "github": {"cockpit-project/cockpit": {"fetched": "…", "releases": [{"tag": "368", "version": "368", "published": "…", "fixes": ["CVE-2026-91147"]}]}}}
```

**The scan reads it as data** (`gapscheck.py`, `Context.radar`): at most 8 MB, `format` 1, the same
distribution and release as the host (else `skipped`, `radar-other-release`), and only the
answers to its **own** selection; every version, series and id is checked by pattern before it is
used. A file that is too large, not JSON or of another format makes the checks `error` with
`reason: "radar"`. Each stage-2 check carries `radar` (`generated`, `age_h`, `stale` after 72
hours, `service`, `limited`); without the radar it is `skipped`, `radar-off`.

**`cve`** (Ubuntu only): `findings[]` per source package: `source`, `packages[]`, `installed`,
`open[]` (`id`, `priority` as Ubuntu rates it, `cvss`, `public`, `description` (300 characters),
`status`: `needs-fixing`, `deferred`, `pending`) and `fixed_newer[]` (fixes with a version above
the installed one, `offered` when the candidate has it, `pro` for an `esm` version); `counts` per
priority, `selected`.

**`upstream`**: `findings[]` per project with newer releases: `repo`, `packages[]`, `installed`,
`upstream` (the upstream part of the installed version), `newest`, `newest_published`, `releases`
(how many are newer), `fixes[]` (CVE and GHSA ids in their notes), `distribution` (true when the
package comes from the distribution, which may have backported fixes).

**`newer`** (Ubuntu only): `findings[]`: `source`, `packages[]`, `installed`, `here` (a newer
version for this release in a pocket the sources do not offer: `version`, `pocket`), `later` (the
newest version in a later release: `series`, `release` when distro-info knows it, `version`).
`Proposed` never counts.

The status for the Status Board adds the item `cve` once the network data are set up: `info` for
open CVEs, `warning` for a `high` one or a fix that does not reach the server, `danger` for a
`critical` one; `value` is the number of open CVEs.

## Settings (`/etc/update-gaps.conf`)

```ini
# comment
HIDE_OUTSIDE=/opt/agent/bin
```

`KEY=VALUE` lines. The only key is `HIDE_OUTSIDE` (repeatable): an absolute path of a folder or file;
everything below it is left out of `outside` and counted in `hidden`. The file must be a regular file
of root, not writable by group or others. An unknown key, a relative path or `..` makes `outside`
an `error` with `reason: "settings"`; nothing is hidden on a guess.

## How the scan runs commands

`gapsproc.run`: a list (never a shell), `PATH=/usr/sbin:/usr/bin:/sbin:/bin`, `LC_ALL=C`, `TZ=UTC`,
its own process group, a deadline (120 s per command, 300 s for `apt-cache policy` of every installed
package); at the deadline the group gets SIGTERM, then SIGKILL. `pro security-status` runs through
`gapsproc.run_unprivileged`: as `nobody` with an empty private `HOME` (removed afterwards). As root
pro always writes `/var/log/ubuntu-advantage.log` and a lock in `/var/lib/ubuntu-advantage`, which
the service (`ProtectSystem=strict`, no exceptions) does not allow; without root it reads the same
public state and logs below `$XDG_CACHE_HOME`.

## Page internals

- No build step, no framework, only `cockpit.js` from `../base1/`.
- Shared design files (`azentrius.css`, `azentrius-theme.js`, `icons.js`, the fonts, `OFL.txt`) are
  copies of `src/` in Azentrius/cockpit-cronjobs, pinned in `tools/design-files.sha256`.
- Texts in `plugin/i18n.js` (`I18N.en`, `I18N.de`); keys: `chk.<check>` (card titles), `name.<check>`
  (neutral names in lists), `<check>.why` / `<check>.todo`, `reason.<reason>`, `missing.<part>`.
  Values from the system go through `tr()`/`esc()`: escaped, and a backtick in a value cannot open a
  `<code>` of the text.
- Loading: `safeLoad()` never runs twice at once; the state file's watch reloads only on a new tag.
- `#/<check>` (a status item's `link`) scrolls to that card once the cards are there and the page
  is shown (`cockpit.hidden` false, again on `visibilitychange`), again on `locationchanged`
  (Cockpit keeps the page loaded and only changes its location, sometimes while it is hidden).
- **Status in Cockpit's menu** (since 0.2.0): the entry “Update Gaps” carries Cockpit's own status
  icon for the host whose menu is shown: `danger` as `error`, `warning` as `warning`, `info` as
  `info`; `ok` and `none` show none. The tooltip is the summary of `status.json` in the session
  language (German from `i18n.de.summary`), cut to 200 characters.
  - The page sends it with `cockpit.transport.control("notify", {page_status: {type, title}})`; the
    shell files it under the page of the frame that sends it and keeps it in
    `sessionStorage["cockpit:page_status"]`, so only the page behind the entry can set it.
    `"preload": ["index"]` in `manifest.json` makes the shell load the page right after the login,
    hidden.
  - `menu-status.js` watches `/var/lib/update-gaps/status.json` (`cockpit.file`, no administrative
    access needed, the file is 644) and reads nothing else. It judges the status as the Status Board
    does: the worst of the document's state and the items' (`danger` > `warning` > `info`), and an
    item whose `checked_at` (with a zone) lies more than `stale_after` seconds back makes it at least
    a warning, with “(as of <time>, out of date)” after the summary; it is checked again the moment
    the first item turns old. A missing or unreadable file shows no icon. A status is sent only when
    it changed, the first one always.
  - `gaps.js` waits for `UpdateGapsMenuStatus.shown`, the first time `cockpit.hidden` is false, before
    it reads the state file, asks `gaps-ctl.sh status`, checks by itself or writes the signature. The
    flag holds once the first answer about `status.json` is back (the shell's hint comes right after
    `init`, and its messages arrive in order); without any answer the page decides after 3 seconds.
- Version: `const VERSION` in `gaps.js`; `index.html` loads every file with `?v=<version>`;
  `tools/check-version.sh` keeps them and `CHANGELOG.md` in step.

## Tests

| File | Checks |
|---|---|
| `test/lib_test.py` | Debian version order (against `dpkg --compare-versions` when dpkg is there), the parsers of `apt-cache policy`, `apt-get -s`, needrestart, deb822, `apt-config`, dpkg's log, Release dates, unattended-upgrades matching, the settings file, credentials removed |
| `test/scan_test.py` | every check against output recorded on real hosts (`test/fixtures/<scenario>/`, `test/fakesys.py`): the findings of each host, no host names in the result; no root, missing tools, a time-out and a failing command breaking only their checks, Debian, a system without apt, the settings file; the state file written atomically; `gapsproc` (environment, time-out of a process group, `nobody` with a private `HOME`), `pro` without root; the `scan-*.json` and `status-*.json` fixtures current |
| `test/radar_test.py` | the radar's parsers (versions, Launchpad, GitHub, OVAL with a refused `DOCTYPE`), fetching through a stub (ETag and 304, size limit, no plain http, no redirect away from https, slow-down), old answers kept and marked, a whole run without network; the checks `cve`, `upstream`, `newer` on the recorded hosts with `radar-*.json`, another release, broken and oversized files, values checked, only the scan's own selection, old data, the status item |
| `test/status_test.py` | the status (schema 1) of every recorded host in both languages: fields, ids, links, states and the overall state, nothing private, no German in English; checks that did not run, Debian, other systems, end of support; `gaps-status.py`: languages, no file, a broken file, wrong calls (64), unreadable (77), well within 2 seconds; `gaps-scan.py --status` |
| `test/page_test.js` | the page in jsdom with the `scan-*.json` fixtures: cards and their order, overview, “No findings”, “Not checked”, page messages (no admin, no state, old state, software changed, failed and running scans, other systems, newer formats), the first check by itself, Refresh, the timer dialog, links, escaping, the watch, both languages and every text key; the menu icon (the recorded hosts in both languages, no file, a broken one, an item worse than the whole, out of date, the check again at 24 hours, what the board ignores), the page loaded hidden (nothing run, the first check only once shown), a link while the page is hidden |
| `test/contrast_test.py`, `test/fonts_test.py` | WCAG contrast of every colour pair in light and dark; every font the page uses ships with it |
| `test/scenarios.sh` | CI (job `scenarios`), in Debian 12/13 and Ubuntu 22.04/24.04/26.04 containers: a held package, a package without a source, a source without lists, files outside apt, a hidden folder, the reboot flag, a Package-Blacklist; the scan as root and as a user; the status read by a user; never `apt-get` from `/usr/local` |
| `test/cockpit-setup.sh`, `test/cockpit-session.py` | CI (job `cockpit`): a real Cockpit with systemd on a throw-away runner, Playwright with Chromium: the page in the menu, the first check by itself through the service (no network), findings of the setup on the page, Refresh, the timer set up and switched off from the page, a user without administrative access in German, the status through the manifest's command as a user, a link `#/restart` at its card; since 0.2.0 the page loaded hidden after the login without checking, the menu icon as `gaps-status.py status` says (English, and German before the page is opened), `cockpit.jump` into the loaded page (another card while it is shown, a card while it is hidden, no reload); no JavaScript or resource errors beyond Cockpit's own |
| `tools/check-units.sh` | `systemd-analyze verify`, and `systemd-analyze security` exposure at most 5.0 |
| `tools/check-version.sh`, `tools/check-design-files.sh` | version, changelog, shared design files |

Fixtures: `test/fixtures/capture.sh` records the commands' output on a host (read only);
`test/fixtures/import_capture.py` turns it into a scenario without host names and with neutral names
for files outside apt; `test/fixtures/make_scans.py` writes the `scan-*.json` the page tests and the
preview read.
