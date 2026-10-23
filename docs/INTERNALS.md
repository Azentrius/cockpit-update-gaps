# Internals: interfaces, formats, flows

Reference for everyone working on the code. The helpers are the **only** bridge between the browser
and root. Whoever changes a format changes helper, page, fixtures (`test/fixtures/`), tests and this
document together; the page tolerates fields it does not know and checks without a renderer.

## Paths

| Path | Content | Owner / mode |
|---|---|---|
| `/usr/share/cockpit/update-gaps/` | the page (package `cockpit-update-gaps`) | root, 644 |
| `/usr/lib/cockpit-update-gaps/` | helpers: `gaps-scan.py`, `gaps-ctl.sh`, `gaps-status.py`, `gaps-radar.py`, `gaps-accept.py` (755), `gapscheck.py`, `gapslib.py`, `gapsproc.py`, `gapsstatus.py`, `gapsradar.py` (644) | root |
| `/usr/lib/systemd/system/update-gaps-scan.{service,timer}` | the scan and its timer (every 6 h, `*-*-* 00/6:37:00`); the timer is off until `gaps-ctl.sh install timer` | root, 644 |
| `/var/lib/update-gaps/scan.json` | the state, written atomically by the service (`StateDirectory`) | root, 644 (folder 755) |
| `/var/lib/update-gaps/status.json` | the add-on's status for the Status Board, written atomically by the service after `scan.json` | root, 644 |
| `/var/lib/update-gaps/accepted.json` | the findings acknowledged on the page (0.7.0), written atomically by `gaps-accept.py`, read by the scan | root, 644 |
| `/usr/lib/systemd/system/update-gaps-radar.{service,timer}` | the radar of stage 2 and its daily timer; off until `gaps-ctl.sh install radar` | root, 644 |
| `/var/lib/update-gaps-radar/radar.json` | the network data, written atomically by the radar (`DynamicUser`; the link points to `/var/lib/private/update-gaps-radar`, which only root can enter) | dynamic user, 644 |
| `/var/lib/update-gaps-radar/cve.oval.xml.bz2` | Canonical's CVE OVAL of the release as downloaded (kept for its ETag and to read again without a download) | dynamic user, 644 |
| `/etc/update-gaps.conf` | settings (optional, see below) | root, not writable by others |
| `/run/update-gaps-scan.lock` | `flock` lock of a scan as root (exit 75 while one runs) | root |
| `/run/update-gaps-accept.lock` | `flock` lock while `gaps-accept.py` writes `accepted.json` | root |

## Calls from the page

| What | Call | Kind | Output |
|---|---|---|---|
| the state | `cockpit.file("/var/lib/update-gaps/scan.json", { syntax: JSON })`, watched | read, no root | `scan.json`, below |
| status | `gaps-ctl.sh status`, `superuser: "try"` | read | one JSON object, below |
| “Refresh” | `gaps-ctl.sh scan`, `superuser: "require"` | runs the service, waits | text, two languages |
| the regular check | `gaps-ctl.sh install timer` / `remove timer`, `superuser: "require"`, through the dialog | changes the add-on's timer | text, two languages, live |
| the network data | `gaps-ctl.sh install radar` / `remove radar` / `radar`, `superuser: "require"`, through the dialog | changes the radar's timer, or fetches now (see Stage 2) | text, two languages, live |
| acknowledging a finding (0.7.0) | `gaps-ctl.sh accept REF DAY` (the reason on stdin) / `unaccept REF`, `superuser: "require"`, through the dialog | writes `accepted.json` (`gaps-accept.py`), then runs the service | text, two languages, live |

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
| 65 | `gaps-accept.py`: no such finding in the last state, or a day out of range |
| 75 | a scan is running already |
| 77 | no root rights (`gaps-ctl.sh scan`, `radar`, `install`/`remove timer`/`radar`, `accept`/`unaccept`, `gaps-accept.py`); `gaps-status.py`: `status.json` exists but cannot be read; `gaps-radar.py`: started as root (it never runs as root) |

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
- `checks`: always in this order: `updates`, `phased` (0.5.0), `dpkg`, `boot` (0.6.0), `held`,
  `pro`, `restart`, `cpu`, `firmware`, `snaps`, `lists`, `keys` (0.6.0), `local`, `auto`, `uu`
  (0.6.0), `backports`, `outside`, `eol`, `cve`, `upstream`, `newer`. Each has `check`, `state`,
  `took_ms` and, when it ran, `source` (the commands and files, for the page's “Source” line). A
  page that does not know a check leaves it out.

`state`:

| Value | Meaning | Further fields |
|---|---|---|
| `found` | checked, with findings | the check's own |
| `none` | checked, nothing found (never “safe”) | the check's own |
| `partial` | checked in part, nothing found in that part | `missing`: `services`, `needrestart`, `journal`, `boot-room`, `keyrings` |
| `skipped` | not checked | `reason`: `needs-root`, `tool-missing` (+ `tool`), `not-applicable`, `unsupported-os`, `unknown-release`, `container` |
| `timeout` | a command ran longer than its limit | `limit_s`, `command` |
| `error` | the check failed | `error` (short, credentials removed); `reason: "settings"` for `/etc/update-gaps.conf` |

A failing command breaks only the checks that need it (`apt-cache policy` of the installed packages:
`held`, `local`, `auto`, `backports`; `apt-get -s dist-upgrade`: `updates` and `phased`;
`apt-config dump`: `auto`). `phased` keeps going without the other two: without `apt-cache policy`
its packages have no versions, without `apt-config dump` its `include` is `null`.

**`ref`** (0.7.0): every finding of those checks has `ref`, `<check>-<12 hex digits>`: the first
digits of SHA-256 over the check and the fields that name it (below), so it stays the same while
the finding does. The page passes it to acknowledge the finding; nothing else is sent.

**`accepted`** (0.7.0): a finding an administrator acknowledged on the page (`accepted.json`, see
“Acknowledged findings”) has `accepted`: `until` (the day), `reason`, `at` (when it was given), and
`expired: true` once the day has passed or `changed: true` when a field it was acknowledged for
changed (its pin). Only an acknowledgement without either holds: the status leaves the finding out,
the page marks it. The check counts those in `accepted`. Firmware findings are named by their device
as well, failed snap refreshes by their change (`id`), since 0.7.0.

**`since`** (0.6.0): every finding of the checks whose findings stay the same from one scan to the
next has `since`, the time a scan first saw it (ISO, UTC). `gaps-scan.py --output FILE` reads the
previous `FILE` first (at most 64 MiB, as data: only a `since` in the format of `generated` is
taken) and carries the time over when the same finding is there again; a new one gets the scan's
`generated`, one that is gone is gone. Which fields name a finding (the others, such as versions,
counts and ages, may change): `phased` (`packages[]`) `package`; `dpkg` `kind`, `package`; `boot`,
`uu` `kind`; `held`, `pro`, `local` `package`; `cpu` `name`; `firmware` `kind`, `remote`, `device`;
`snaps` `kind`, `snap`, `id`; `lists` `kind`, `site`, `release`, `file`; `keys` `kind`, `file`,
`inline`, and `select` and `fingerprints` when a finding has them (0.7.1; one without
them keeps the name, and so the `ref`, it had in 0.7.0); `auto` `kind`, `what`, `site`, `o`, `a`,
`pattern`; `backports` `source`. Findings from
the network data (`cve`, `upstream`, `newer`) change with every download and have none. The page
shows “seen since <date>” once an earlier scan saw a finding. A scan to stdout (no `--output`)
starts afresh.

### The checks

**`updates`** (`apt-get -s -o Debug::NoLocking=1 dist-upgrade`): `count` (`Inst` lines), `security`
(those with a `-security` origin), `kept_back[]`, `phased[]` (“deferred due to phasing”). `found`
when `count` > 0; the page shows it in the overview, not as a card.

**`phased`** (0.5.0; the same simulation, run once per scan, `apt-cache policy`, `apt-config
dump`): updates Ubuntu rolls out in phases that apt defers on this host for now. Software Updates
(PackageKit) lists them all the same and refuses them in its install transaction, which then fails
as a whole, the other updates with it (“Package id '<name>;<version>;…' is not available as an
update candidate”, [LP #1466587](https://bugs.launchpad.net/ubuntu/+source/packagekit/+bug/1466587)).
`packages[]` (at most 300, the rest in `more`):

```json
{"package": "systemd", "installed": "259.5-0ubuntu3.4", "version": "259.9-0ubuntu0.1", "percent": 10}
```

`version` is the deferred version: the candidate when `apt-cache policy` marks it `(phased N%)`,
else the newest phased version above the installed one; `percent` is that share of the rollout.
Both, and `installed`, are `null` when `apt-cache policy` failed or did not say. Only names that
look like package names (`name` or `name:arch`) are taken. `include` is how apt's configuration
treats phasing, read as apt reads it (`pkgDepCache::PhasingApplied`): `always` when
`APT::Get::Always-Include-Phased-Updates` is true (or, when that key is not set,
`Update-Manager::Always-Include-Phased-Updates`), else `never` for the `Never-Include` pair, else
`default`; `null` when `apt-config dump` failed. `setting` names the key that decided, or `null`.
`found` with a package; with `include: "always"` apt defers nothing, and the page says so under “No
findings” instead of offering the setting. The page quotes PackageKit's message with the first
package, counts the other updates from `updates`, and gives commands to copy, never to run:
`sudo apt-get upgrade` (the rest, still deferring the phased ones), `sudo apt-get install
--only-upgrade <packages>` (the phased ones ahead of the rollout) and, unless `include` is
`always` or `never`, the host-wide setting in `/etc/apt/apt.conf.d/99-phased-updates` with its
price (the server is among the first of every rollout). The status for the Status Board has no
item for it.

**`dpkg`** (0.6.0; the status letters of `dpkg-query -W` (`${db:Status-Abbrev}`), the folder
`/var/lib/dpkg/updates`): packages dpkg left half done and a run of dpkg that was interrupted. Until
that is finished, apt and Software Updates refuse every further update. `findings[]` (at most 300,
the rest in `more`):

| `kind` | Fields | Meaning |
|---|---|---|
| `interrupted` | | `/var/lib/dpkg/updates` holds a journal entry (a name of digits): apt stops with “dpkg was interrupted” |
| `package` | `package`, `version`, `state` | `half-installed` (H), `unpacked` (U), `half-configured` (F), `triggers-awaited` (W), `triggers-pending` (t), or `reinst-required` (R in the third letter) |

The page gives `sudo dpkg --configure -a`, `sudo apt-get -f install` and, for `reinst-required`,
`sudo apt-get install --reinstall <packages>` to copy.

**`boot`** (0.6.0; `/boot`, `statvfs` of it): `kernels[]` (from `vmlinuz-*`, in version order),
`running`, `free` and `size` (bytes of the file system of `/boot`, `free` as a user may use it),
`need`: 1.5 times the largest kernel with its initramfs (the largest, not the newest: an update
that ran out of room left the newest without one). `findings[]`:

| `kind` | Fields | Meaning |
|---|---|---|
| `space` | `free`, `need` | less room than the next kernel update needs: it would stop halfway, its initramfs not written, dpkg half done |
| `old-kernels` | `kernels[]` | kernels besides the running one and the two newest (those apt's autoremove keeps) |

`skipped`/`not-applicable` without a kernel in `/boot` (a container); `partial` with
`missing: ["boot-room"]` when the room could not be measured.

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

**`keys`** (0.6.0; the files of the `Sourcesentry` of `apt-get indextargets`, their `Signed-By`,
`/etc/apt/trusted.gpg` and `/etc/apt/trusted.gpg.d/*.{gpg,asc}`, `gpg --batch --no-autostart
--with-colons --with-subkey-fingerprint --show-keys <keyring>`): the keys apt checks the
signatures of the enabled sources with. The keyrings are those of `Signed-By` (deb822
`Signed-By:`, one-line `[signed-by=…]`), a key in `Signed-By` itself (handed to gpg on stdin), and,
for entries without either, apt's trusted ones (`default: true`). gpg runs through
`gapsproc.run_unprivileged` (as `nobody` with a fresh home it may create, so not with
`--no-options`), once per file, and imports nothing. A keyring is valid until its latest signing
key (`s` among the capabilities, a subkey no longer than its primary key, revoked ones left out)
expires, or for ever (`never`).

Fingerprints in `Signed-By` (0.7.1) are read as apt reads them (sources.list(5), apt's
`NormalizeSignedBy` and `methods/gpgv.cc`): values split at commas and whitespace in both formats,
fingerprints upper case, 40 hex digits, optionally with `!`; one value of another form makes apt
refuse them all, and nothing is selected. Then only the keys they select count: a
fingerprint selects that key and every subkey of it, one with `!` that key alone; from the files of
`Signed-By`, or from apt's trusted keyrings when it names none (`default: true` with `select`).
Without a fingerprint every key of the file counts, as before. Each selection is a keyring of its
own, its fingerprints in `select` (upper case, `!` kept): sources that share a keyring file may
select from it differently. It is named by the file of its selected signing key that lasts
longest. A key in a sources file has `fingerprints`, those of its primary keys; the same key in two
entries of one file is one keyring. A `Signed-By` in a Release file (apt's fallback when the source
has none) is not read.

`keyrings[]`: `file`, `sources[]` (the URIs, at most 20), `expires` (ISO or `never`), `inline` or
`default` when so, `select` or `fingerprints` when so; `soon_days` (60); `findings[]` (the fields of
the keyring and):

| `kind` | Fields | Meaning |
|---|---|---|
| `expired` | `expires` | every signing key has expired: apt reads the source no more |
| `expires` | `expires`, `days` | the last signing key expires within 60 days |
| `missing` | | the file named in `Signed-By` is not there: apt cannot check the source |

`unchecked[]` (`file`, `reason`: `unreadable`, a sources file or a keyring gpg could not read,
`no-key`, a keyring without a signing key, or `no-selected-key` with `select`, a selection that
matches no signing key of its files, `/etc/apt/trusted.gpg.d` for the trusted ones; apt cannot check
such a source either) with `missing: ["keyrings"]`, `partial` when there is no finding.
`skipped`/`tool-missing` with `tool: "gpg"` without gpg.

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

**`uu`** (0.6.0; `/var/log/unattended-upgrades/unattended-upgrades.log` and `.log.1`, `systemctl
show apt-daily-upgrade.service -p Result`): what the automatic updates did, where `auto` says how
they are set up. The last finished run counts: one that ends with “All upgrades installed”, “No
packages found that can be upgraded unattended”, or an error (`ERROR`, `CRITICAL`, “Lock could not
be acquired”, “dpkg returned an error”). apt-daily's download run (`unattended-upgrade
--download-only`, twice a day) writes no end and is left out, as is a run still going. The log has
the server's local time, read as UTC. `off` (from `auto`: switched off, then `never` and `old` are
no findings), `last_run`, `outcome` (`installed`, `nothing`, `failed`), `upgraded[]` (the packages
of that run), `service` (the last `Result` of `apt-daily-upgrade.service`, or `null`). `findings[]`:

| `kind` | Fields | Meaning |
|---|---|---|
| `never` | `log` (whether a log is there) | no finished run in the log |
| `old` | `hours` | the last finished run is older than 72 hours |
| `failed` | `lines[]` (at most 10) | the last run ended with an error |
| `kept-back` | `packages[]` | packages it kept back |
| `conffile` | `packages[]` | packages it left for an upgrade by hand: their configuration file was changed here |
| `service` | `result` | `apt-daily-upgrade.service` ended with something else than `success` (a run that is stopped writes no end) |

`skipped`/`tool-missing` with `tool: "unattended-upgrades"` when it is not installed (that is a
finding of `auto`).

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

### Stage 3: the machine (0.4.0)

Local, like stage 1: files, `systemd-detect-virt`, fwupd over D-Bus and snapd over its socket; no
network. The machine is `metal`, `vm`, `container` or `unknown` (`systemd-detect-virt`; without it
`/.dockerenv` or `/run/.containerenv` mean a container). In a container `cpu` and `firmware` are
`skipped` with `reason: "container"`: they are the host's.

**`cpu`** (`/sys/devices/system/cpu/vulnerabilities/*`, `/proc/cpuinfo`, `/proc/cmdline`,
`systemd-detect-virt`; on a physical server also `/sys/class/dmi/id` and the microcode package):
`machine`, `virt`, `cpu` (`vendor`, `model`, `threads`, `revisions[]` of the loaded microcode),
`mitigated` and `not_affected` (counts), `mitigations_off[]` (words of the kernel command line that
switch a protection off: `mitigations=off`, `nopti`, `<name>=off` …), `microcode_pending` (from
`restart`: newer microcode waits for a restart; the finding stays there), `findings[]`:

```json
{"name": "tsa", "text": "Vulnerable: Clear CPU buffers attempted, no microcode", "kind": "vulnerable",
 "microcode": true, "fix": "provider"}
```

`text` is the kernel's, quoted (control characters out, at most 300 characters). `kind`:
`vulnerable` (starts with “Vulnerable”), `partial` (a mitigation, but something still vulnerable,
such as “SMT vulnerable”), `unknown`; mitigated and unaffected ones are only counted. `fix`:
`provider` in a VM when the text names microcode or the hypervisor (only the provider can fix it),
else `here`. On a physical server `firmware` (`sys_vendor`, `product_name`, `board_vendor`,
`board_name`, `bios_vendor`, `bios_version`, `bios_date`; placeholders of the board maker left out,
no serial numbers) and `microcode_package` (`name` for the CPU's vendor, `installed`, `candidate`,
and when not installed `available`: `false` when no source offers it, on Debian the component
`non-free-firmware`). `found` with a finding, a protection switched off or a missing microcode
package; `skipped`/`not-applicable` without the folder (another architecture, an old kernel).

**`firmware`** (`fwupdmgr get-updates --json --no-unreported-check --no-metadata-check`,
`fwupdmgr get-remotes --json`, `systemctl is-enabled fwupd-refresh.timer`): only the metadata fwupd
already has (it fetches them itself); `skipped`/`tool-missing` with `tool: "fwupd"` and `machine`
when fwupd is not installed (the page then says that firmware is not checked, and in a VM that the
provider looks after it). `machine`, `timer`, `remotes[]` (`id`, `enabled`, `kind`, `age_days`),
`findings[]`:

| `kind` | Fields | Meaning |
|---|---|---|
| `update` | `device`, `vendor`, `version`, `new`, `urgency` (`critical`, `high`, `medium`, `low` or `null`), `issues[]` (CVE and GHSA ids) | fwupd has a newer release for the device (the newest per device) |
| `metadata-old` | `remote`, `days` | the metadata of an enabled download remote are older than 30 days (`Mtime` in the JSON of `get-remotes`; `ModificationTime`, the D-Bus name, is read when it is missing) |
| `refresh-off` | `timer` | `fwupd-refresh.timer` is not enabled |
| `no-remote` | | no download remote is enabled |

Exit 2 of `get-updates` means nothing to update; any other but 0 is an `error`.

**`snaps`** (snapd's REST API over `/run/snapd.socket`: `/v2/snaps`, `/v2/system-info`,
`/v2/changes?select=all`; `/usr/share/distro-info/ubuntu.csv`): snapd is asked only when `/snap`
holds a snap with a `current` revision, because a request starts snapd through its socket.
Without snaps `none` with `installed: 0` and `snapd` (whether `/usr/bin/snap` is there). Otherwise
`installed`, `snaps[]` (`name`, `version`, `channel`, `type`, `base`), `findings[]`:

| `kind` | Fields | Meaning |
|---|---|---|
| `held` | `snap`, `until` (`null`: until further notice) | `snap refresh --hold` for one snap |
| `refresh-held` | `until` | refreshes held for every snap |
| `inhibited` | `snap`, `until` | the refresh waits because the app runs (`refresh-inhibit`) |
| `refresh-failed` | `id`, `when`, `summary`, `error` | an auto-refresh ended with `Error` in the last 7 days (at most 5) |
| `old-base` | `snap`, `base`, `release`, `ended`, `esm_until` | an app snap builds on a base whose Ubuntu release is out of standard support (`core` 16.04 … `core26` 26.04) |

A newer version in the Store is no finding: snapd refreshes by itself several times a day.

## `status.json` and `gaps-status.py status` (status contract)

The [status format all Azentrius add-ons share](https://github.com/Azentrius/cockpit-status-board/blob/main/docs/STATUS-CONTRACT.md)
(schema 1), for the [Status Board](https://github.com/Azentrius/cockpit-status-board) and other
tools. The service writes `/var/lib/update-gaps/status.json` after `scan.json`
(`gaps-scan.py --status FILE`); the verb only reads it:

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

The items, in this order (`cve` of stage 2 first, see there). A check that does not apply here
(`pro` outside Ubuntu, every check without apt, `cpu` in a container) has no item, nor do
`dpkg`, `boot`, `keys`, `uu`, `firmware` and `snaps` without a finding (the first four not when
partly checked either); one that was skipped, failed or ran out of time is `none` with “not
checked” or “check failed”; a partial check adds “partly checked” to its detail. Findings
acknowledged on the page (0.7.0) do not count: the detail ends with “n acknowledged”, a check found
only through findings that are all acknowledged is `ok`, and one with an item only with a finding
has none. Findings beyond a check's list (`more`) cannot be acknowledged and keep counting: `dpkg`
then says “n more packages left half done, not listed”, and its names end with `(+n)` counting them.

| `id` | `ok` | `info` | `warning` | `danger` | `value` |
|---|---|---|---|---|---|
| `dpkg` (only with a finding) | | | a package left half done, an interrupted run | | packages |
| `held` | nothing held, or held without a newer version | | a held package has a newer version | | packages with a newer version |
| `restart` | nothing pending | | kernel, microcode, services on old libraries or the reboot flag | | |
| `boot` (only with a finding) | | old kernels | too little room for the next kernel | | |
| `cpu` | nothing reported as vulnerable | only vulnerabilities the provider of a VM can fix | a vulnerability this server can fix, a protection switched off, no microcode package on a physical server | | findings |
| `pro` | no fix only with Ubuntu Pro | fixes only with Ubuntu Pro | | | packages |
| `lists` | no finding | only left-over lists or messages of apt-daily | a source without lists, lists older than 48 hours, an expired Release file, apt-daily failed | | |
| `keys` (only with a finding) | | a key expires within 60 days | a key expired, expires within 14 days, or its file is missing | | keyrings |
| `uu` (only with a finding) | | packages kept back or left for an upgrade by hand | no finished run, none for 72 hours, the last one failed, the service failed | | |
| `eol` | standard support continues | | ends within 180 days | ended | days left |
| `firmware` (only with a finding) | | old metadata, the refresh timer off, no download remote | a firmware update | | updates |
| `snaps` (only with a finding) | | held, put off, a base out of support | a failed refresh | | findings |
| `updates` | none | regular updates (no link: Software Updates shows them) | | | updates |

The add-on's state is the worst of `danger`, `warning` and `info`; without any of them `ok` when an
item is `ok`, else `none`. `stale_after` is 24 hours, as on the page; `link` is `#/<id>` and opens
the page at that card. Texts hold only numbers, states and names of packages, services, kernels
and keyring files (at most 6 names, services 2, then `(+n)`; a detail longer than 200 characters, where the Status Board cuts it, ends at a word with ` …`): no addresses, URLs, user names or paths.

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
to that service for this run. Launchpad gets at most 100 source packages per run, those with the
oldest answers first (never asked first); the others keep their answers until a later run
(`deferred` in the service's state). `generated` is the time of the run and is new every day, also
when every request failed; how old the data are says each answer's `fetched` (kept when a later
request for it fails, renewed by a 304) and for the OVAL `services.oval.data_fetched`: the last
good download or 304 of the copy in the state directory (`null` for a copy of unknown time). A
failed download keeps that copy (`partial`); without a copy the OVAL service is `error` and the
section `oval` empty.

**Selected** are the source packages of a fixed list of binary packages when they come from the
distribution (`cockpit`, `cockpit-bridge`, `openssh-server`, `sudo`, `docker.io`, `docker-ce`,
`containerd`, `containerd.io`, `runc`, `restic`, `skopeo`, `nginx`, `caddy`, `wireguard-tools`)
and packages installed by hand from Ubuntu's universe and multiverse (no security commitment);
upstream projects: `cockpit-project/cockpit`, `moby/moby`, `containerd/containerd`,
`opencontainers/runc`, `docker/compose`, `restic/restic`. Where a package comes from is what
`apt-cache policy` says of the installed version. When only dpkg's status knows that version (the
archive has moved on, as when a security update was replaced by the next one), a newer version
from Ubuntu or Debian stands in, but only when the installed version is that distribution's build
by its version string (`…ubuntu5.24.04.4`, `…+deb12u1`; never a PPA, NodeSource or Docker version).
Otherwise such a package of the fixed list (or one installed by hand whose newer version is in
universe or multiverse) goes to `unverified`: not asked about, and named by the checks.

```json
{"format": 1, "generated": "2026-10-20T09:36:28Z", "distro": "ubuntu", "codename": "resolute",
 "selection": {"sources": {"cockpit": ["cockpit"]}, "upstream": {"cockpit-project/cockpit": ["cockpit"]}, "unverified": {}},
 "services": {"oval": {"state": "ok", "fetched": "…", "errors": [], "limited": false, "data_fetched": "…"},
              "launchpad": {…}, "github": {…}},
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
`reason: "radar"`. Each stage-2 check carries `radar`: `generated` (the radar's run), `data_at`
(when its data were last fetched successfully: the OVAL's `data_fetched`; for Launchpad and GitHub
the oldest answer of the selection; a file without these times counts from `generated`), `age_h`
and `stale` (older than 72 hours) from `data_at`, `service` (`ok`, `partial`, `error`), `limited`
and `errors` (at most three, 200 characters). `data_at: null` (the field there, its value null) means
the age is unknown: a copy whose time radar.json no longer has (`data_fetched` null or broken, as
when `oval_file` was lost and the next download failed); `age_h` is then null and `stale` true, and
the radar's run is never taken for the time of the data. Only a state without the field (0.4.1 and
older) counts from `generated`. Without the radar it is `skipped`, `radar-off`. A check without
findings in old data is `partial` with `missing: ["radar-old"]`, in data of unknown age with
`missing: ["radar-unknown"]`; `cve` and `newer`
name the `unverified` packages and are `partial` with `missing: ["radar-origin"]` when there is
nothing else.

**`cve`** (Ubuntu only): `findings[]` per source package: `source`, `packages[]`, `installed`,
`open[]` (`id`, `priority` as Ubuntu rates it, `cvss`, `public`, `description` (300 characters),
`status`: `needs-fixing`, `deferred`, `pending`) and `fixed_newer[]` (fixes with a version above
the installed one, `offered` when the candidate has it, `pro` for an `esm` version); `counts` per
priority, `selected`, `unverified[]`. When the OVAL could not be fetched and there is no copy
(service `error`, section empty), `cve` is `error` with `reason: "radar-fetch"` and the first
`error` of the radar, never `none`: an empty section after a good download is a real "nothing
found".

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
`critical` one; `value` is the number of open CVEs. Its `checked_at` is the data's `data_at`, not
the scan's time, and `stale_after` is 72 hours: a new local scan never makes old network data look
new. With data of unknown age (`data_at: null`) the item has neither `checked_at` nor `stale_after`
(both optional in the contract; no time is made up), is at least a `warning` (as an item out of date
would be; a `danger` stays), and its detail and the summary, first so no cut loses it, say that the
age of the network data is unknown; the menu shows that summary. When the OVAL could not be fetched it is `none` with “Canonical's list of security issues
could not be fetched”.

## Acknowledged findings (`accepted.json`, 0.7.0)

An administrator can acknowledge a finding of the checks above (not the network data) on the page,
until a day at most 90 days ahead, with an optional reason: it then no longer counts for the status
(the Status Board, the menu icon), and the page marks it (“acknowledged until … : reason”) and keeps
showing it. It counts again once the day has passed, or as soon as what it was acknowledged for
changes: the pin, a digest of these fields, differs from the one written then.

| Check | Pin |
|---|---|
| `held` | `security` (a newer version from a security source) |
| `cpu` | `kind`, `fix` (the provider's or this server's) |
| `pro` | `status` |
| `firmware` | `new`, `urgency` |
| `dpkg` | `state` |
| others | nothing: what names the finding is all there is |

A key in a sources file is named by its fingerprints and a selection of `Signed-By` by its
fingerprints as well (0.7.1; `label` then adds them as key IDs, `x.sources
(871920D1991BC93C)`). 0.7.0 gave two keys in one sources file one ref: an acknowledgement from then
for such a key matches neither of them now, and it counts until acknowledged again. A finding
beyond a check's list (`more`) has no ref and cannot be acknowledged; the page counts its card as
open while there is one.

```json
{"format": 1, "accepted": [
 {"ref": "held-4b95c50d995c", "check": "held", "label": "docker-ce", "pin": "8f0b9f3c2a71",
  "until": "2026-11-01", "reason": "Docker is updated in the maintenance window", "at": "2026-10-22T08:14:03Z"}]}
```

The page's dialog asks for the day (30 days ahead to begin with, at most 90) and the reason, then
runs `gaps-ctl.sh accept REF DAY` with the reason on stdin, never on the command line. `gaps-ctl.sh`
checks REF (`^[a-z]{2,12}-[0-9a-f]{12}$`) and DAY (`YYYY-MM-DD`) and runs `gaps-accept.py`, which
checks them again, needs root, takes the finding from the last `scan.json` (65 when it is not there,
or the day is not between today and 90 days ahead), keeps the reason as one line of at most 200
characters, and writes `accepted.json` under a lock, atomically, 0644. It drops acknowledgements
that ended more than 30 days before and keeps at most 500. `unaccept` removes one. Then
`gaps-ctl.sh` starts the scan service, so the page and the status show it at once; without systemd
it says the next scan will. The scan reads the file as data (at most 1 MiB; a broken file means no
acknowledgement, never a failed scan) and checks every entry: its ref against its check, a day no
further than 90 days past the day it was given. The reason is in `scan.json`, which every local
user can read: it is no place for secrets.

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
public state and logs below `$XDG_CACHE_HOME`. `gpg --show-keys` for the keyrings of the sources
(`keys`) runs the same way; a key from a sources file goes to it on stdin.

## Page internals

- No build step, no framework, only `cockpit.js` from `../base1/`.
- Shared design files (`azentrius.css`, `azentrius-theme.js`, `icons.js`, the fonts, `OFL.txt`) are
  copies of `src/` in Azentrius/cockpit-cronjobs, pinned in `tools/design-files.sha256`.
- Texts in `plugin/i18n.js` (`I18N.en`, `I18N.de`); keys: `chk.<check>` (card titles), `name.<check>`
  (neutral names in lists), `<check>.why` / `<check>.todo`, `reason.<reason>`, `missing.<part>`.
  Values from the system go through `tr()`/`esc()`: escaped, and a backtick in a value cannot open a
  `<code>` of the text.
- Loading: `safeLoad()` never runs twice at once; the state file's watch reloads only on a new tag.
- Cards fold through their title (`.ug-toggle`, `aria-expanded`, `aria-controls`); the closed ones are kept in
  `localStorage` (`update-gaps:collapsed`, a list of check names), so per browser and not on the server. A chip of
  the overview and a link `#/<check>` open their card. Storage that is blocked or broken leaves every card open.
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
| `test/lib_test.py` | Debian version order (against `dpkg --compare-versions` when dpkg is there), the parsers of `apt-cache policy` (with the share of a phased version), `apt-get -s`, needrestart, deb822, `apt-config` (and how it treats phased updates: both keys, the fallback, case, apt's booleans), dpkg's log, Release dates, unattended-upgrades matching, the settings file, credentials removed; stage 3: CPU vulnerabilities sorted, `/proc/cpuinfo`, the kernel command line, DMI values and dates, the JSON of fwupd, snapd's times; 0.6.0: when a keyring expires (real keyrings of Docker and GitHub CLI, the expired key beside the new one, a subkey and its primary key, revoked keys, no signing key), `Signed-By` in deb822 and one-line sources (disabled entries, fingerprints, a key in the file, comments), the last finished run in the log of unattended-upgrades (the download run left out, failed, kept back, conffile), dpkg's status letters; 0.7.0: refs and pins of findings (a new version is the same finding, a fix from a security source is not), labels, the reason cleaned, `accepted.json` read with every kind of entry it must refuse; 0.7.1: the keys the fingerprints of `Signed-By` select (a subkey through its primary key or its own fingerprint, `!` for that key alone, upper case, a fingerprint the keyring does not hold, gpg's output without fingerprints), the fingerprints read from both formats, keys told apart by their fingerprints while a finding without them keeps its ref of 0.7.0, labels with key IDs |
| `test/scan_test.py` | every check against output recorded on real hosts (`test/fixtures/<scenario>/`, `test/fakesys.py`): the findings of each host, no host names in the result; no root, missing tools, a time-out and a failing command breaking only their checks, Debian, a system without apt, the settings file; the state file written atomically; `gapsproc` (environment, time-out of a process group, `nobody` with a private `HOME`), `pro` without root; the `scan-*.json` and `status-*.json` fixtures current; stage 3: the VMs of the recorded hosts where only the provider can fix `tsa`, an Intel VM, a physical server with and without its microcode package (Debian without `non-free-firmware`), protections switched off, containers (also without `systemd-detect-virt`), fwupd with an update, old metadata and the refresh timer off, nothing to update, a failing fwupdmgr; snaps held, put off, failing and on an old base, snapd not asked without snaps, snapd not answering; phased updates: none on the recorded hosts, systemd deferred during a rollout (versions, share, the updates beside it), the setting on or set to never, a failing `apt-config dump` or `apt-cache policy`, a time-out of the simulation, names that are no package names; 0.6.0: nothing found on the recorded hosts, upkeep gone wrong (`fakesys.upkeep`); `dpkg` with packages unpacked, half configured or to reinstall and an interrupted run; `boot` full (the largest kernel counts), old kernels, the running one never old, no room measured, no kernel; `uu` failed, kept back and conffile, never run, old, the service failed, switched off, not installed; `keys` expired, expiring in 29 and in 90 days, a missing keyring, an unreadable one or sources file, the trusted keyrings for a source without `Signed-By`, a key in the sources file on stdin, without gpg, and gpg for real without root (when gpg and the Ubuntu keyring are there); `since` kept from scan to scan, new ones, renamed ones, odd previous documents, the previous file read by `gaps-scan.py`; 0.7.0: acknowledged findings marked and counted, ended or changed ones counting again, a held package that gets a security fix, broken files; `gaps-accept.py`: acknowledged and taken back (the file 0644, the reason from stdin, none from a terminal), refused calls (64), not root (77), days out of range and unknown findings (65), old acknowledgements dropped; 0.7.1: `Signed-By` with fingerprints (every key without one, the selected key expired or valid, deb822 with the fingerprint on a line of its own, one keyring file selected differently by three sources and read once, a subkey with and without `!`, a fingerprint from the trusted keyrings and one none of them holds), gpg asked for the fingerprints of subkeys and, for real, a fingerprint selected from the Ubuntu keyring; two keys in one sources file (two findings, one acknowledged through `gaps-accept.py` while the other counts in the status, refs and `since` kept from scan to scan, an acknowledgement of 0.7.0 covering neither, one key in two entries one keyring); 301 packages half done with the 300 listed acknowledged (the one beyond the list still in the status) |
| `test/radar_test.py` | the radar's parsers (versions, Launchpad, GitHub, OVAL with a refused `DOCTYPE`), fetching through a stub (ETag and 304, size limit, no plain http, no redirect away from https, slow-down), old answers kept and marked, a whole run without network; the checks `cve`, `upstream`, `newer` on the recorded hosts with `radar-*.json`, another release, broken and oversized files, values checked, only the scan's own selection, old data, the status item; the selection with a superseded installed version (an Ubuntu build stays selected, an unmarked or third-party build is named as unverified), a failed OVAL download without a copy (an error, not "nothing found"), a good download without entries, an old copy after failed downloads and old Launchpad and GitHub answers (their own age, also in the status), a copy of unknown time, the radar keeping the time of its last good download; data of unknown age (a copy without its time and failed downloads, twice and six days apart: no time in the status, at least a warning, a danger kept, the summary in both languages; nothing found in them; known old and fresh times; a state without `data_at`) |
| `test/status_test.py` | the status (schema 1) of every recorded host (`checked_at` and `stale_after` optional, but valid when there) in both languages: fields, ids, links, states and the overall state, nothing private, no German in English; checks that did not run, Debian, other systems, end of support; `gaps-status.py`: languages, no file, a broken file, wrong calls (64), unreadable (77), well within 2 seconds; `gaps-scan.py --status` (the second scan gets the first one's file); the items `cpu` (info in a VM, a warning for this server), `firmware` and `snaps` (only with a finding); `dpkg`, `boot`, `keys`, `uu` only with a finding, their states and texts in both languages (old kernels, a key that expires and a conffile as info, under 14 days a warning); acknowledged findings left out of the items (“6 acknowledged”), ended and changed ones counted again, no item when every finding of such a check is acknowledged; findings beyond the list (`more`) counting while the listed ones are acknowledged, with some listed ones open, and none beyond it, in both languages |
| `test/page_test.js` | the page in jsdom with the `scan-*.json` fixtures: cards and their order, overview, “No findings”, “Not checked”, page messages (no admin, no state, old state, software changed, failed and running scans, other systems, newer formats), the first check by itself, Refresh, the timer dialog, links, escaping, the watch, both languages and every text key; the menu icon (the recorded hosts in both languages, no file, a broken one, an item worse than the whole, out of date, the check again at 24 hours, what the board ignores), the page loaded hidden (nothing run, the first check only once shown), a link while the page is hidden; the network data after a failed fetch without a copy (under “Not checked”, not “No findings”), an old copy (its age on the card and at the top, partly checked without findings), packages of unclear origin, a state of 0.4.1 without `data_at`; data of unknown age (neither “0 hours old” nor the radar's run as their time, the reason under “No findings”, the menu's warning and tooltip); the cards `cpu`, `firmware` and `snaps` for a VM, a physical server and what the hosts do not have, escaped, in both languages; phased updates (the card first, PackageKit's message with the package and version, the other updates it blocks, the share of the rollout, the commands to copy and no button, the setting said instead of offered, odd names kept out of the command, escaped, nothing deferred and the setting under “No findings”, both languages); upkeep gone wrong (the cards `dpkg`, `boot`, `keys`, `uu` in their place, the commands, both languages), “seen since” only for findings an earlier scan saw, the four under “No findings”, a keyring not read named there; acknowledged findings (marked with day and reason, apart in the overview, the dialog with the day between today and 90 days ahead and the reason on stdin, a day out of range refused before anything runs, taken back, ended and changed ones said, no buttons without administrative access, German); cards with findings beyond their list (`more`: dpkg, local, phased) open in the overview while those listed are acknowledged; acknowledging firmware updates and the Package-Blacklist and held packages of the automatic updates (open, acknowledged, ended, changed, escaped, the dialog with the device, no buttons without administrative access but the marks, German); keyrings with the keys `Signed-By` selects, keys in a sources file and a selection nothing matches (both languages, escaped, the dialog naming the key) |
| `test/contrast_test.py`, `test/fonts_test.py` | WCAG contrast of every colour pair in light and dark; every font the page uses ships with it |
| `test/scenarios.sh` | CI (job `scenarios`), in Debian 12/13 and Ubuntu 22.04/24.04/26.04 containers: a held package, a package without a source, a source without lists, files outside apt, a hidden folder, the reboot flag, a Package-Blacklist, a package whose postinst fails (half configured); the scan as root, twice (`since` kept), and as a user; the status read by a user; never `apt-get` from `/usr/local`; `cpu` and `firmware` skipped in the container, no snaps, no kernel in `/boot`; the keyrings of the image read by gpg as root and as a user; unattended-upgrades never ran; the held package acknowledged with `gaps-accept.py` as root (a user gets 77), marked by the next scan and left out of the status |
| `test/cockpit-setup.sh`, `test/cockpit-session.py` | CI (job `cockpit`): a real Cockpit with systemd on a throw-away runner, Playwright with Chromium: the page in the menu, the first check by itself through the service (no network), findings of the setup on the page, Refresh, the timer set up and switched off from the page, a user without administrative access in German, the status through the manifest's command as a user, a link `#/restart` at its card; since 0.2.0 the page loaded hidden after the login without checking, the menu icon as `gaps-status.py status` says (English, and German before the page is opened), `cockpit.jump` into the loaded page (another card while it is shown, a card while it is hidden, no reload); since 0.4.0 `cpu`, `firmware` and `snaps` in the real service (the runner is a VM); since 0.7.0 the held package acknowledged and taken back through the page (`accepted.json` 0644, the finding marked, the status item `ok`); no JavaScript or resource errors beyond Cockpit's own |
| `tools/check-units.sh` | `systemd-analyze verify`, and `systemd-analyze security` exposure at most 5.0 |
| `tools/check-version.sh`, `tools/check-design-files.sh` | version, changelog, shared design files |

Fixtures: `test/fixtures/capture.sh` records the commands' output on a host (read only);
`test/fixtures/import_capture.py` turns it into a scenario without host names and with neutral names
for files outside apt; `test/fixtures/make_scans.py` writes the `scan-*.json` the page tests and the
preview read. `scan-resolute-nodesource-phased.json` is the recorded host during a phased rollout
(`fakesys.phased_results`: systemd 259.9 at 10 % beside three regular updates, as on the recorded
Ubuntu 26.04 hosts on 2026-10-20). `scan-noble-held-upkeep.json` is the recorded host after
upkeep went wrong (`fakesys.upkeep`: `/boot` of its own nearly full when the kernel update came,
the kernel half configured, unattended-upgrades failed in dpkg, two old kernels, and the keyring of
GitHub CLI with only the key that expired on 2026-09-06). `scan-noble-held-accepted.json` is the
recorded host with acknowledgements (`fakesys.accepted_files`): the six Docker packages held until
the maintenance window of 2026-11-01, and `tsa`, which only the provider can fix. `capture.sh` keeps the keys of `apt-config
dump` that the scan reads (unattended-upgrades, `APT::Periodic`, the phasing keys), nothing else of
it; since 0.6.0 also the sizes in `/boot` and its room, `/var/lib/dpkg/updates`, the end of the log
of unattended-upgrades, the sources files (credentials removed) and gpg's view of their keyrings
(public keys). A key inside a sources file is not recorded: give such a scenario
`commands/gpg-stdin.txt` by hand. The data of 0.6.0 in the three recorded scenarios were read on the
same hosts on 2026-10-21, their log dates moved to the scenarios' clock.
