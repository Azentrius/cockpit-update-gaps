# Changelog

## 0.6.0 – 2026-10-21

Four new checks for what keeps updates back on the server itself, and since when each finding has
been there.

- **New card “Packages dpkg left half done”:** packages dpkg left unpacked, half configured,
  waiting for triggers or in need of a reinstall (its status letters in `dpkg-query -W`), and a
  run of dpkg that was interrupted (its journal in `/var/lib/dpkg/updates`). Until that is
  finished every update fails, Software Updates included, with a message that does not say why.
  The card gives `sudo dpkg --configure -a` and `sudo apt-get -f install` to copy.
- **New card “Room for the next kernel in /boot”:** too little room for the next kernel update
  (1.5 times the largest kernel with its initramfs; such an update stops halfway and leaves dpkg
  half done), and the kernels apt's autoremove no longer keeps; `sudo apt autoremove --purge` to
  copy.
- **New card “Signing keys of the sources”:** the keyrings of `Signed-By`, or apt's trusted ones
  for a source without it, as `gpg --show-keys` shows them, run as `nobody` in a fresh home: a
  keyring whose last signing key has expired (apt then reads the source no more and its updates
  drop out of every list, as on hosts that kept only the key of GitHub CLI that expired on
  2026-09-06), one that expires within 60 days, and a keyring file that is missing.
- **New card “Automatic updates: what the last run did”:** from the log of unattended-upgrades and
  `apt-daily-upgrade.service`: no finished run, none for 72 hours, a failed run with its error
  lines, a stopped service, packages kept back or left for an upgrade by hand because their
  configuration file was changed. apt-daily's download run, which writes no end to the log, is
  left out.
- **Since when:** every finding that stays the same from one scan to the next carries the time a
  scan first saw it (`since`, kept in `scan.json` only); the page shows “seen since <date>” once an
  earlier scan saw it.
- **Status Board:** the items `dpkg`, `boot`, `keys` and `uu`, only with a finding.
- **AppStream:** screenshots of the page.
- **Formats:** `scan.json` has the checks `dpkg` and `boot` after `phased`, `keys` after `lists`
  and `uu` after `auto`, and `since` on their findings and those of most other checks;
  `gaps-scan.py --output` reads its previous file for it.
- **Tests:** the new data of the three recorded hosts, read on them on 2026-10-21; a scenario of
  upkeep gone wrong (`/boot` full, a kernel half configured, a failed run, an expired key); in the
  containers a package whose postinst fails, gpg reading the image's keyrings as root and as a
  user, and a second scan that keeps `since`.

## 0.5.0 – 2026-10-21

Phased updates that make Software Updates fail, explained with the commands that get around them;
network data that failed or got old no longer look fresh.

- **New card “Phased updates Software Updates cannot install”:** when Ubuntu rolls an update out
  in phases and apt defers it on this server (“deferred due to phasing”), Software Updates still
  lists it, refuses it when it installs and fails on every other update with it, security updates
  included (PackageKit ignores phasing, LP #1466587). The card quotes the message (“Package id
  '<name>;<version>;…' is not available as an update candidate”), names the deferred packages with
  the installed and the deferred version and the share of the rollout (`apt-cache policy`), counts
  the updates they block, and gives commands to copy: `sudo apt-get upgrade` for the rest,
  `sudo apt-get install --only-upgrade <packages>` for the phased ones ahead of the rollout, and
  the host-wide `APT::Get::Always-Include-Phased-Updates` with its price (the server is among the
  first of every rollout). The page installs nothing. Whether that setting, or its opposite
  `Never-Include-Phased-Updates`, is on comes from `apt-config dump`, read locally; when it is,
  the page says so instead of offering it. The card comes first: it keeps the other updates back.
- **Failed and old network data:** when Canonical's CVE list could not be fetched and there is no
  earlier copy, `cve` is listed under “Not checked”, no longer under “No findings”. The age of the
  network data comes from their last good fetch, not from the radar's daily run, so old data show
  their age on the cards, at the top of the page and in the status (`checked_at` of the data,
  out of date after 72 hours); nothing found in old data is “partly checked”. A copy whose time
  is lost counts as of unknown age: no time is made up, and the status item is at least a warning.
- **Packages the archive has moved past stay checked:** a newer version from the distribution
  stands in for the origin of a distribution build; a package whose origin stays unclear is named
  on the cards instead of being left out.
- **Firmware:** fwupd's metadata time is read from `Mtime`, so old metadata show.
- **Formats:** `scan.json` has the check `phased` after `updates`; the network-data checks carry
  `radar.data_at` and `radar.errors`. States and network data of 0.4.1 still read.

## 0.4.1 – 2026-10-21

The descriptions catch up with what the add-on checks since 0.2.0 and 0.4.0.

- **Package and AppStream description:** they name the CPU vulnerabilities, firmware updates and
  snaps, and the network data; Cockpit's list of applications shows the same text.
- **README:** the network data in the introduction and the overview, the radar in the
  architecture and the parts, the items the Status Board gets, red in the menu also for a
  security issue Ubuntu rates critical, uninstalling with both timers, and the new known limits
  (network data for Ubuntu, microcode in a VM, firmware only through the LVFS).
- **INTERNALS and CONTRIBUTING:** the radar's helpers and calls in the overview tables; the
  add-on never installs a tool it could use; snapd is not woken without snaps.

## 0.4.0 – 2026-10-20

The machine itself: CPU vulnerabilities the kernel reports, firmware updates from fwupd and snaps
that are not refreshed. All local, no network.

- **CPU vulnerabilities:** what `/sys/devices/system/cpu/vulnerabilities` reports as vulnerable,
  only partly mitigated or unknown, quoted word for word with a common name, plus the CPU and its
  loaded microcode. In a virtual machine a missing microcode is the provider's to fix (the
  hypervisor supplies it): the Status Board shows it as information, not as a warning. On a
  physical server the card names the board and BIOS, and warns when the microcode package for the
  CPU is missing (on Debian it is in `non-free-firmware`). Protections switched off on the kernel
  command line (`mitigations=off` and others) are a warning everywhere.
- **Firmware:** with fwupd installed, the updates in its local metadata (device, versions,
  urgency, CVEs), metadata older than 30 days and `fwupd-refresh.timer` switched off. Without
  fwupd “Not checked” says so; in a VM the provider looks after the firmware.
- **Snaps:** held snaps, refreshes held for all, put off while an app runs or failed in the last
  seven days, and app snaps on a base whose Ubuntu release is out of support. snapd is asked only
  when snaps are installed, since a request would start it through its socket.
- In a container the CPU and the firmware are the host's: both are skipped there.
- “Not checked” no longer lists snaps and firmware as such.

## 0.3.0 – 2026-10-20

Cards open and close, and the page remembers which are closed.

- **Cards fold:** every card with findings opens and closes through its title (a button with
  `aria-expanded`, by keyboard too). The overview, “No findings” and “Not checked” stay open.
- **Remembered in the browser:** which cards are closed is kept in this browser
  (`localStorage`, key `update-gaps:collapsed`), not on the server; new cards come open. A chip of
  the overview or a link of the Status Board opens the card it leads to.
- **Radar:** at most 100 source packages per run go to Launchpad, those with the oldest answers
  first; the others keep their answers until a later run. A host with many packages installed by
  hand (seen on a CI runner) took longer than ten minutes before.

## 0.2.0 – 2026-10-20

Network data: security issues Ubuntu has not fixed yet, fixes upstream and newer versions elsewhere
in Ubuntu, for selected packages, off until set up on the page. And Cockpit's menu shows the state
of Update Gaps next to its entry.

- **Radar:** `update-gaps-radar.service` runs once a day as an unprivileged user of its own
  (`DynamicUser`, no capabilities, exposure 1.1) and writes `/var/lib/update-gaps-radar/radar.json`.
  It fetches Canonical's CVE OVAL of the release (only the release name leaves the server), the
  published versions of the selected source packages from Launchpad, and the releases of a fixed
  list of projects from GitHub. A source that fails keeps its last answers, marked as such; a
  service that asks to slow down is left alone for that run.
- **Selected packages:** a fixed list (Cockpit, OpenSSH, sudo, Docker, containerd, runc, restic,
  skopeo, nginx, Caddy, WireGuard) and packages installed by hand from universe and multiverse.
  The root scan works the selection out itself and reads `radar.json` as data only.
- **New cards:** “Security issues Ubuntu has not fixed yet” (open CVEs with Ubuntu's priority, and
  fixes newer than the installed version that do not reach this server), “Fixes upstream, not here
  yet” (newer releases whose notes name a CVE or GHSA; a fix still open in Ubuntu is marked) and
  “Newer versions elsewhere in Ubuntu” (another pocket of this release, or a later release).
- **The page:** the overview shows the network data (off, daily, last fetched) with Set up, Fetch
  now and Switch off; the set-up dialog says what leaves the server. Old network data are told.
- **Status for the Status Board:** a `cve` item (info, warning for high priority or a fix that
  does not reach the server, danger for critical) once the network data are set up.
- `gaps-ctl.sh`: the verbs `install radar`, `remove radar` and `radar`; its status names the
  radar's timer and data.
- **Status in Cockpit's menu:** the entry “Update Gaps” carries Cockpit's own status icon (blue:
  something to know, yellow: something to do or a state older than 24 hours, red: support ended or a critical security issue)
  with the summary of the status as its tooltip, in the session language; nothing found, no icon.
  It is judged as the Status Board judges the status: never better than an item, and an item older
  than its `stale_after` at least a warning, checked again the moment it turns old. For this
  Cockpit loads the page hidden right after the login (`preload`, as for its own Software Updates
  page); until it is opened, the page only watches `/var/lib/update-gaps/status.json`
  (`plugin/menu-status.js`). The first check by itself, the helpers and the state file wait until
  the page is shown.
- **Fix: a link while the page is hidden.** Cockpit keeps a loaded page and changes only its
  location when the Status Board jumps to it again, and it may do so before the page is shown
  again. The scroll to the card then came too early and was lost; it now waits until the page is
  shown.
- **Tests:** `test/page_test.js`: the icon for the recorded hosts in English and German, no file
  and a broken one, an item worse than the whole, a state out of date (in both languages, with the
  time), what the board ignores, the check again at 24 hours, the page loaded hidden (nothing run,
  the first check only once shown, no second start), a link that comes while the page is hidden.
  The Cockpit job in CI: the page loaded hidden after the login without checking, the icon as
  `gaps-status.py status` says (English, and German before the page is opened), and `cockpit.jump`
  into the loaded page, to another card while it is shown and into it while it is hidden.

## 0.1.0 – 2026-10-20

First release: where a Debian or Ubuntu server misses updates although Cockpit's Software Updates
lists none, with the reason for every finding. Read only.

- **Checks:** held packages and what they miss, fixes only with Ubuntu Pro, a pending restart
  (kernel, microcode, services on old libraries, the reboot flag), missing, left-over, old or expired
  package lists and errors of `apt-daily.service`, packages without a source, sources and packages
  the automatic updates leave out (`Allowed-Origins`, `Origins-Pattern`, `Package-Blacklist`, held
  packages), backports not installed, software outside the package manager, the end of support.
- **The page:** an overview with the regular updates and the areas with findings, one card per area
  with “Why Software Updates does not show it”, “What you can do” and the source, then “No findings”
  and always “Not checked”. The time of the check and of the package lists is always shown. English
  and German, light and dark, phones.
- **The scan:** a local service without network access (`update-gaps-scan.service`), started by
  “Refresh” and, once set up from the page, every 6 hours. The state is readable without
  administrative access. `pro security-status` runs as `nobody`, so the service may write nothing
  outside its own folder.
- **Status for the Status Board:** after every check the service writes `status.json` in the status
  format all Azentrius add-ons share; `gaps-status.py status --lang en|de` reads it without
  administrative access, and `manifest.json` names the command (`azentrius.status`). A link of an
  item (`#/held`) opens the page at its card.
- **Settings:** `/etc/update-gaps.conf` hides known folders from “Software outside the package
  manager”.
- Tests against output recorded on real servers, scenarios in Debian and Ubuntu containers, and the
  page in a real Cockpit session in CI.
