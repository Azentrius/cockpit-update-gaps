# Changelog

## 0.3.0 – 2026-10-20

Cards open and close, and the page remembers which are closed.

- **Cards fold:** every card with findings opens and closes through its title (a button with
  `aria-expanded`, by keyboard too). The overview, “No findings” and “Not checked” stay open.
- **Remembered in the browser:** which cards are closed is kept in this browser
  (`localStorage`, key `update-gaps:collapsed`), not on the server; new cards come open. A chip of
  the overview or a link of the Status Board opens the card it leads to.

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
