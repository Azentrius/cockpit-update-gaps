# Changelog

## 0.2.0 – 2026-10-20

Network data: security issues Ubuntu has not fixed yet, fixes upstream and newer versions elsewhere
in Ubuntu, for selected packages. Off until set up on the page.

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
