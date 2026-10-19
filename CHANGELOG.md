# Changelog

## 0.1.0 – 2026-10-19

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
  administrative access.
- **Settings:** `/etc/update-gaps.conf` hides known folders from “Software outside the package
  manager”.
- Tests against output recorded on real servers, scenarios in Debian and Ubuntu containers, and the
  page in a real Cockpit session in CI.
