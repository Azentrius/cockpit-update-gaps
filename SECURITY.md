# Security Policy

## Reporting a vulnerability

Please do **not** open a public issue for security problems.

Report them privately through GitHub instead:
[Report a vulnerability](https://github.com/Azentrius/cockpit-update-gaps/security/advisories/new)
(tab **Security → Report a vulnerability** in this repository).
If you cannot use GitHub, write to **support@azentrius.com**.

Please include:

- what is affected (page, helper script, systemd unit or package; version or commit),
- steps to reproduce,
- the impact you expect.

Do not send real credentials, tokens, passwords or other private data from your servers. Redact logs
and command output before you attach them (host names, IP addresses, repository credentials); a
made-up example is just as good.

We aim to acknowledge reports within 7 days. This is a small project, so a fix may take longer; we
will keep you informed and credit you in the advisory unless you prefer to stay anonymous. Please keep
the details private until a fixed release is out.

## Supported versions

| Version | Security fixes |
|---|---|
| Newest release | yes |
| Older releases | no |

The add-on is in its 0.x line: only the newest release is supported. Security fixes go into a new
patch or minor release of the latest release line; older releases get no backports. The `main` branch
is a development state, not a supported installation.

To stay on a supported version, upgrade to the newest release:

```bash
# From packages.azentrius.com (Debian, Ubuntu; see README)
sudo apt update && sudo apt install cockpit-update-gaps

# From the files of the release: check the download first, then install it
sha256sum --ignore-missing -c SHA256SUMS
gh attestation verify <file> --repo Azentrius/cockpit-update-gaps
sudo apt install ./cockpit-update-gaps_X.Y.Z-1_all.deb
```

## How fixes are announced

A fixed vulnerability is announced with:

- a GitHub security advisory in this repository (tab **Security**), with a CVE ID where one is assigned,
- an entry in `CHANGELOG.md` marked as a security fix,
- the release notes of the fixed release, which come from `CHANGELOG.md`.

packages.azentrius.com takes the new release within an hour. To be notified, watch this repository's
releases on GitHub (**Watch › Custom › Releases**).

## Especially relevant

The helpers in `lib/` run as root, from Cockpit and from the add-on's systemd service. Reports are
particularly welcome for:

- ways to make the page run commands or arguments other than the fixed helper verbs,
- anything that makes the root helpers run or import code from a directory others can write,
- package names, versions, file names or other data from the system that reach the page as markup or
  script (the Cockpit session can act as root),
- credentials from package sources or other secrets that end up in the add-on's state file, which
  every local user can read,
- the scan service reaching the network although it runs with `PrivateNetwork=yes`,
- data from security-metadata.canonical.com, api.launchpad.net or api.github.com that the root scan
  takes as more than checked data, or that reaches the page as markup or script, and the radar
  running as root,
- `gaps-ctl.sh accept`/`unaccept` or `gaps-accept.py` writing anything but
  `/var/lib/update-gaps/accepted.json`, accepting a ref or a day it should refuse, taking the reason
  from anywhere but stdin, or an acknowledgement that still hides a finding after it changed in a
  way that matters,
- `pro` or `gpg` running with root's rights, or writing outside the fresh home the scan gives them
  (it runs them as `nobody`),
- `/etc/update-gaps.conf` being accepted when others than root can write it,
- the package `cockpit-update-gaps` (its install and removal scripts) or `make install` overwriting or
  exposing files it should not touch,
- release archives, packages or `SHA256SUMS` that do not match the tagged source.
