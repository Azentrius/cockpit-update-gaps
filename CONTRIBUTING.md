# Contributing

Bug reports, ideas and pull requests for Update Gaps are welcome. Security problems do not belong in
public issues: report them as described in [SECURITY.md](SECURITY.md). For a larger change, open an
issue first so we can agree on the approach.

## Setup

```bash
git clone https://github.com/Azentrius/cockpit-update-gaps.git
cd cockpit-update-gaps
(cd test && npm ci)                    # jsdom for the page tests
pip install -r test/requirements.txt   # pinned check tools: shellcheck, ruff, playwright
```

- The helpers need **Python ≥ 3.8, standard library only**, and POSIX `sh`. `ruff` checks Python 3.8
  syntax.
- The page is plain JavaScript without a build step.
- Node.js and npm (CI uses Node 22) are needed for the tests only.

## Tests and checks

```bash
make check                       # every offline test: helpers with fake commands, page under jsdom, version and changelog
make lint                        # shellcheck, ruff, systemd-analyze for the units, as in CI
make packages                    # .deb and .rpm in dist/ (needs dpkg-deb and rpmbuild)
python3 tools/preview/build.py   # the page with test data: tools/preview/out/update-gaps/index.html?scenario=noble-held&lang=en (or de)
```

The offline tests need no root and no network: the helpers run against fake `apt`, `apt-config`,
`dpkg`, `needrestart`, `pro`, `gpg`, `systemctl`, `journalctl`, `fwupdmgr` and snapd answers
(`test/fakesys.py`) and recorded files of `/sys`, `/proc` and `/boot` (with its free room,
`statvfs`) and the log of unattended-upgrades from real systems (`test/fixtures/`), and the radar
against a stub instead of the network services. The `test` workflow runs the lint, the tests and the
package build on every push and pull request; its job `test` has to be green before a merge. Its
other jobs: `python-min` runs the helper tests on Python 3.8, `scenarios` runs the helpers on Debian
12 and 13 and Ubuntu 22.04, 24.04 and 26.04 in throw-away containers, and `install` installs and
removes the packages on more distributions and checks that Ubuntu 20.04 and Rocky Linux 8 refuse
them.

## The page in a real Cockpit

The job `cockpit` installs Cockpit on a throw-away GitHub runner and drives the page through
Cockpit's login with Playwright (`test/cockpit-setup.sh`, `test/cockpit-session.py`): this build
installed with apt, the page in the menu, the first check by itself through the service, “Refresh”,
the regular check and the network data set up from the page, a finding acknowledged and taken back,
a user without administrative access, the links of the status, errors in the browser. It creates
users, holds a package and sets the reboot flag, so it runs only there, never on a machine you use.
Its summary lists the versions and every step; the artifact `cockpit-session` has screenshots. A
change to what the page does in Cockpit gets a step there.

## How the add-on is built

- **Read only.** The helpers never run `apt update`, install, remove or restart anything. They write
  only the add-on's own files in `/var/lib/update-gaps` (`scan.json`, `status.json`, and
  `accepted.json` through `gaps-accept.py`) and their locks. The only changes from the page are
  setting up the add-on's own timers (the regular check, the network data) and acknowledging
  findings, each as show → confirm → live output → result. The add-on never installs anything, not
  even a tool it could use (fwupd, needrestart): the page says what it could not check.
- **Root code only in `lib/`**, installed to `/usr/lib/cockpit-update-gaps` (root-owned). Nothing is
  ever run or imported from a directory others can write.
- **Root never on the network, network never as root.** The scan service runs with
  `PrivateNetwork=yes`; the network data come from the radar, an unprivileged service of its own
  (`DynamicUser`), whose file the scan reads as data only. The scan does not wake services that go
  to the network on their own either: snapd is asked only when snaps are installed.
- **Fixed verbs.** The page calls the helpers only with fixed commands. Every argument is checked in the
  helper. New verbs go into `docs/INTERNALS.md`.
- **Quote, do not judge.** A finding says what is missing, where the information comes from, why
  Cockpit's “Software Updates” does not show it and what one can do. An empty list never means “safe”,
  and the page always says what it did not check and how old its data is.
- **Formats are contracts.** `scan.json` and the helpers' JSON change together with the page, the
  fixtures in `test/fixtures/`, the tests and `docs/INTERNALS.md`. Code tolerates data one version
  older.
- **No build step, no runtime dependencies.** Python standard library, POSIX `sh`, JavaScript without
  a framework. `node_modules` is for the tests only.
- **Browser without network.** No CDNs, external fonts or images; the fonts ship with the add-on and
  Cockpit's strict CSP stays.
- **Shared design files** (`plugin/azentrius.*`, `plugin/icons.js`, the fonts) are byte-identical
  copies from another Azentrius add-on, pinned in `tools/design-files.sha256`. Do not edit them here.

## Requirements for a change

- **English and German.** Every user-facing text goes into `I18N.en` and `I18N.de` in
  `plugin/i18n.js`; the helpers emit codes, not prose, and the few messages of `lib/gaps-ctl.sh` go
  through `msg de en`. German addresses the user formally (“Sie”). The tests check that the English
  page contains no German.
- **English in the repository.** Code, comments, docs, commit messages and pull requests are in
  English; the only German is the translation and the tests that check it.
- **Tests** for new behaviour; `make check` and `make lint` green.
- **SPDX header** `SPDX-License-Identifier: Apache-2.0` in every new source file.
- **Versions and changelog** are the maintainer's: the pull request that raises the version adds its
  section to `CHANGELOG.md`. Describe user-visible changes in your pull request.
- **No private data.** No secrets, tokens, passwords, repository credentials, host names, IP
  addresses or other real server data in issues, pull requests, tests or fixtures.

## Pull requests

- Open them against `main`. `main` is protected: every change goes through a pull request and is
  squash-merged once the `test` check is green.
- The title becomes the commit on `main`: short, imperative, English, without a version number
  (e.g. "Show held packages with their newest version").
- Keep one topic per pull request and fill in the template: what and why, how it was tested.

## License

Update Gaps is licensed under the [Apache License 2.0](LICENSE); contributions are accepted under the
same license. Third-party material keeps its own license and is listed in [NOTICE](NOTICE); new
third-party material needs a compatible license and an entry there.
