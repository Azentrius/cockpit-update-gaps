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
python3 tools/preview/build.py   # the page with test data: tools/preview/out/update-gaps/index.html?lang=en (or de)
```

The offline tests need no root and no network: the helpers run against fake `apt`, `dpkg`,
`needrestart`, `pro`, `fwupdmgr` and snapd answers and recorded files of `/sys` and `/proc` from real
systems (`test/fixtures/`), and the radar against a stub instead of the network services. The
`test` workflow runs the lint, the tests and the package build on every push and pull request; it has
to be green before a merge.

## How the add-on is built

- **Read only.** The helpers never run `apt update`, install, remove or restart anything. They write
  only the add-on's own state (`/var/lib/update-gaps/scan.json`) and lock. The only changes from the
  page are setting up the add-on's own timers (the regular check, the network data), and they run as
  show → confirm → live output → result. The add-on never installs anything, not even a tool it
  could use (fwupd, needrestart): the page says what it could not check.
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
