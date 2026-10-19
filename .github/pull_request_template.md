<!--
Title: short, imperative, English, without a version number. It becomes the commit on main.
Security problems: do not open a pull request, see SECURITY.md.
-->

## What and why

<!-- What does this change, and why? Link the issue if there is one. -->

## How tested

- [ ] `make check`
- [ ] `make lint`
- [ ] The page in the preview (`python3 tools/preview/build.py`) or in Cockpit (when `plugin/` changed)

<!-- Anything else you tried, and on which system. -->

## Checklist

- [ ] Every new or changed text exists in English and German (`I18N.en` and `I18N.de`, `msg de en`)
- [ ] Changed formats (`scan.json`, the helpers' JSON) are changed together with the page, `test/fixtures/`, the tests and `docs/INTERNALS.md`
- [ ] The helpers still only read: no `apt update`, no install, no restart, no network in the scan
- [ ] No secrets, tokens or real server data (host names, IP addresses, credentials) in code, tests, fixtures or this description
- [ ] SPDX header on every new source file
