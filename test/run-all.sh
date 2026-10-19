#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Runs every offline test: no root, no network, no apt run on this machine (the helpers read
# recorded output of real hosts, test/fixtures/).
#   cd test && npm ci && ./run-all.sh
# The scenarios in real containers are separate: scenarios.sh (CI, job scenarios).
set -u
cd "$(dirname "$0")" || exit 2

if [ ! -d node_modules/jsdom ] && [ -z "${NODE_PATH:-}" ]; then
    echo "jsdom missing – run first: (cd test && npm ci)" >&2
    exit 2
fi

fail=0
run() {
    local name=$1; shift
    local log
    log=$(mktemp)
    if "$@" >"$log" 2>&1; then
        echo "PASS  $name"
    else
        echo "FAIL  $name"
        sed 's/^/      | /' "$log"
        fail=1
    fi
    rm -f "$log"
}

run "python: parsers, versions, unattended-upgrades" python3 lib_test.py
run "python: checks against recorded hosts"           python3 scan_test.py
run "python: status for the Status Board, its verb"    python3 status_test.py
run "python: syntax lib/*.py"                          python3 -c 'import ast, glob; [ast.parse(open(f).read(), f) for f in glob.glob("../lib/*.py")]'
run "shell:  syntax of the shell scripts"              bash -c 'for f in ../lib/*.sh ../tools/*.sh ../packaging/scripts/* *.sh fixtures/*.sh; do sh -n "$f" || exit 1; done'
run "shell:  gaps-ctl.sh status (JSON), wrong calls"   bash -c 'sh ../lib/gaps-ctl.sh status | python3 -c "import json, sys; d = json.load(sys.stdin); assert set(d) >= {\"root\", \"timer\", \"running\", \"dpkg_status_mtime\"}" && ! sh ../lib/gaps-ctl.sh nonsense 2>/dev/null && ! sh ../lib/gaps-ctl.sh scan now please 2>/dev/null'
run "page:   cards, messages, refresh, timer, texts"   node page_test.js
run "design: contrast (light + dark)"                  python3 contrast_test.py
run "design: fonts ship with the add-on"               python3 fonts_test.py
run "repo:   version + changelog"                      sh ../tools/check-version.sh
run "repo:   shared design files"                      sh ../tools/check-design-files.sh

echo
if [ $fail = 0 ]; then echo "ALL TESTS PASSED"; else echo "THERE ARE FAILURES"; fi
exit $fail
