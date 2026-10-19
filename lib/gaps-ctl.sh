#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Update Gaps, the Cockpit add-on: the scan service and its timer, from the page.
#
# Called by the page through cockpit.spawn with a FIXED set of arguments only:
#   gaps-ctl.sh status           one JSON object on stdout (read-only, any user)
#   gaps-ctl.sh scan             run update-gaps-scan.service now and wait for it (root)
#   gaps-ctl.sh install timer    enable update-gaps-scan.timer, then run a scan (root)
#   gaps-ctl.sh remove timer     disable update-gaps-scan.timer (root)
# Everything else is rejected (exit 64). Nothing here changes the system beyond the
# add-on's own timer; the scan itself only reads (gaps-scan.py).
#
# Lives in /usr/lib/cockpit-update-gaps (root-owned, from the package cockpit-update-gaps).
#
# Environment: GAPS_LANG=de|en, the language of this script's own messages.

set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
TZ=UTC
LC_ALL=C
export PATH TZ LC_ALL

SERVICE=update-gaps-scan.service
TIMER=update-gaps-scan.timer
STATE=/var/lib/update-gaps/scan.json
SETTINGS=/etc/update-gaps.conf

msg() { if [ "${GAPS_LANG:-en}" = de ]; then printf '%s\n' "$1"; else printf '%s\n' "$2"; fi; }
die() { code=$1; shift; msg "$@" >&2; exit "$code"; }

json_str() { printf '"%s"' "$(printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' | tr -d '\000-\037')"; }
json_bool() { if [ "$1" = 1 ]; then printf true; else printf false; fi; }
iso() { printf '%s' "$1" | sed -n -E 's/^[A-Za-z]{3} ([0-9]{4}-[0-9]{2}-[0-9]{2}) ([0-9]{2}:[0-9]{2}:[0-9]{2}) UTC$/\1T\2Z/p'; }
mtime_iso() { [ -e "$1" ] && date -u -d "@$(stat -c %Y "$1")" +%Y-%m-%dT%H:%M:%SZ 2> /dev/null || true; }

need_root() {
    [ "$(id -u)" = 0 ] || die 77 "Dafür wird administrativer Zugriff benötigt." "This needs administrative access."
}

unit_exists() { systemctl cat "$1" > /dev/null 2>&1; }

run() {
    printf '+ %s\n' "$*"
    "$@"
}

do_status() {
    is_root=0; [ "$(id -u)" = 0 ] && is_root=1
    timer=missing; next=""
    if [ -d /run/systemd/system ] && unit_exists "$TIMER"; then
        if systemctl is-active --quiet "$TIMER" 2> /dev/null; then timer=active; else timer=inactive; fi
        next=$(iso "$(systemctl show "$TIMER" -p NextElapseUSecRealtime --value 2> /dev/null || true)")
    fi
    running=0
    if [ "$(systemctl is-active "$SERVICE" 2> /dev/null || true)" = activating ]; then running=1; fi
    settings=""; [ -e "$SETTINGS" ] && settings=$SETTINGS
    printf '{"root": %s, "timer": %s, "next": %s, "running": %s, "state_file": %s, "dpkg_status_mtime": %s, "settings": %s}\n' \
        "$(json_bool "$is_root")" "$(json_str "$timer")" \
        "$( [ -n "$next" ] && json_str "$next" || printf null)" "$(json_bool "$running")" \
        "$(json_bool "$( [ -e "$STATE" ] && echo 1 || echo 0)")" \
        "$(m=$(mtime_iso /var/lib/dpkg/status); [ -n "$m" ] && json_str "$m" || printf null)" \
        "$( [ -n "$settings" ] && json_str "$settings" || printf null)"
}

do_scan() {
    need_root
    unit_exists "$SERVICE" || die 2 "Der Dienst $SERVICE fehlt (Paket cockpit-update-gaps)." \
                                     "The service $SERVICE is missing (package cockpit-update-gaps)."
    msg "Prüfe diesen Server …" "Checking this server …"
    if ! systemctl start "$SERVICE"; then
        journalctl -u "$SERVICE" -n 10 --no-pager -o cat 2> /dev/null || true
        die 1 "Die Prüfung ist fehlgeschlagen: journalctl -u $SERVICE" "The check failed: journalctl -u $SERVICE"
    fi
    msg "Fertig." "Done."
}

do_install_timer() {
    need_root
    unit_exists "$TIMER" || die 2 "Der Timer $TIMER fehlt (Paket cockpit-update-gaps)." \
                                   "The timer $TIMER is missing (package cockpit-update-gaps)."
    run systemctl enable --now "$TIMER"
    run systemctl start "$SERVICE"
    msg "Regelmäßige Prüfung eingerichtet: alle 6 Stunden." "Regular check set up: every 6 hours."
}

do_remove_timer() {
    need_root
    unit_exists "$TIMER" || die 2 "Der Timer $TIMER fehlt." "The timer $TIMER is missing."
    run systemctl disable --now "$TIMER"
    msg "Regelmäßige Prüfung ausgeschaltet. Der letzte Stand bleibt." "Regular check switched off. The last state stays."
}

[ $# -le 2 ] || die 64 "Aufruf: gaps-ctl.sh status | scan | install timer | remove timer" \
                       "usage: gaps-ctl.sh status | scan | install timer | remove timer"
case "${1:-} ${2:-}" in
    "status ") do_status ;;
    "scan ") do_scan ;;
    "install timer") do_install_timer ;;
    "remove timer") do_remove_timer ;;
    *) die 64 "Aufruf: gaps-ctl.sh status | scan | install timer | remove timer" \
              "usage: gaps-ctl.sh status | scan | install timer | remove timer" ;;
esac
