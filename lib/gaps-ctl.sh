#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Update Gaps, the Cockpit add-on: the scan service and its timer, from the page.
#
# Called by the page through cockpit.spawn with a FIXED set of arguments only:
#   gaps-ctl.sh status           one JSON object on stdout (read-only, any user)
#   gaps-ctl.sh scan             run update-gaps-scan.service now and wait for it (root)
#   gaps-ctl.sh install timer    enable update-gaps-scan.timer, then run a scan (root)
#   gaps-ctl.sh remove timer     disable update-gaps-scan.timer (root)
#   gaps-ctl.sh install radar    enable update-gaps-radar.timer (network data), fetch, scan (root)
#   gaps-ctl.sh remove radar     disable update-gaps-radar.timer; its data stay until out of date (root)
#   gaps-ctl.sh radar            fetch the network data now, then scan (root)
# Everything else is rejected (exit 64). Nothing here changes the system beyond the
# add-on's own timers; the scan only reads (gaps-scan.py), the radar runs unprivileged.
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
RADAR_SERVICE=update-gaps-radar.service
RADAR_TIMER=update-gaps-radar.timer
RADAR_FILE=/var/lib/update-gaps-radar/radar.json
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

timer_state() {
    if [ -d /run/systemd/system ] && unit_exists "$1"; then
        if systemctl is-active --quiet "$1" 2> /dev/null; then echo active; else echo inactive; fi
    else
        echo missing
    fi
}

timer_next() {
    [ "$(timer_state "$1")" = active ] || return 0
    iso "$(systemctl show "$1" -p NextElapseUSecRealtime --value 2> /dev/null || true)"
}

is_running() { [ "$(systemctl is-active "$1" 2> /dev/null || true)" = activating ] && echo 1 || echo 0; }

opt_str() { if [ -n "$1" ]; then json_str "$1"; else printf null; fi; }

do_status() {
    is_root=0; [ "$(id -u)" = 0 ] && is_root=1
    timer=$(timer_state "$TIMER"); next=$(timer_next "$TIMER")
    radar=$(timer_state "$RADAR_TIMER"); radar_next=$(timer_next "$RADAR_TIMER")
    settings=""; [ -e "$SETTINGS" ] && settings=$SETTINGS
    # The radar's data live below /var/lib/private, which only root can enter.
    radar_file=""; [ "$is_root" = 1 ] && radar_file=$(mtime_iso "$RADAR_FILE")
    printf '{"root": %s, "timer": %s, "next": %s, "running": %s, "state_file": %s, "dpkg_status_mtime": %s, "settings": %s, "radar": %s, "radar_next": %s, "radar_running": %s, "radar_file": %s}\n' \
        "$(json_bool "$is_root")" "$(json_str "$timer")" "$(opt_str "$next")" "$(json_bool "$(is_running "$SERVICE")")" \
        "$(json_bool "$( [ -e "$STATE" ] && echo 1 || echo 0)")" \
        "$(opt_str "$(mtime_iso /var/lib/dpkg/status)")" "$(opt_str "$settings")" \
        "$(json_str "$radar")" "$(opt_str "$radar_next")" "$(json_bool "$(is_running "$RADAR_SERVICE")")" \
        "$(opt_str "$radar_file")"
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

fetch_radar() {
    msg "Hole die Netzdaten (unprivilegiert, $RADAR_SERVICE) …" "Fetching the network data (unprivileged, $RADAR_SERVICE) …"
    if ! systemctl start "$RADAR_SERVICE"; then
        journalctl -u "$RADAR_SERVICE" -n 10 --no-pager -o cat 2> /dev/null || true
        die 1 "Der Abruf ist fehlgeschlagen: journalctl -u $RADAR_SERVICE" "Fetching failed: journalctl -u $RADAR_SERVICE"
    fi
    journalctl -u "$RADAR_SERVICE" -n 1 --no-pager -o cat 2> /dev/null || true
    run systemctl start "$SERVICE"
}

do_install_radar() {
    need_root
    unit_exists "$RADAR_TIMER" || die 2 "Der Timer $RADAR_TIMER fehlt (Paket cockpit-update-gaps)." \
                                         "The timer $RADAR_TIMER is missing (package cockpit-update-gaps)."
    run systemctl enable --now "$RADAR_TIMER"
    fetch_radar
    msg "Netzdaten eingerichtet: täglich." "Network data set up: daily."
}

do_remove_radar() {
    need_root
    unit_exists "$RADAR_TIMER" || die 2 "Der Timer $RADAR_TIMER fehlt." "The timer $RADAR_TIMER is missing."
    run systemctl disable --now "$RADAR_TIMER"
    msg "Netzdaten ausgeschaltet. Der letzte Stand bleibt, bis er veraltet." \
        "Network data switched off. The last data stay until they are out of date."
}

do_radar() {
    need_root
    unit_exists "$RADAR_SERVICE" || die 2 "Der Dienst $RADAR_SERVICE fehlt." "The service $RADAR_SERVICE is missing."
    fetch_radar
    msg "Fertig." "Done."
}

USAGE_DE="Aufruf: gaps-ctl.sh status | scan | radar | install timer|radar | remove timer|radar"
USAGE_EN="usage: gaps-ctl.sh status | scan | radar | install timer|radar | remove timer|radar"

[ $# -le 2 ] || die 64 "$USAGE_DE" "$USAGE_EN"
case "${1:-} ${2:-}" in
    "status ") do_status ;;
    "scan ") do_scan ;;
    "radar ") do_radar ;;
    "install timer") do_install_timer ;;
    "remove timer") do_remove_timer ;;
    "install radar") do_install_radar ;;
    "remove radar") do_remove_radar ;;
    *) die 64 "$USAGE_DE" "$USAGE_EN" ;;
esac
