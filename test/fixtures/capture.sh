#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Records, on a real Debian or Ubuntu host, the raw output of the fixed commands Update Gaps
# runs, for new test scenarios (test/fixtures/import_capture.py turns it into one).
#
#   sudo bash test/fixtures/capture.sh        -> ./update-gaps-capture.tar.gz
#
# Only reads. It runs every command the scan runs, plus `pro security-status` once without
# network (systemd-run, as the scan service does), and writes nothing but a temporary folder and
# the archive in the current directory. Credentials in source URIs are removed; host names are
# removed later by the import. Look at the archive before you share it.
set -u
export LC_ALL=C TZ=UTC PATH=/usr/sbin:/usr/bin:/sbin:/bin
strip() { sed -E 's#(https?://)[^/@ ]+@#\1***@#g'; }
ms() { echo $(( $(date +%s%N) / 1000000 )); }
dest=$PWD/update-gaps-capture.tar.gz
out=$(mktemp -d) || exit 1
trap 'rm -rf -- "${out:?}"' EXIT
cd "$out" || exit 1
hostname > hostname.txt
cp /etc/os-release os-release
uname -r > uname-r.txt
for k in /boot/vmlinuz-*; do [ -e "$k" ] && basename "$k"; done > boot.txt
t=$(ms); apt-get -s -o Debug::NoLocking=1 dist-upgrade > apt-get-s-dist-upgrade.txt 2> apt-get-s-dist-upgrade.err; echo "dist-upgrade $(( $(ms) - t ))" >> timings.txt
apt-mark showhold > apt-mark-showhold.txt
t=$(ms); apt-cache policy 2> /dev/null | strip > apt-cache-policy.txt; echo "policy $(( $(ms) - t ))" >> timings.txt
dpkg-query -W -f '${binary:Package}\t${Version}\t${source:Package}\t${db:Status-Abbrev}\t${Architecture}\n' > dpkg-query.txt
t=$(ms); awk -F '\t' '$4 ~ /^[ih]i/ {print $1}' dpkg-query.txt | xargs apt-cache policy 2> /dev/null | strip > apt-cache-policy-installed.txt; echo "policy-installed $(( $(ms) - t ))" >> timings.txt
t=$(ms); apt-get indextargets 2> /dev/null | strip > indextargets.txt; apt-get indextargets --no-release-info 2> /dev/null | strip > indextargets-all.txt; echo "indextargets $(( $(ms) - t ))" >> timings.txt
ls -1 /var/lib/apt/lists > lists.txt
for f in /var/lib/apt/lists/*InRelease /var/lib/apt/lists/*_Release; do
  [ -e "$f" ] || continue
  printf '%s\t%s\t%s\t%s\n' "$(basename "$f")" "$(stat -c %Y "$f")" "$(grep -m1 '^Date:' "$f" | cut -c7-)" "$(grep -m1 '^Valid-Until:' "$f" | cut -c14-)"
done > inrelease.txt
for p in /var/lib/apt/periodic/* /var/lib/apt/lists/partial /var/lib/dpkg/status /var/run/reboot-required /var/run/reboot-required.pkgs; do
  [ -e "$p" ] && printf '%s\t%s\n' "$p" "$(stat -c %Y "$p")"
done > stamps.txt
[ -f /var/run/reboot-required.pkgs ] && cp /var/run/reboot-required.pkgs reboot-required.pkgs
systemctl show apt-daily.service apt-daily-upgrade.service -p Id -p Result -p ExecMainExitTimestamp -p ExecMainStatus > systemctl-show.txt 2>&1
systemctl is-enabled apt-daily.timer apt-daily-upgrade.timer unattended-upgrades.service > systemctl-is-enabled.txt 2>&1
journalctl -u apt-daily.service --since -3d -o short-iso --no-pager 2> /dev/null | strip > journal-apt-daily.txt
apt-config dump 2> /dev/null | grep -E '^(Unattended-Upgrade::|APT::Periodic::)' > apt-config.txt
t=$(ms); timeout 120 systemd-run --quiet --wait --pipe --collect -p PrivateNetwork=yes -p ProtectSystem=strict \
  -p ReadWritePaths=-/var/log/ubuntu-advantage.log pro security-status --format json > pro.json 2> pro.err; echo "pro $? $(( $(ms) - t ))" >> timings.txt
t=$(ms); timeout 120 needrestart -b -r l > needrestart.txt 2> needrestart.err; echo "needrestart $? $(( $(ms) - t ))" >> timings.txt
for d in /usr/local/bin /usr/local/sbin /opt/*/bin; do
  [ -d "$d" ] || continue
  for f in "$d"/*; do
    [ -e "$f" ] || [ -L "$f" ] || continue
    first=""
    if [ -f "$f" ] && [ ! -L "$f" ]; then
      first=$(head -c 128 "$f" 2> /dev/null | head -n 1 | tr -d '\r' | grep -E '^#!' || true)
      magic=$(head -c 4 "$f" 2> /dev/null | od -An -tx1 | tr -d ' \n')
    else
      magic=""
    fi
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$f" "$(stat -c %F "$f")" "$(stat -c %Y "$f")" "$(stat -c %a "$f")" "$magic" "$first" "$(readlink "$f" || true)"
  done
done > outside.txt
for c in ubuntu debian; do [ -f "/usr/share/distro-info/$c.csv" ] && cp "/usr/share/distro-info/$c.csv" "distro-info-$c.csv"; done
for p in $(cat apt-mark-showhold.txt); do zgrep -h -E " (install|upgrade) $p:" /var/log/dpkg.log* 2> /dev/null; done | sort > dpkg-log-held.txt
tar -czf "$dest" -C "$out" .
echo "$dest"
