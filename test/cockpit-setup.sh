#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Prepares a throw-away machine for test/cockpit-session.py (CI, test workflow, job cockpit;
# never a machine you use):
#   - two Cockpit users with the passwords given: ADMIN_USER in the sudo group, PLAIN_USER not,
#   - needrestart installed, a held package and the reboot flag, so the page has findings.
# Prints HELD (the held package) for the session test (KEY=value, for $GITHUB_ENV); all other
# output goes to stderr.
#
#   sudo env ADMIN_USER=… ADMIN_PW=… PLAIN_USER=… PLAIN_PW=… sh test/cockpit-setup.sh >> "$GITHUB_ENV"
set -eu
: "${ADMIN_USER:?}" "${ADMIN_PW:?}" "${PLAIN_USER:?}" "${PLAIN_PW:?}"
export DEBIAN_FRONTEND=noninteractive

# The GitHub runner image sets XDG_CONFIG_HOME=/home/runner/.config for everyone in
# /etc/environment: Cockpit's bridge, started for another user, then fails on the runner's
# config folder and the login ends with 401. The test users get their own.
if grep -q '^XDG_CONFIG_HOME=' /etc/environment 2> /dev/null; then
    echo "removing XDG_CONFIG_HOME from /etc/environment" >&2
    sed -i '/^XDG_CONFIG_HOME=/d' /etc/environment
fi
useradd -m -s /bin/bash -G sudo "$ADMIN_USER"
useradd -m -s /bin/bash "$PLAIN_USER"
printf '%s:%s\n%s:%s\n' "$ADMIN_USER" "$ADMIN_PW" "$PLAIN_USER" "$PLAIN_PW" | chpasswd

apt-get install -y -qq --no-install-recommends needrestart unattended-upgrades distro-info-data > /dev/null
held=jq
dpkg -s "$held" > /dev/null 2>&1 || apt-get install -y -qq "$held" > /dev/null
apt-mark hold "$held" >&2
echo '*** System restart required ***' > /var/run/reboot-required
echo linux-base > /var/run/reboot-required.pkgs
echo "HELD=$held"
