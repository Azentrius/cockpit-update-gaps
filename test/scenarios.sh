#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# The helpers on a real Debian or Ubuntu, in a throw-away container (CI, job scenarios):
#
#   docker run --rm -v "$PWD:/src:ro" ubuntu:24.04 sh /src/test/scenarios.sh /src
#
# NEVER on a machine you use: it holds a package, installs a package without a source, adds a
# package source that does not exist, writes into /usr/local, /opt and /etc and sets the reboot
# flag. Then it runs gaps-scan.py from the checkout, as root (with the files the service writes)
# and as a user, reads the status as a user and checks what it found. No systemd runs in the
# container: the scan runs directly, as the service would.
set -eu
src=${1:?usage: scenarios.sh CHECKOUT}
export DEBIAN_FRONTEND=noninteractive LC_ALL=C
. /etc/os-release
echo "== $PRETTY_NAME"

apt-get update -qq
apt-get install -y -qq --no-install-recommends python3 unattended-upgrades needrestart distro-info-data dpkg-dev > /dev/null

# A held package, a package without a source, a source without package lists.
# apt-mark holds a package that is not installed as well; it must be installed to count.
apt-get install -y -qq --no-install-recommends tzdata > /dev/null
apt-mark hold tzdata
pkg=$(mktemp -d)
mkdir -p "$pkg/DEBIAN" "$pkg/usr/share/doc/ug-local"
printf 'Package: ug-local\nVersion: 1.0\nArchitecture: all\nMaintainer: Test <test@example.invalid>\nDescription: a package without a source\n' > "$pkg/DEBIAN/control"
dpkg-deb --build "$pkg" /tmp/ug-local.deb > /dev/null
dpkg -i /tmp/ug-local.deb > /dev/null
echo "deb http://update-gaps.invalid/debian stable main" > /etc/apt/sources.list.d/ug-test.list
# Kept out of the automatic updates by name.
printf 'Unattended-Upgrade::Package-Blacklist { "^ug-local$"; };\n' > /etc/apt/apt.conf.d/99ug-test
# Software outside the package manager; one folder hidden by the settings.
mkdir -p /usr/local/bin /opt/ugapp/bin /opt/ugother/bin
printf '#!/bin/sh\necho tool\n' > /usr/local/bin/ug-tool
chmod 755 /usr/local/bin/ug-tool
cp /bin/true /opt/ugother/bin/ug-binary
ln -sf /usr/local/bin/ug-tool /opt/ugother/bin/ug-link
cp /bin/true /opt/ugapp/bin/hidden-tool
printf '# test\nHIDE_OUTSIDE=/opt/ugapp/bin\n' > /etc/update-gaps.conf
chmod 644 /etc/update-gaps.conf
# A reboot asked for by a package.
echo '*** System restart required ***' > /var/run/reboot-required
echo linux-base > /var/run/reboot-required.pkgs
# Never run from /usr/local: a fake apt-get there must stay untouched.
printf '#!/bin/sh\ntouch /tmp/ug-fake-apt-ran\nexit 1\n' > /usr/local/bin/apt-get
chmod 755 /usr/local/bin/apt-get

mkdir -p /var/lib/update-gaps
python3 -I "$src/lib/gaps-scan.py" --output /var/lib/update-gaps/scan.json --status /var/lib/update-gaps/status.json
cp /var/lib/update-gaps/scan.json /tmp/scan-root.json
useradd -m ugplain 2> /dev/null || true
su ugplain -s /bin/sh -c "python3 -I '$src/lib/gaps-scan.py'" > /tmp/scan-user.json
sh "$src/lib/gaps-ctl.sh" status > /tmp/status.json
su ugplain -s /bin/sh -c "python3 -I '$src/lib/gaps-status.py' status --lang de" > /tmp/board.json
# The radar of stage 2: never as root; as a user it works out what it would ask about (no network).
if python3 -I "$src/lib/gaps-radar.py" --dry-run > /dev/null 2>&1; then echo "the radar ran as root"; exit 1; fi
su ugplain -s /bin/sh -c "python3 -I '$src/lib/gaps-radar.py' --dry-run" > /tmp/selection.json

python3 - "$ID" <<'EOF'
import json, sys
ident = sys.argv[1]
doc = json.load(open("/tmp/scan-root.json"))
c = {x["check"]: x for x in doc["checks"]}
for x in doc["checks"]:
    print(f'{x["check"]:10} {x["state"]:8} {x.get("reason") or x.get("error") or ""}')
assert doc["root"] and doc["pm"] == "apt", doc
assert not [x for x in doc["checks"] if x["state"] in ("error", "timeout")], "a check failed"
assert "tzdata" in [f["package"] for f in c["held"]["findings"]], c["held"]
local = {f["package"]: f for f in c["local"]["findings"]}
assert local["ug-local"]["cause"] == "lists-missing", local
missing = [f for f in c["lists"]["findings"] if f["kind"] == "missing"]
assert any(f["site"].startswith("http://update-gaps.invalid") for f in missing), c["lists"]
assert any(f["entry"].startswith("/etc/apt/sources.list.d/ug-test.list") for f in missing), missing
dirs = {d["dir"]: {f["name"]: f for f in d["files"]} for d in c["outside"]["dirs"]}
assert dirs["/usr/local/bin"]["ug-tool"]["kind"] == "script", dirs
assert dirs["/usr/local/bin"]["ug-tool"]["interpreter"] == "sh", dirs
assert dirs["/opt/ugother/bin"]["ug-binary"]["kind"] == "binary", dirs
assert dirs["/opt/ugother/bin"]["ug-link"]["kind"] == "link", dirs
assert "/opt/ugapp/bin" not in dirs and c["outside"]["hidden"] == 1, c["outside"]
assert c["restart"]["reboot_required"]["packages"] == ["linux-base"], c["restart"]
bl = [f for f in c["auto"]["findings"] if f["kind"] == "blacklist"]
assert bl and bl[0]["packages"] == ["ug-local"], c["auto"]
assert c["eol"]["state"] in ("none", "found") and c["eol"]["standard_until"], c["eol"]
if ident == "ubuntu":
    assert c["pro"]["state"] in ("none", "found") or c["pro"].get("reason") == "tool-missing", c["pro"]
else:
    assert c["pro"]["reason"] == "not-applicable", c["pro"]
user = json.load(open("/tmp/scan-user.json"))
u = {x["check"]: x for x in user["checks"]}
assert user["root"] is False
assert not [x for x in user["checks"] if x["state"] in ("error", "timeout")], "a check failed without root"
assert u["lists"]["missing"] == ["journal"]
st = json.load(open("/tmp/status.json"))
assert st["timer"] == "missing" and st["root"] is True, st
board = json.load(open("/tmp/board.json"))
items = {i["id"]: i for i in board["items"]}
print("status:", board["state"], "|", board["summary"])
assert board["schema"] == 1 and board["addon"] == "update-gaps" and board["version"] != "unknown", board
assert items["restart"]["state"] == "warning" and "linux-base" in items["restart"]["detail"], items
assert items["held"]["state"] in ("ok", "warning") and "tzdata" in items["held"]["detail"], items
assert board["state"] in ("warning", "danger") and "Neustart" in board["summary"], board
assert ("pro" in items) == (ident == "ubuntu"), items
sel = json.load(open("/tmp/selection.json"))
assert set(sel) == {"sources", "upstream"}, sel
print("radar would ask about:", sorted(sel["sources"]), sorted(sel["upstream"]))
for k in ("cve", "upstream", "newer"):
    assert c[k]["state"] == "skipped" and c[k]["reason"] in ("radar-off", "not-applicable"), c[k]
# Stage 3 in a container: the CPU and the firmware are the host's, and there are no snaps.
for k in ("cpu", "firmware"):
    assert c[k]["state"] == "skipped" and c[k]["reason"] == "container", c[k]
assert c["snaps"]["state"] == "none" and c["snaps"]["installed"] == 0, c["snaps"]
assert not {"cpu", "firmware", "snaps"} & set(items), items
print("SCENARIO OK")
EOF
test ! -e /tmp/ug-fake-apt-ran || { echo "the helper ran apt-get from /usr/local/bin"; exit 1; }
echo "== $PRETTY_NAME: all checks as expected"
