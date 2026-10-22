#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""gapslib: Debian version order, the parsers of apt, dpkg and needrestart
output, unattended-upgrades matching, the settings file."""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gapslib as L  # noqa: E402
from fakesys import FPR_A, FPR_B, FPR_P, FPR_S, TWO_KEYS, WITH_SUBKEY  # noqa: E402

PAIRS = [
    ("1.0", "1.0", 0), ("1.0", "1.1", -1), ("1.10", "1.9", 1), ("1.0~rc1", "1.0", -1),
    ("1.0", "1.0+b1", -1), ("1:1.0", "2.0", 1), ("5:29.8.0-1~ubuntu.24.04~noble", "5:29.9.1-1~ubuntu.24.04~noble", -1),
    ("0.16.4-2ubuntu0.24.04.3", "0.16.4-2ubuntu0.24.04.3+esm2", -1), ("362-1~bpo24.04.1", "362-1", -1),
    ("360-1", "362-1~bpo24.04.1", -1), ("6.8.0-146-generic", "6.8.0-147-generic", -1),
    ("7.0.0-38-generic", "7.0.0-34-generic", 1), ("1.0-1", "1.0-1ubuntu1", -1), ("2.0", "2.0-0", 0),
    ("1.0a", "1.0", 1), ("1.0~", "1.0", -1), ("1.0~~", "1.0~", -1), ("a", "b", -1), ("1.0.0", "1.0", 1),
    ("0:1.0", "1.0", 0), ("10", "9", 1), ("1.0-0", "1.0", 0), ("2.4.2-2~ubuntu.24.04~noble", "2.3.5-1~ubuntu.24.04~noble", 1),
]


def sign(n):
    return (n > 0) - (n < 0)


class VersionTest(unittest.TestCase):
    def test_pairs(self):
        for a, b, want in PAIRS:
            self.assertEqual(sign(L.vercmp(a, b)), want, f"{a} vs {b}")
            self.assertEqual(sign(L.vercmp(b, a)), -want, f"{b} vs {a}")

    def test_sort_key(self):
        vs = ["1.10", "1.9", "1.0~rc1", "1.0", "1:0.1"]
        self.assertEqual([v for v in sorted(vs, key=L.Version)], ["1.0~rc1", "1.0", "1.9", "1.10", "1:0.1"])

    @unittest.skipUnless(shutil.which("dpkg"), "dpkg not installed")
    def test_against_dpkg(self):
        """The order dpkg itself gives, for the pairs above and every pair of
        versions in the fixtures' version tables."""
        here = os.path.dirname(os.path.abspath(__file__))
        versions = set()
        for sc in ("noble-held", "resolute-stale-lists", "resolute-nodesource"):
            with open(os.path.join(here, "fixtures", sc, "commands", "apt-cache-policy-installed.txt")) as f:
                for name, pkg in L.parse_policy_packages(f.read()).items():
                    versions.update(v["version"] for v in pkg["versions"])
        vs = sorted(versions)[:120]
        pairs = [(a, b) for a, b, _ in PAIRS] + [(vs[i], vs[j]) for i in range(len(vs)) for j in range(i + 1, len(vs), 7)]
        for a, b in pairs:
            lt = subprocess.run(["dpkg", "--compare-versions", a, "lt", b]).returncode == 0
            eq = subprocess.run(["dpkg", "--compare-versions", a, "eq", b]).returncode == 0
            want = -1 if lt else 0 if eq else 1
            self.assertEqual(sign(L.vercmp(a, b)), want, f"{a} vs {b}")


class ParserTest(unittest.TestCase):
    def test_policy_sources(self):
        text = """Package files:
 100 /var/lib/dpkg/status
     release a=now
 500 https://user:secret@download.docker.com/linux/ubuntu noble/stable amd64 Packages
     release o=Docker,a=noble,l=Docker CE,c=stable,b=amd64
     origin download.docker.com
 100 http://archive.ubuntu.com/ubuntu noble-backports/universe amd64 Packages
     release v=24.04,o=Ubuntu,a=noble-backports,n=noble,l=Ubuntu,c=universe,b=amd64
     origin archive.ubuntu.com
Pinned packages:
"""
        src = L.parse_policy_sources(text)
        self.assertNotIn("secret", " ".join(src))
        docker = src["https://***@download.docker.com/linux/ubuntu noble/stable amd64 Packages"]
        self.assertEqual(docker["release"]["l"], "Docker CE")
        self.assertEqual(docker["origin"], "download.docker.com")
        self.assertEqual(docker["suite"], "noble")
        bp = src["http://archive.ubuntu.com/ubuntu noble-backports/universe amd64 Packages"]
        self.assertEqual((bp["priority"], bp["release"]["a"], bp["component"]), (100, "noble-backports", "universe"))
        self.assertEqual(src[L.DPKG_STATUS]["release"], {"a": "now"})

    def test_policy_packages(self):
        text = """docker-ce:
  Installed: 5:29.8.0-1~ubuntu.24.04~noble
  Candidate: 5:29.9.1-1~ubuntu.24.04~noble
  Version table:
     5:29.9.1-1~ubuntu.24.04~noble 500
        500 https://download.docker.com/linux/ubuntu noble/stable amd64 Packages
 *** 5:29.8.0-1~ubuntu.24.04~noble 500
        500 https://download.docker.com/linux/ubuntu noble/stable amd64 Packages
        100 /var/lib/dpkg/status
hc-utils:
  Installed: 0.0.6-1
  Candidate: 0.0.6-1
  Version table:
 *** 0.0.6-1 100
        100 /var/lib/dpkg/status
foo:
  Installed: (none)
  Candidate: 2.0-1
  Version table:
     2.0-1 500 (phased 10%)
        500 http://archive.ubuntu.com/ubuntu noble-updates/main amd64 Packages
"""
        p = L.parse_policy_packages(text)
        self.assertEqual(p["docker-ce"]["candidate"], "5:29.9.1-1~ubuntu.24.04~noble")
        cur = L.installed_entry(p["docker-ce"])
        self.assertTrue(cur["current"])
        self.assertEqual(L.entry_sources(cur), ["https://download.docker.com/linux/ubuntu noble/stable amd64 Packages"])
        self.assertEqual(L.entry_sources(L.installed_entry(p["hc-utils"])), [])
        self.assertIsNone(p["foo"]["installed"])
        self.assertEqual(p["foo"]["versions"][0]["priority"], 500)
        self.assertEqual(p["foo"]["versions"][0]["phased"], 10)
        self.assertNotIn("phased", p["docker-ce"]["versions"][0], "only a phased version carries the share")

    def test_dist_upgrade(self):
        text = """Reading package lists...
The following packages have been kept back:
  containerd.io docker-ce
  docker-ce-cli
The following upgrades have been deferred due to phasing:
  snapd
The following packages will be upgraded:
  libssl3t64 openssl
Inst libssl3t64 [3.0.13-0ubuntu3.5] (3.0.13-0ubuntu3.6 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64])
Inst openssl [3.0.13-0ubuntu3.5] (3.0.13-0ubuntu3.6 Ubuntu:24.04/noble-updates [amd64]) []
Conf libssl3t64 (3.0.13-0ubuntu3.6 Ubuntu:24.04/noble-updates, Ubuntu:24.04/noble-security [amd64])
2 upgraded, 0 newly installed, 0 to remove and 3 not upgraded.
"""
        d = L.parse_dist_upgrade(text)
        self.assertEqual([i["package"] for i in d["inst"]], ["libssl3t64", "openssl"])
        self.assertEqual(d["inst"][0]["origins"], ["Ubuntu:24.04/noble-updates", "Ubuntu:24.04/noble-security"])
        self.assertTrue(any(L.is_security_origin(o) for o in d["inst"][0]["origins"]))
        self.assertFalse(any(L.is_security_origin(o) for o in d["inst"][1]["origins"]))
        self.assertEqual(d["kept_back"], ["containerd.io", "docker-ce", "docker-ce-cli"])
        self.assertEqual(d["phased"], ["snapd"])
        self.assertEqual(d["summary"]["not_upgraded"], 3)

    def test_needrestart(self):
        nr = L.parse_needrestart("NEEDRESTART-VER: 3.11\nNEEDRESTART-KCUR: 7.0.0-34-generic\n"
                                 "NEEDRESTART-KEXP: 7.0.0-38-generic\nNEEDRESTART-KSTA: 3\n"
                                 "NEEDRESTART-UCSTA: 2\nNEEDRESTART-SVC: dbus.service\nNEEDRESTART-SESS: u @ s\n")
        self.assertEqual(nr["kernel"], {"running": "7.0.0-34-generic", "expected": "7.0.0-38-generic", "state": 3})
        self.assertEqual(nr["microcode"]["state"], 2)
        self.assertEqual((nr["services"], nr["sessions"], nr["version"]), (["dbus.service"], 1, "3.11"))

    def test_apt_config(self):
        conf = L.parse_apt_config('APT::Periodic::Unattended-Upgrade "1";\n'
                                  'Unattended-Upgrade::Allowed-Origins "";\n'
                                  'Unattended-Upgrade::Allowed-Origins:: "${distro_id}:${distro_codename}";\n'
                                  'Unattended-Upgrade::Package-Blacklist:: "^docker\\.io";\n')
        self.assertEqual(conf["Unattended-Upgrade::Allowed-Origins"], ["${distro_id}:${distro_codename}"])
        self.assertEqual(L.config_scalar(conf, "APT::Periodic::Unattended-Upgrade"), "1")
        self.assertEqual(conf["Unattended-Upgrade::Package-Blacklist"], ["^docker\\.io"])

    def test_phasing_policy(self):
        def policy(text):
            return L.phasing_policy(L.parse_apt_config(text))
        self.assertEqual(policy('APT::Periodic::Unattended-Upgrade "1";\n'), ("default", None))
        self.assertEqual(policy('APT::Get::Always-Include-Phased-Updates "true";\n'),
                         ("always", "APT::Get::Always-Include-Phased-Updates"))
        self.assertEqual(policy('apt::get::always-include-phased-updates "1";\n'),
                         ("always", "APT::Get::Always-Include-Phased-Updates"), "keys without regard to case")
        self.assertEqual(policy('Update-Manager::Always-Include-Phased-Updates "yes";\n'),
                         ("always", "Update-Manager::Always-Include-Phased-Updates"), "update-manager's key is the fallback")
        self.assertEqual(policy('APT::Get::Always-Include-Phased-Updates "false";\n'
                                'Update-Manager::Always-Include-Phased-Updates "true";\n'), ("default", None),
                         "apt's own key, set to false, wins over the fallback")
        self.assertEqual(policy('APT::Get::Never-Include-Phased-Updates "on";\n'),
                         ("never", "APT::Get::Never-Include-Phased-Updates"))
        self.assertEqual(policy('APT::Get::Never-Include-Phased-Updates "true";\n'
                                'APT::Get::Always-Include-Phased-Updates "true";\n')[0], "always", "always is asked first")
        self.assertEqual(policy('APT::Get::Always-Include-Phased-Updates "";\n'), ("default", None), "empty is not set")
        self.assertEqual(policy('APT::Get::Always-Include-Phased-Updates "maybe";\n'), ("default", None))
        self.assertEqual([L.apt_bool(v) for v in ("1", "Yes", "TRUE", "with", "on", "enable", "0", "no", "off", "2", "")],
                         [True] * 6 + [False] * 5)

    def test_deb822(self):
        recs = L.parse_deb822("Site: a\nRelease: x\n\nSite: b\nDescription: one\n two\n")
        self.assertEqual(recs, [{"Site": "a", "Release": "x"}, {"Site": "b", "Description": "one\ntwo"}])

    def test_dpkg_log(self):
        log = L.parse_dpkg_log([
            "2026-08-05 11:16:45 upgrade docker-ce:amd64 5:29.6.2-1 5:29.7.1-1",
            "2026-09-08 13:48:10 upgrade docker-ce:amd64 5:29.7.1-1 5:29.8.0-1",
            "2026-09-08 13:48:10 status installed docker-ce:amd64 5:29.8.0-1",
            "2026-01-01 00:00:00 install foo:all <none> 1.0"])
        self.assertEqual(log["docker-ce"], ("2026-09-08T13:48:10", "5:29.8.0-1"))
        self.assertEqual(log["foo"], ("2026-01-01T00:00:00", "1.0"))

    def test_release_dates(self):
        self.assertEqual(L.iso(L.parse_release_date("Mon, 19 Oct 2026  1:07:49 UTC")), "2026-10-19T01:07:49Z")
        self.assertEqual(L.iso(L.parse_release_date("Sun, 18 Oct 2026 21:11:43 +0000")), "2026-10-18T21:11:43Z")
        self.assertIsNone(L.parse_release_date(""))

    def test_os_release(self):
        osr = L.parse_os_release('ID=ubuntu\nVERSION_CODENAME=noble\nPRETTY_NAME="Ubuntu 24.04.5 LTS"\n')
        self.assertEqual((osr["ID"], osr["PRETTY_NAME"]), ("ubuntu", "Ubuntu 24.04.5 LTS"))
        self.assertEqual(L.distro_id(osr), "Ubuntu")
        self.assertEqual(L.distro_id({"ID": "debian"}), "Debian")


class UnattendedTest(unittest.TestCase):
    UB = {"o": "Ubuntu", "a": "noble-security", "n": "noble", "l": "Ubuntu", "c": "main"}

    def test_allowed_origins(self):
        p = L.uu_allowed_to_pattern(L.uu_expand("${distro_id}:${distro_codename}-security", "Ubuntu", "noble"))
        self.assertEqual(p, {"o": "Ubuntu", "a": "noble-security"})
        self.assertTrue(L.uu_match(p, self.UB, "archive.ubuntu.com"))
        self.assertFalse(L.uu_match(p, dict(self.UB, a="noble-backports"), "archive.ubuntu.com"))
        esm = L.uu_allowed_to_pattern("UbuntuESMApps:noble-apps-security")
        self.assertTrue(L.uu_match(esm, {"o": "UbuntuESMApps", "a": "noble-apps-security"}, "esm.ubuntu.com"))

    def test_origins_pattern(self):
        p = L.uu_pattern("origin=Debian,codename=trixie,label=Debian-Security")
        self.assertEqual(p, {"o": "Debian", "n": "trixie", "l": "Debian-Security"})
        self.assertTrue(L.uu_match(p, {"o": "Debian", "n": "trixie", "l": "Debian-Security", "a": "stable-security"}, ""))
        self.assertFalse(L.uu_match(p, {"o": "Debian", "n": "trixie", "l": "Debian"}, ""))
        self.assertTrue(L.uu_match(L.uu_pattern("site=*.docker.com"), {}, "download.docker.com"))
        self.assertTrue(L.uu_match(L.uu_pattern("o=Docker,a=*"), {"o": "Docker", "a": "noble"}, ""))
        self.assertIsNone(L.uu_pattern("colour=red"))
        self.assertFalse(L.uu_match(None, {}, ""))

    def test_escaped_separators(self):
        self.assertEqual(L.uu_allowed_to_pattern(r"Foo\:Bar:stable"), {"o": "Foo:Bar", "a": "stable"})
        self.assertEqual(L.uu_pattern(r"l=A\,B"), {"l": "A,B"})


class SettingsTest(unittest.TestCase):
    def test_good(self):
        s = L.parse_settings("# known tools\nHIDE_OUTSIDE=/opt/agent/bin\n\nHIDE_OUTSIDE=/usr/local/bin/x/\n")
        self.assertEqual(s["hide_outside"], ["/opt/agent/bin", "/usr/local/bin/x"])
        self.assertTrue(L.hidden("/opt/agent/bin/tool", s["hide_outside"]))
        self.assertFalse(L.hidden("/opt/agent/binary", s["hide_outside"]))

    def test_refused(self):
        for bad in ("COLOUR=red", "HIDE_OUTSIDE=relative/path", "HIDE_OUTSIDE=/opt/../etc",
                    "HIDE_OUTSIDE=/opt/a b", "HIDE_OUTSIDE"):
            with self.assertRaises(L.SettingsError, msg=bad):
                L.parse_settings(bad)


class CredentialsTest(unittest.TestCase):
    def test_strip(self):
        self.assertEqual(L.strip_credentials("deb https://u:p@h.example/x stable"), "deb https://***@h.example/x stable")
        self.assertEqual(L.strip_credentials("http://h.example/x"), "http://h.example/x")


class CpuTest(unittest.TestCase):
    def test_classify(self):
        cases = {
            "Not affected": "not-affected",
            "Mitigation: PTI": "mitigated",
            "KVM: Mitigation: VMX unsupported": "mitigated",
            "Mitigation: Clear CPU buffers; SMT Host state unknown": "mitigated",
            "Mitigation: Clear CPU buffers; SMT vulnerable": "partial",
            "Vulnerable: Clear CPU buffers attempted, no microcode; SMT Host state unknown": "vulnerable",
            "Vulnerable: No microcode": "vulnerable",
            "Vulnerable": "vulnerable",
            "Unknown: Dependent on hypervisor status": "unknown",
            "Processor vulnerable": "partial",
            "": "unknown",
        }
        for text, want in cases.items():
            self.assertEqual(L.classify_vulnerability(text), want, text)

    def test_machine(self):
        for virt, want in (("none", "metal"), ("kvm", "vm"), ("microsoft", "vm"), ("docker", "container"),
                           ("wsl", "container"), ("", "unknown"), ("kvm; rm -rf", "unknown")):
            self.assertEqual(L.machine_kind(virt), want, virt)

    def test_cpuinfo(self):
        text = ("processor\t: 0\nvendor_id\t: GenuineIntel\nmodel name\t: Intel Xeon\nmicrocode\t: 0x1\n\n"
                "processor\t: 1\nvendor_id\t: GenuineIntel\nmodel name\t: Intel Xeon\nmicrocode\t: 0xF8\n\n"
                "processor\t: 2\nmicrocode\t: <script>\n")
        self.assertEqual(L.parse_cpuinfo(text), {"vendor": "GenuineIntel", "model": "Intel Xeon", "threads": 3,
                                                 "revisions": ["0x1", "0xf8"]})
        self.assertEqual(L.parse_cpuinfo(None)["threads"], 0)

    def test_mitigations_off(self):
        self.assertEqual(L.mitigations_off("BOOT_IMAGE=/vmlinuz ro mitigations=off nosmt tsa=off spectre_v2=on nopti"),
                         ["mitigations=off", "tsa=off", "nopti"])
        self.assertEqual(L.mitigations_off("root=/dev/sda1 ro quiet"), [])

    def test_dmi(self):
        self.assertEqual(L.dmi_date("08/30/2024"), "2024-08-30")
        self.assertIsNone(L.dmi_date("2024-08-30"))
        self.assertIsNone(L.dmi_date("13/40/2024"))
        self.assertIsNone(L.dmi_value("To Be Filled By O.E.M.\n"))
        self.assertIsNone(L.dmi_value(""))
        self.assertEqual(L.dmi_value(" ASRockRack\n"), "ASRockRack")


class FirmwareSnapTest(unittest.TestCase):
    def test_fwupd_updates(self):
        doc = ('{"Devices": [{"Name": "Dock\\u0000 X", "Version": "1.0", "Releases": [{"Version": "1.2", '
               '"Urgency": "urgent", "Issues": ["CVE-2026-1234", "x"]}]}, {"Name": "Y", "Releases": []}]}')
        self.assertEqual(L.parse_fwupd_updates(doc), [{"device": "Dock X", "vendor": None, "version": "1.0", "new": "1.2",
                                                       "urgency": None, "issues": ["CVE-2026-1234"]}])
        with self.assertRaises(ValueError):
            L.parse_fwupd_updates("No updatable devices")
        with self.assertRaises(ValueError):
            L.parse_fwupd_updates("[]")

    def test_fwupd_remotes(self):
        # fwupdmgr --json names the time of the metadata "Mtime" (fwupd_remote_to_json); "ModificationTime" is
        # the key of the D-Bus variant and is read only when "Mtime" is missing.
        doc = '{"Remotes": [{"Id": "lvfs", "Kind": "download", "Enabled": true, "Mtime": 1792400000}, {"Id": ""}]}'
        self.assertEqual(L.parse_fwupd_remotes(doc), [{"id": "lvfs", "enabled": True, "kind": "download",
                                                       "mtime": 1792400000}])
        doc = '{"Remotes": [{"Id": "lvfs", "Kind": "download", "Enabled": "true", "ModificationTime": 1792400000}]}'
        self.assertEqual(L.parse_fwupd_remotes(doc)[0]["mtime"], 1792400000)
        doc = '{"Remotes": [{"Id": "lvfs", "Kind": "download", "Enabled": true, "Mtime": 0}]}'
        self.assertIsNone(L.parse_fwupd_remotes(doc)[0]["mtime"], "0: never refreshed")

    def test_rfc3339(self):
        self.assertEqual(L.iso(L.parse_rfc3339("2026-10-20T15:11:00.123456789+02:00")), "2026-10-20T13:11:00Z")
        self.assertEqual(L.iso(L.parse_rfc3339("2026-10-20T15:11:00Z")), "2026-10-20T15:11:00Z")
        for bad in ("2026-10-20", "yesterday", None, 5, "2026-13-40T00:00:00Z"):
            self.assertIsNone(L.parse_rfc3339(bad), bad)


# `gpg --show-keys --with-colons` of real keyrings (pub/sub/uid lines; 2026-10-21).
DOCKER = """pub:-:4096:1:8D81803C0EBFCD88:1487788586:::-:::escaESCA::::::23::0:
uid:-::::1487792064::B50C6A3598EE2C27B34302761B93B277BF674C93::Docker Release (CE deb) <docker@docker.com>::::::::::0:
sub:-:4096:1:7EA0A9C3F273FCD8:1487788586::::::s::::::23:
"""
GITHUB_OLD = """pub:e:4096:1:23F3D4EA75716059:1662463626:1788612228::-:::sc::::::23::0:
uid:e::::1725540228::8112F49127753770F34E73A49614E0AFC050A705::GitHub CLI <opensource+cli@github.com>::::::::::0:
sub:e:4096:1:E5FAF19590714157:1662463626:1788612228:::::e::::::23:
"""
GITHUB_NEW = """pub:-:4096:1:5612B36462313325:1775559160:::-:::scESC::::::23::0:
uid:-::::1775559160::8112F49127753770F34E73A49614E0AFC050A705::GitHub CLI <opensource+cli@github.com>::::::::::0:
sub:-:4096:1:F4CAB2C46C97E579:1775559160::::::e::::::23:
"""


class KeysTest(unittest.TestCase):
    def test_keyring_expiry(self):
        self.assertEqual(L.keyring_expiry(DOCKER), "never")
        self.assertEqual(L.iso(L.keyring_expiry(GITHUB_OLD)), "2026-09-05T12:43:48Z", "expired: its date")
        self.assertEqual(L.keyring_expiry(GITHUB_OLD + GITHUB_NEW), "never", "the new key signs on")
        # A signing subkey that outlives its primary key ends with it; the latest signing key counts.
        rings = ("pub:-:4096:1:A:1700000000:1800000000::-:::cC:\nsub:-:4096:1:B:1700000000:1900000000:::::s:\n"
                 "pub:-:4096:1:C:1700000000:1790000000::-:::scSC:\n")
        self.assertEqual(L.keyring_expiry(rings).timestamp(), 1800000000)
        self.assertIsNone(L.keyring_expiry("pub:r:4096:1:A:1700000000:::-:::sc:\nsub:-:4096:1:B:1700000000::::::s:\n"),
                          "a revoked key and its subkeys do not count")
        self.assertIsNone(L.keyring_expiry("pub:-:4096:1:A:1700000000:::-:::eE:\n"), "no signing key")
        self.assertIsNone(L.keyring_expiry(""))

    def test_fingerprints_of_signed_by_select_keys(self):
        """As apt does (sources.list(5)): a fingerprint selects that key and its subkeys, one with
        `!` that key alone; without a fingerprint every key of the keyring counts."""
        self.assertEqual(L.keyring_expiry(TWO_KEYS), "never", "every key: B signs on")
        self.assertEqual(L.keyring_expiry(TWO_KEYS, []), "never")
        self.assertEqual(L.iso(L.keyring_expiry(TWO_KEYS, [FPR_A])), "2026-09-01T00:00:00Z", "only A, which expired")
        self.assertEqual(L.keyring_expiry(TWO_KEYS, [FPR_B]), "never")
        self.assertEqual(L.keyring_expiry(TWO_KEYS, [FPR_A, FPR_B]), "never")
        self.assertIsNone(L.keyring_expiry(TWO_KEYS, ["E5" * 20]), "a fingerprint the keyring does not hold")
        self.assertIsNone(L.keyring_expiry(TWO_KEYS, [FPR_A.lower()]), "apt compares upper case (sources_keyrings converts)")
        self.assertIsNone(L.keyring_expiry(TWO_KEYS, [FPR_B, "0123456789ABCDEF"]), "apt refuses the whole value for a key ID")
        self.assertIsNone(L.keyring_expiry(TWO_KEYS, ["B2" * 32]), "and for 64 digits")
        # A subkey that signs: selected through its primary key, or by its own fingerprint.
        self.assertEqual(L.keyring_expiry(WITH_SUBKEY, [FPR_P]).timestamp(), 1800000000)
        self.assertIsNone(L.keyring_expiry(WITH_SUBKEY, [FPR_P + "!"]), "the primary key alone does not sign")
        self.assertEqual(L.keyring_expiry(WITH_SUBKEY, [FPR_S]).timestamp(), 1800000000)
        self.assertEqual(L.keyring_expiry(WITH_SUBKEY, [FPR_S + "!"]).timestamp(), 1800000000)
        self.assertIsNone(L.keyring_expiry(DOCKER, ["9DC858229FC7DD38854AE2D88D81803C0EBFCD88"]),
                          "without fingerprints in gpg's output nothing can be selected")
        keys = L.keyring_keys(WITH_SUBKEY)
        self.assertEqual([(k["fpr"], k["primary"], k["sign"]) for k in keys], [(FPR_P, FPR_P, False), (FPR_S, FPR_P, True)])

    def test_sources_keyrings(self):
        text = ("# comment\nTypes: deb\nURIs: https://download.docker.com/linux/ubuntu/\nSuites: resolute\n"
                "Signed-By: /etc/apt/keyrings/docker.asc\n\nTypes: deb\nURIs: https://a.example/ https://b.example/\n"
                "Enabled: no\nSigned-By: /x.gpg\n\nTypes: deb deb-src\nURIs: http://archive.ubuntu.com/ubuntu/\n"
                "Signed-By: /usr/share/keyrings/a.gpg, 0123456789ABCDEF /usr/share/keyrings/b.gpg\n\n"
                "Types: deb\nURIs: https://repo.example/apt\nSigned-By:\n -----BEGIN PGP PUBLIC KEY BLOCK-----\n .\n"
                " mQINBGZ\n -----END PGP PUBLIC KEY BLOCK-----\n\nTypes: deb\nURIs: https://plain.example/\n")
        self.assertEqual(L.sources_keyrings(text, True), [
            {"uris": ["https://download.docker.com/linux/ubuntu/"], "inline": None, "keyrings": ["/etc/apt/keyrings/docker.asc"],
             "select": []},
            {"uris": ["http://archive.ubuntu.com/ubuntu/"], "inline": None,
             "keyrings": ["/usr/share/keyrings/a.gpg", "/usr/share/keyrings/b.gpg"], "select": ["0123456789ABCDEF"]},
            {"uris": ["https://repo.example/apt"], "keyrings": [], "select": [],
             "inline": "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmQINBGZ\n-----END PGP PUBLIC KEY BLOCK-----\n"},
            {"uris": ["https://plain.example/"], "inline": None, "keyrings": [], "select": []}])
        text = ("deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu   noble stable\n"
                "# deb [signed-by=/old.gpg] https://old.example/ x main\ndeb-src https://src.example/ x main\n"
                "deb [ arch=amd64 ] http://archive.ubuntu.com/ubuntu noble main\n")
        self.assertEqual(L.sources_keyrings(text, False), [
            {"uris": ["https://download.docker.com/linux/ubuntu"], "inline": None, "keyrings": ["/etc/apt/keyrings/docker.gpg"],
             "select": []},
            {"uris": ["https://src.example/"], "inline": None, "keyrings": [], "select": []},
            {"uris": ["http://archive.ubuntu.com/ubuntu"], "inline": None, "keyrings": [], "select": []}])
        self.assertEqual(L.sources_keyrings(None, True), [])

    def test_sources_keyrings_keep_the_fingerprints(self):
        """Fingerprints in Signed-By, upper case as apt makes them, `!` kept; apt splits the value at
        commas and whitespace in both formats."""
        a, b = FPR_A.lower(), FPR_B
        text = (f"deb [signed-by=/etc/apt/keyrings/x.gpg,{a}] https://x.example/ noble main\n"
                f"deb [arch=amd64 signed-by={b}!] https://y.example/ noble main\n")
        self.assertEqual([(e["keyrings"], e["select"]) for e in L.sources_keyrings(text, False)],
                         [(["/etc/apt/keyrings/x.gpg"], [FPR_A]), ([], [FPR_B + "!"])])
        text = (f"Types: deb\nURIs: https://x.example/\nSuites: noble\nSigned-By: /etc/apt/keyrings/x.gpg {a}\n\n"
                f"Types: deb\nURIs: https://y.example/\nSuites: noble\nSigned-By: {b},{FPR_S}!\n")
        self.assertEqual([(e["keyrings"], e["select"]) for e in L.sources_keyrings(text, True)],
                         [(["/etc/apt/keyrings/x.gpg"], [FPR_A]), ([], [FPR_B, FPR_S + "!"])])


# unattended-upgrades.log as 2.9 and 2.12 write it (Ubuntu 24.04 and 26.04).
UU_LOG = """2026-10-20 06:20:58,117 INFO Starting unattended upgrades script
2026-10-20 06:20:58,118 INFO Allowed origins are: o=Ubuntu,a=noble, o=Ubuntu,a=noble-security
2026-10-20 06:20:58,118 INFO Initial blacklist:
2026-10-20 06:20:58,118 INFO Initial whitelist (not strict):
2026-10-20 06:21:01,872 INFO Packages that will be upgraded: nginx-common openssl
2026-10-20 06:21:01,873 INFO Package nginx-common has conffile prompt and needs to be upgraded manually
2026-10-20 06:21:01,873 INFO Writing dpkg log to /var/log/unattended-upgrades/unattended-upgrades-dpkg.log
2026-10-20 06:21:40,391 INFO All upgrades installed
2026-10-20 10:57:47,301 WARNING Could not figure out development release: Distribution data outdated. Please check for an update for distro-info-data. See /usr/share/doc/distro-info-data/README.Debian
2026-10-20 10:57:47,301 INFO Starting unattended upgrades script
2026-10-20 10:57:47,302 INFO Allowed origins are: o=Ubuntu,a=noble, o=Ubuntu,a=noble-security
2026-10-20 10:57:47,302 INFO Initial blacklist:
2026-10-20 10:57:47,302 INFO Initial whitelist (not strict):
"""


class UnattendedLogTest(unittest.TestCase):
    def test_last_finished_run(self):
        run = L.parse_uu_log(UU_LOG)
        self.assertEqual(run["started"].isoformat(), "2026-10-20T06:20:58", "apt-daily's download run has no end")
        self.assertEqual((run["outcome"], run["packages"], run["conffile"], run["errors"]),
                         ("installed", ["nginx-common", "openssl"], ["nginx-common"], []))

    def test_outcomes(self):
        head = "2026-10-21 06:06:11,803 INFO Starting unattended upgrades script\n"
        run = L.parse_uu_log(head + "2026-10-21 06:06:12,636 INFO No packages found that can be upgraded unattended "
                             "and no pending auto-removals\n")
        self.assertEqual(run["outcome"], "nothing")
        run = L.parse_uu_log(head + "2026-10-21 06:06:12,001 INFO Packages that are kept back: libfoo1 bar\n"
                             "2026-10-21 06:06:20,002 ERROR Installing the upgrades failed!\n"
                             "2026-10-21 06:06:20,003 ERROR dpkg returned an error! See the log for details\n")
        self.assertEqual((run["outcome"], run["kept_back"], len(run["errors"])), ("failed", ["bar", "libfoo1"], 2))
        run = L.parse_uu_log(head + "2026-10-21 06:06:12,001 INFO Lock could not be acquired (another package manager running?)\n")
        self.assertEqual(run["outcome"], "failed")
        self.assertIsNone(L.parse_uu_log(head), "a run without an end is no finished run")
        self.assertIsNone(L.parse_uu_log(""))
        self.assertIsNone(L.parse_uu_log("garbage\n"))

    def test_dpkg_problem(self):
        for abbrev, want in (("ii", None), ("ii ", None), ("rc", None), ("hi", None), ("iU", "unpacked"),
                             ("iF", "half-configured"), ("iH", "half-installed"), ("iW", "triggers-awaited"),
                             ("it", "triggers-pending"), ("iiR", "reinst-required"), ("", None), (None, None)):
            self.assertEqual(L.dpkg_problem(abbrev), want, abbrev)


class AcknowledgedTest(unittest.TestCase):
    HELD = {"package": "docker-ce", "installed": "5:29.8.0-1", "candidate": "5:29.9.1-1", "newer": 4, "security": None}

    def test_ref_and_pin(self):
        ref = L.finding_ref("held", self.HELD)
        self.assertRegex(ref, r"^held-[0-9a-f]{12}$")
        self.assertRegex(ref, L.REF_RE)
        newer = dict(self.HELD, candidate="5:29.9.2-1", newer=5)
        self.assertEqual(L.finding_ref("held", newer), ref, "a new version is the same finding")
        self.assertEqual(L.finding_pin("held", newer), L.finding_pin("held", self.HELD), "and still what was acknowledged")
        self.assertNotEqual(L.finding_pin("held", dict(self.HELD, security=True)), L.finding_pin("held", self.HELD),
                            "a fix from a security source is not")
        self.assertNotEqual(L.finding_ref("held", dict(self.HELD, package="docker-ce-cli")), ref)
        self.assertNotEqual(L.finding_ref("local", self.HELD), ref, "the check is part of the name")
        # Firmware updates and failed snap refreshes are told apart by device and change.
        self.assertNotEqual(L.finding_ref("firmware", {"kind": "update", "device": "UEFI dbx"}),
                            L.finding_ref("firmware", {"kind": "update", "device": "Dock"}))
        self.assertNotEqual(L.finding_ref("snaps", {"kind": "refresh-failed", "id": "41"}),
                            L.finding_ref("snaps", {"kind": "refresh-failed", "id": "42"}))

    def test_keys_are_told_apart_by_their_fingerprints(self):
        """Two keys in one sources file, or one keyring that two sources select from in different
        ways, are different findings. One without those fields keeps the ref it had in 0.7.0."""
        ring = {"kind": "expired", "file": "/usr/share/keyrings/x.gpg", "sources": ["https://x.example/"],
                "expires": "2026-09-01T00:00:00Z"}
        old = "keys-" + hashlib.sha256(("keys" + json.dumps(["expired", "/usr/share/keyrings/x.gpg", None])).encode()).hexdigest()[:12]
        self.assertEqual(L.finding_ref("keys", ring), old)
        self.assertEqual(L.finding_ref("keys", dict(ring, sources=["https://y.example/"], expires="2026-09-02T00:00:00Z")), old)
        a, b = dict(ring, select=[FPR_A]), dict(ring, select=[FPR_B])
        self.assertEqual(len({L.finding_ref("keys", x) for x in (ring, a, b)}), 3)
        inline = {"kind": "expired", "file": "/etc/apt/sources.list.d/x.sources", "inline": True}
        k1, k2 = dict(inline, fingerprints=[FPR_A]), dict(inline, fingerprints=[FPR_B])
        self.assertNotEqual(L.finding_ref("keys", k1), L.finding_ref("keys", k2))
        self.assertEqual(L.finding_ref("keys", k1), L.finding_ref("keys", dict(k1, sources=["https://z.example/"])))
        self.assertEqual(L.finding_label(k1), "/etc/apt/sources.list.d/x.sources (" + FPR_A[-16:] + ")")
        self.assertEqual(L.finding_label(dict(ring, select=[FPR_S + "!"])), "/usr/share/keyrings/x.gpg (" + FPR_S[-16:] + "!)")

    def test_label_and_reason(self):
        self.assertEqual(L.finding_label(self.HELD), "docker-ce")
        self.assertEqual(L.finding_label({"kind": "space", "free": 1}), "space")
        self.assertEqual(L.finding_label({"kind": "expired", "file": "/usr/share/keyrings/x.gpg"}), "/usr/share/keyrings/x.gpg")
        self.assertEqual(L.finding_label({}), "")
        self.assertEqual(L.clean_reason("  until\nthe\twindow \x1b[31m "), "until the window [31m")
        self.assertEqual(len(L.clean_reason("x" * 500)), 200)
        self.assertEqual(L.clean_reason(None), "")

    def test_parse_accepted(self):
        ref = L.finding_ref("held", self.HELD)
        good = {"ref": ref, "check": "held", "label": "docker-ce", "pin": "0123456789ab", "until": "2026-11-01",
                "reason": "maintenance\nwindow", "at": "2026-10-19T08:00:00Z"}
        today = L.parse_day("2026-10-22")
        text = json.dumps({"format": 1, "accepted": [
            good,
            dict(good, ref="held-zzzz"),                                       # not a ref
            dict(good, ref="cpu-0123456789ab"),                                # ref of another check
            dict(good, ref="cve-0123456789ab", check="cve"),                   # network data cannot be acknowledged
            dict(good, ref="held-111111111111", until="2027-03-01"),           # more than 90 days after it was given
            dict(good, ref="held-222222222222", until="2026-09-01"),           # ended more than 30 days ago
            dict(good, ref="held-333333333333", until="2026-10-01"),           # ended, still shown
            dict(good, ref="held-444444444444", until="2026-13-01"),           # no day
            dict(good, ref="held-555555555555", pin="no"),                     # no pin: never matches
            "nonsense"]})
        out = L.parse_accepted(text, today)
        self.assertEqual(sorted(out), sorted([ref, "held-333333333333", "held-555555555555"]))
        self.assertEqual(out[ref]["reason"], "maintenance window")
        self.assertEqual(out["held-555555555555"]["pin"], "")
        for bad in ("", "{", "[]", '{"format": 2, "accepted": []}', '{"format": 1, "accepted": {}}'):
            self.assertEqual(L.parse_accepted(bad, today), {}, bad)


if __name__ == "__main__":
    unittest.main()
