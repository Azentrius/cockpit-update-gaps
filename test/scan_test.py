#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""The checks against output recorded on real hosts (test/fixtures/):

  noble-held            Ubuntu 24.04: Docker from download.docker.com held, fixes only with
                        Ubuntu Pro, a reboot and services pending, Cockpit from backports, a
                        package without a source, scripts in /usr/local and /opt
  resolute-stale-lists  Ubuntu 26.04 right after a package source moved: the new source has no
                        lists yet, the old lists are still there, its packages look sourceless;
                        Docker from Ubuntu on the Package-Blacklist of unattended-upgrades
  resolute-nodesource   Ubuntu 26.04 with NodeSource, nothing to restart, apt-daily printed an
                        error

and the cases those hosts do not have: no root, missing tools, time limits,
broken settings, another distribution, a phased rollout (resolute-nodesource
while Ubuntu rolls systemd out in phases, fakesys.phased_results), upkeep gone
wrong (noble-held with /boot full, a kernel half configured, a failed run of
unattended-upgrades and an expired key, fakesys.upkeep)."""

import hashlib
import importlib.util
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "lib"))
sys.path.insert(0, HERE)
import gapscheck  # noqa: E402
import gapslib as L  # noqa: E402
import gapsproc  # noqa: E402
import gapsstatus  # noqa: E402
from fakesys import (FPR_A, FPR_B, FPR_P, NOBLE_ACCEPTED, TWO_KEYS, WITH_SUBKEY, FakeSystem,  # noqa: E402
                     accepted_files, command_text, phased_results, upkeep)

STATES = {"found", "none", "partial", "skipped", "timeout", "error"}
UBUNTU_KEYRING = "/usr/share/keyrings/ubuntu-archive-keyring.gpg"
CHECKS = [name for name, _ in gapscheck.CHECKS]


def scan(scenario, **kw):
    doc = gapscheck.scan(FakeSystem(scenario, **kw))
    return doc, {c["check"]: c for c in doc["checks"]}


def bare(findings):
    """Findings without the time a scan first saw them and their ref (classes
    Since and Acknowledged test those)."""
    if isinstance(findings, dict):
        return {k: v for k, v in findings.items() if k not in ("since", "ref", "accepted")}
    return [bare(f) for f in findings]


def accepted_for(check, findings, until="2026-11-01", at="2026-10-19T08:00:00Z"):
    """`files` for FakeSystem: accepted.json as gaps-accept.py writes it, for
    `findings` (with their ref) of `check` from an earlier scan."""
    items = [{"ref": f["ref"], "check": check, "label": L.finding_label(f), "pin": L.finding_pin(check, f),
              "until": until, "reason": "", "at": at} for f in findings]
    return {gapscheck.ACCEPTED: json.dumps({"format": 1, "accepted": items})}


def status_item(doc, cid, lang="en"):
    return {i["id"]: i for i in gapsstatus.document(doc, lang, "0.1.0")["items"]}.get(cid)


class Shape(unittest.TestCase):
    def test_every_scenario(self):
        for sc in ("noble-held", "resolute-stale-lists", "resolute-nodesource"):
            doc, checks = scan(sc)
            json.dumps(doc)
            self.assertEqual(doc["format"], 1)
            self.assertEqual(doc["pm"], "apt")
            self.assertEqual([c["check"] for c in doc["checks"]], CHECKS)
            self.assertRegex(doc["generated"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
            for c in doc["checks"]:
                self.assertIn(c["state"], STATES, (sc, c))
                self.assertNotEqual(c["state"], "error", (sc, c))
                self.assertIsInstance(c["took_ms"], int)
            self.assertTrue(doc["root"])

    def test_no_host_names_or_secrets(self):
        for sc in ("noble-held", "resolute-stale-lists", "resolute-nodesource"):
            text = json.dumps(scan(sc)[0])
            self.assertNotRegex(text, r"\b[a-z]+-host\b", "a host name of the recording")
            self.assertNotIn(":secret@", text)


class NobleHeld(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.doc, cls.c = scan("noble-held")

    def test_updates(self):
        u = self.c["updates"]
        self.assertEqual((u["state"], u["count"], u["security"]), ("none", 0, 0))
        self.assertIn("docker-ce", u["kept_back"])

    def test_held(self):
        h = self.c["held"]
        self.assertEqual(h["state"], "found")
        names = [f["package"] for f in h["findings"]]
        self.assertEqual(names, ["containerd.io", "docker-buildx-plugin", "docker-ce", "docker-ce-cli",
                                 "docker-ce-rootless-extras", "docker-compose-plugin"])
        d = h["findings"][2]
        self.assertEqual(d["installed"], "5:29.8.0-1~ubuntu.24.04~noble")
        self.assertEqual(d["candidate"], "5:29.9.1-1~ubuntu.24.04~noble")
        self.assertGreaterEqual(d["newer"], 3)
        self.assertIsNone(d["security"], "Docker's repository does not say what is a security fix")
        self.assertEqual((d["origin"]["o"], d["origin"]["host"]), ("Docker", "download.docker.com"))
        self.assertEqual(d["installed_at"], "2026-09-08T13:48:10")

    def test_pro(self):
        p = self.c["pro"]
        self.assertEqual(p["state"], "found")
        self.assertFalse(p["attached"])
        self.assertEqual(sorted(f["package"] for f in p["findings"]), ["python3-pip", "python3-wheel", "restic", "skopeo"])
        r = next(f for f in p["findings"] if f["package"] == "restic")
        self.assertEqual((r["service"], r["status"]), ("esm-apps", "pending_attach"))
        self.assertEqual(r["installed"], "0.16.4-2ubuntu0.24.04.3")

    def test_restart(self):
        r = self.c["restart"]
        self.assertEqual(r["state"], "found")
        self.assertEqual(r["kernel"], {"running": "6.8.0-146-generic", "expected": "6.8.0-147-generic", "state": 3})
        self.assertIn("dbus.service", r["services"])
        self.assertEqual(r["reboot_required"]["since"], "2026-10-14T06:04:25Z")
        self.assertIn("linux-image-6.8.0-147-generic", r["reboot_required"]["packages"])
        self.assertTrue(r["tool"].startswith("needrestart 3.6"))

    def test_lists(self):
        ls = self.c["lists"]
        self.assertEqual(ls["state"], "none", ls["findings"])
        self.assertEqual(ls["last_update"]["src"], "update-success-stamp")
        self.assertEqual(ls["last_update"]["ts"], "2026-10-19T14:29:37Z")
        self.assertEqual(ls["apt_daily"]["result"], "success")

    def test_local(self):
        self.assertEqual([(f["package"], f["cause"]) for f in self.c["local"]["findings"]], [("hc-utils", "no-source")])

    def test_auto(self):
        a = self.c["auto"]
        self.assertEqual(a["state"], "found")
        self.assertIn("Ubuntu:noble-updates", a["allowed"])
        groups = {f["host"] + " " + f["a"]: f["packages"] for f in a["findings"] if f["kind"] == "source"}
        self.assertIn("docker-ce", groups["download.docker.com noble"])
        self.assertIn("cockpit", groups["mirror.hetzner.com noble-backports"])
        self.assertIn("cockpit-cronjobs", groups["packages.azentrius.com stable"])
        self.assertNotIn("restic", sum(groups.values(), []), "restic comes from noble-updates, which is covered")
        held = next(f for f in a["findings"] if f["kind"] == "held")
        self.assertIn("docker-ce", held["packages"])

    def test_backports_installed_already(self):
        self.assertEqual(self.c["backports"]["state"], "none")

    def test_outside(self):
        o = self.c["outside"]
        self.assertEqual(o["state"], "found")
        dirs = {d["dir"]: d["files"] for d in o["dirs"]}
        self.assertEqual([f["name"] for f in dirs["/usr/local/bin"]], ["local-1", "local-2"])
        self.assertEqual(dirs["/usr/local/bin"][0]["kind"], "script")
        self.assertEqual(dirs["/usr/local/bin"][0]["interpreter"], "python3")
        self.assertEqual(o["hidden"], 0)

    def test_eol(self):
        e = self.c["eol"]
        self.assertEqual((e["state"], e["standard_until"], e["extended_until"]), ("none", "2029-05-31", "2034-04-25"))


class ResoluteStaleLists(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.doc, cls.c = scan("resolute-stale-lists")

    def test_lists(self):
        ls = self.c["lists"]
        self.assertEqual(ls["state"], "found")
        kinds = {f["kind"]: f for f in ls["findings"]}
        self.assertEqual((kinds["missing"]["site"], kinds["missing"]["release"]), ("https://packages.azentrius.com/apt", "stable"))
        self.assertEqual(kinds["missing"]["entry"], "/etc/apt/sources.list.d/azentrius.sources:1")
        self.assertEqual((kinds["orphaned"]["site"], kinds["orphaned"]["files"]), ("packages.azentrius.de/apt", 3))

    def test_local_because_of_lists(self):
        f = self.c["local"]["findings"]
        self.assertEqual([x["package"] for x in f], ["azentrius-repository", "cockpit-cronjobs", "cockpit-image-update-monitor"])
        self.assertTrue(all(x["cause"] == "lists-missing" for x in f))

    def test_blacklist(self):
        bl = {f["pattern"]: f["packages"] for f in self.c["auto"]["findings"] if f["kind"] == "blacklist"}
        self.assertEqual(bl["^docker\\.io"], ["docker.io"])
        self.assertEqual(bl["^runc$"], ["runc"])
        self.assertIn("containerd", bl["^containerd"])

    def test_restart_with_microcode(self):
        r = self.c["restart"]
        self.assertEqual(r["state"], "found")
        self.assertEqual(r["microcode"]["state"], 1)
        self.assertEqual(r["kernel"]["state"], 3)

    def test_nothing_held(self):
        self.assertEqual(self.c["held"]["state"], "none")


class ResoluteNodesource(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.doc, cls.c = scan("resolute-nodesource")

    def test_nothing_to_restart(self):
        r = self.c["restart"]
        self.assertEqual(r["state"], "none")
        self.assertIsNone(r["reboot_required"])

    def test_nodesource_not_automatic(self):
        groups = {f["host"]: f for f in self.c["auto"]["findings"] if f["kind"] == "source"}
        self.assertEqual(groups["deb.nodesource.com"]["packages"], ["nodejs"])

    def test_apt_daily_error_line(self):
        f = [x for x in self.c["lists"]["findings"] if x["kind"] == "apt-daily"]
        self.assertEqual(len(f), 1)
        self.assertTrue(any("nm-online" in ln for ln in f[0]["lines"]))


class Degraded(unittest.TestCase):
    def test_without_root(self):
        doc, c = scan("resolute-nodesource", uid=1000)
        self.assertFalse(doc["root"])
        self.assertEqual(c["restart"]["state"], "partial")
        self.assertEqual(c["restart"]["missing"], ["services"])
        self.assertEqual(c["lists"]["missing"], ["journal"])
        self.assertEqual(c["lists"]["state"], "partial")
        self.assertFalse(any(x["kind"] == "apt-daily" for x in c["lists"]["findings"]),
                         "without root the journal is not read")

    def test_needrestart_missing(self):
        doc, c = scan("noble-held", missing={"needrestart"})
        r = c["restart"]
        self.assertEqual(r["state"], "found")
        self.assertEqual(r["missing"], ["needrestart"])
        self.assertEqual(r["kernel"]["expected"], "6.8.0-147-generic")
        self.assertEqual(r["services"], [])

    def test_pro_missing(self):
        doc, c = scan("noble-held", missing={"pro"})
        self.assertEqual((c["pro"]["state"], c["pro"]["reason"], c["pro"]["tool"]), ("skipped", "tool-missing", "pro"))

    def test_pro_runs_without_root(self):
        fs = FakeSystem("noble-held")
        gapscheck.scan(fs, only={"pro"})
        self.assertEqual(fs.unprivileged, ["pro"])

    def test_timeout_is_one_check_only(self):
        doc, c = scan("noble-held", results={"apt-get-s-dist-upgrade": gapsproc.Result(None, timeout=True)})
        self.assertEqual(c["updates"]["state"], "timeout")
        self.assertEqual(c["held"]["state"], "found")

    def test_failing_policy_breaks_its_checks_only(self):
        doc, c = scan("noble-held", results={"apt-cache-policy-installed": gapsproc.Result(100, "", "E: broken")})
        for name in ("held", "local", "auto", "backports"):
            self.assertEqual(c[name]["state"], "error", name)
            self.assertIn("E: broken", c[name]["error"])
        self.assertEqual(c["restart"]["state"], "found")

    def test_debian(self):
        osr = 'ID=debian\nVERSION_ID="13"\nVERSION_CODENAME=trixie\nPRETTY_NAME="Debian GNU/Linux 13 (trixie)"\n'
        doc, c = scan("resolute-nodesource", files={"/etc/os-release": osr})
        self.assertEqual((c["pro"]["state"], c["pro"]["reason"]), ("skipped", "not-applicable"))
        self.assertEqual(c["eol"]["source"], ["/usr/share/distro-info/debian.csv"])
        self.assertEqual(c["eol"]["codename"], "trixie")
        self.assertIsNotNone(c["eol"]["standard_until"])

    def test_not_apt(self):
        fs = FakeSystem("noble-held")
        del fs.meta["stat"]["/usr/bin/apt-get"]
        doc = gapscheck.scan(fs)
        self.assertIsNone(doc["pm"])
        self.assertTrue(all(c["state"] == "skipped" and c["reason"] == "unsupported-os" for c in doc["checks"]))
        self.assertEqual(fs.calls, [], "nothing runs on a system without apt")


def apt_config_plus(scenario, text):
    with open(os.path.join(HERE, "fixtures", scenario, "commands", "apt-config-dump.txt"), encoding="utf-8") as f:
        return gapsproc.Result(0, f.read() + text, "")


class Phased(unittest.TestCase):
    """Ubuntu rolls an update out in phases and apt defers it here; Software
    Updates (PackageKit) lists it all the same and fails on it."""

    def test_none_on_the_recorded_hosts(self):
        for sc in ("noble-held", "resolute-stale-lists", "resolute-nodesource"):
            p = scan(sc)[1]["phased"]
            self.assertEqual((p["state"], p["packages"], p["include"], p["setting"]), ("none", [], "default", None), sc)
            self.assertEqual(p["source"], ["apt-get -s dist-upgrade", "apt-config dump"], "no apt-cache policy without a phased package")

    def test_deferred_with_versions_and_share(self):
        doc, c = scan("resolute-nodesource", results=phased_results())
        self.assertEqual([x["check"] for x in doc["checks"]][:3], ["updates", "phased", "dpkg"])
        p = c["phased"]
        self.assertEqual(p["state"], "found")
        self.assertEqual(bare(p["packages"]), [{"package": "systemd", "installed": "259.5-0ubuntu3.4",
                                          "version": "259.9-0ubuntu0.1", "percent": 10}])
        self.assertEqual((p["include"], p["setting"]), ("default", None))
        self.assertEqual(p["source"], ["apt-get -s dist-upgrade", "apt-config dump", "apt-cache policy"])
        u = c["updates"]
        self.assertEqual((u["state"], u["count"], u["security"], u["phased"]), ("found", 3, 1, ["systemd"]),
                         "the updates Software Updates fails on together with systemd")

    def test_setting_read_from_apt_config(self):
        on = apt_config_plus("resolute-nodesource", 'APT::Get::Always-Include-Phased-Updates "true";\n')
        p = scan("resolute-nodesource", results={"apt-config-dump": on})[1]["phased"]
        self.assertEqual((p["state"], p["include"], p["setting"]), ("none", "always", "APT::Get::Always-Include-Phased-Updates"))
        never = apt_config_plus("resolute-nodesource", 'Update-Manager::Never-Include-Phased-Updates "1";\n')
        p = scan("resolute-nodesource", results=dict(phased_results(), **{"apt-config-dump": never}))[1]["phased"]
        self.assertEqual((p["state"], p["include"], p["setting"]), ("found", "never", "Update-Manager::Never-Include-Phased-Updates"))

    def test_failing_apt_config_or_policy(self):
        broken = gapsproc.Result(100, "", "E: broken")
        doc, c = scan("resolute-nodesource", results=dict(phased_results(), **{"apt-config-dump": broken}))
        p = c["phased"]
        self.assertEqual((p["state"], p["include"], p["setting"]), ("found", None, None), "the setting is not known")
        self.assertEqual(c["auto"]["state"], "error", "auto needs the configuration")
        doc, c = scan("resolute-nodesource", results=dict(phased_results(), **{"apt-cache-policy-installed": broken}))
        p = c["phased"]
        self.assertEqual(p["state"], "found")
        self.assertEqual(bare(p["packages"]), [{"package": "systemd", "installed": None, "version": None, "percent": None}],
                         "the name is enough to say what fails")
        self.assertNotIn("apt-cache policy", p["source"])

    def test_simulation_timeout_and_odd_names(self):
        c = scan("noble-held", results={"apt-get-s-dist-upgrade": gapsproc.Result(None, timeout=True)})[1]
        self.assertEqual((c["updates"]["state"], c["phased"]["state"]), ("timeout", "timeout"))
        odd = phased_results()
        odd["apt-get-s-dist-upgrade"] = gapsproc.Result(0, odd["apt-get-s-dist-upgrade"].out.replace(
            "  systemd\n", "  systemd $(reboot) libfoo:i386\n"), "")
        p = scan("resolute-nodesource", results=odd)[1]["phased"]
        self.assertEqual([x["package"] for x in p["packages"]], ["systemd", "libfoo:i386"], "only what looks like a package name")
        self.assertEqual(bare(p["packages"][1]), {"package": "libfoo:i386", "installed": None, "version": None, "percent": None})


VULN = gapscheck.CPU_VULN
# vpn-host on 2026-10-20 (Intel Xeon Skylake, Hetzner vServer), as the kernel reported it.
VPN_HOST_VULN = {
    "gather_data_sampling": "Unknown: Dependent on hypervisor status",
    "itlb_multihit": "KVM: Mitigation: VMX unsupported",
    "l1tf": "Mitigation: PTE Inversion",
    "mds": "Mitigation: Clear CPU buffers; SMT Host state unknown",
    "meltdown": "Mitigation: PTI",
    "mmio_stale_data": "Vulnerable: Clear CPU buffers attempted, no microcode; SMT Host state unknown",
    "spectre_v2": "Mitigation: IBRS; IBPB: conditional; STIBP: disabled; RSB filling; PBRSB-eIBRS: Not affected",
    "srbds": "Not affected",
}


def with_vulns(fs, vulns):
    fs.meta["dirs"][VULN] = sorted(vulns)
    for k, v in vulns.items():
        fs.meta["files"][f"{VULN}/{k}"] = v + "\n"
    return fs


def dpkg_plus(scenario, line):
    with open(os.path.join(HERE, "fixtures", scenario, "commands", "dpkg-query-W.txt"), encoding="utf-8") as f:
        return gapsproc.Result(0, f.read() + line + "\n", "")


class Cpu(unittest.TestCase):
    def test_vm_with_tsa_is_the_providers(self):
        c = scan("noble-held")[1]["cpu"]
        self.assertEqual((c["state"], c["machine"], c["virt"]), ("found", "vm", "kvm"))
        self.assertEqual(bare(c["findings"]), [{"name": "tsa", "text": "Vulnerable: Clear CPU buffers attempted, no microcode",
                                          "kind": "vulnerable", "microcode": True, "fix": "provider"}])
        self.assertEqual((c["mitigated"], c["not_affected"]), (4, 10))
        self.assertEqual(c["cpu"], {"vendor": "AuthenticAMD", "model": "AMD EPYC-Genoa Processor", "threads": 8,
                                    "revisions": ["0x1000065"]})
        self.assertNotIn("microcode_package", c, "in a VM the package is not the point")
        self.assertNotIn("firmware", c)

    def test_physical_server_clean(self):
        c = scan("resolute-stale-lists")[1]["cpu"]
        self.assertEqual((c["state"], c["machine"], c["findings"]), ("none", "metal", []))
        self.assertEqual(c["firmware"], {"sys_vendor": "Hetzner", "board_vendor": "ASRockRack", "board_name": "B450D4U-V1L",
                                         "bios_vendor": "American Megatrends International, LLC.",
                                         "bios_version": "L2.12", "bios_date": "2024-08-30"})
        self.assertEqual(c["microcode_package"], {"name": "amd64-microcode", "installed": "3.20251202.1ubuntu2",
                                                  "candidate": "3.20251202.1ubuntu2"})
        self.assertFalse(c["microcode_pending"], "needrestart: the microcode is current")

    def test_intel_vm(self):
        fs = with_vulns(FakeSystem("resolute-nodesource"), VPN_HOST_VULN)
        c = {x["check"]: x for x in gapscheck.scan(fs, only={"cpu"})["checks"]}["cpu"]
        got = {f["name"]: (f["kind"], f["fix"]) for f in c["findings"]}
        self.assertEqual(got, {"gather_data_sampling": ("unknown", "provider"),
                               "mmio_stale_data": ("vulnerable", "provider")})
        self.assertEqual((c["mitigated"], c["not_affected"]), (5, 1))

    def test_metal_without_the_microcode_package(self):
        intel = "processor\t: 0\nvendor_id\t: GenuineIntel\nmodel name\t: Intel(R) Xeon(R) E-2276G\nmicrocode\t: 0xf8\n"
        policy = "intel-microcode:\n  Installed: (none)\n  Candidate: 3.20260210.1ubuntu2\n  Version table:\n"
        fs = FakeSystem("resolute-stale-lists", files={"/proc/cpuinfo": intel},
                        results={"apt-cache-policy-intel-microcode": gapsproc.Result(0, policy, "")})
        c = {x["check"]: x for x in gapscheck.scan(fs, only={"cpu"})["checks"]}["cpu"]
        self.assertEqual(c["state"], "found")
        self.assertEqual(c["microcode_package"], {"name": "intel-microcode", "installed": None,
                                                  "candidate": "3.20260210.1ubuntu2", "available": True})
        none = policy.replace("Candidate: 3.20260210.1ubuntu2", "Candidate: (none)")
        fs = FakeSystem("resolute-stale-lists", files={"/proc/cpuinfo": intel},
                        results={"apt-cache-policy-intel-microcode": gapsproc.Result(0, none, "")})
        c = {x["check"]: x for x in gapscheck.scan(fs, only={"cpu"})["checks"]}["cpu"]
        self.assertIs(c["microcode_package"]["available"], False)

    def test_partial_and_switched_off_on_metal(self):
        fs = with_vulns(FakeSystem("resolute-stale-lists", files={"/proc/cmdline": "BOOT_IMAGE=/vmlinuz ro mitigations=off nosmt\n"}),
                        {"mds": "Mitigation: Clear CPU buffers; SMT vulnerable", "spectre_v2": "Vulnerable"})
        c = {x["check"]: x for x in gapscheck.scan(fs, only={"cpu"})["checks"]}["cpu"]
        self.assertEqual(c["state"], "found")
        self.assertEqual(c["mitigations_off"], ["mitigations=off"])
        self.assertEqual([(f["name"], f["kind"], f["fix"]) for f in c["findings"]],
                         [("mds", "partial", "here"), ("spectre_v2", "vulnerable", "here")])

    def test_container_is_the_hosts(self):
        r = {"systemd-detect-virt": gapsproc.Result(0, "docker\n", "")}
        c = scan("noble-held", results=r)[1]
        self.assertEqual((c["cpu"]["state"], c["cpu"]["reason"]), ("skipped", "container"))
        self.assertEqual((c["firmware"]["state"], c["firmware"]["reason"]), ("skipped", "container"))
        # docker run without systemd: no systemd-detect-virt, but /.dockerenv
        fs = FakeSystem("noble-held", missing={"systemd-detect-virt"})
        fs.meta["stat"]["/.dockerenv"] = {"type": "file", "mtime": 1, "mode": "755"}
        c = {x["check"]: x for x in gapscheck.scan(fs, only={"cpu"})["checks"]}["cpu"]
        self.assertEqual((c["state"], c["reason"], c["virt"]), ("skipped", "container", "container-other"))

    def test_without_systemd_detect_virt_or_the_files(self):
        c = scan("noble-held", missing={"systemd-detect-virt"})[1]["cpu"]
        self.assertEqual((c["state"], c["machine"]), ("found", "unknown"))
        self.assertEqual(c["findings"][0]["fix"], "here", "unknown machine: not blamed on a provider")
        fs = FakeSystem("noble-held")
        del fs.meta["dirs"][VULN]
        c = {x["check"]: x for x in gapscheck.scan(fs, only={"cpu"})["checks"]}["cpu"]
        self.assertEqual((c["state"], c["reason"]), ("skipped", "not-applicable"))


FWUPD_UPDATES = json.dumps({"Devices": [
    {"Name": "UEFI dbx", "Vendor": "Linux Foundation", "Version": "371", "Plugin": "uefi_dbx",
     "Releases": [{"Version": "377", "Urgency": "high", "Issues": ["CVE-2026-12345", "not-an-id"]},
                  {"Version": "376"}]},
    {"Name": "No release", "Version": "1", "Releases": []},
]})


def fwupd(updates=(0, FWUPD_UPDATES), mtime=1792400000, timer="enabled"):
    remotes = json.dumps({"Remotes": [{"Id": "lvfs", "Kind": "download", "Enabled": True, "Mtime": mtime},
                                      {"Id": "vendor-directory", "Kind": "directory", "Enabled": "true"}]})
    return {"dpkg-query-W": dpkg_plus("resolute-stale-lists", "fwupd\t2.1.1-1ubuntu3.1\tfwupd\tii \tamd64"),
            "fwupdmgr-get-updates": gapsproc.Result(updates[0], updates[1], ""),
            "fwupdmgr-get-remotes": gapsproc.Result(0, remotes, ""),
            "systemctl-is-enabled-fwupd-refresh": gapsproc.Result(0 if timer == "enabled" else 1, timer + "\n", "")}


class Firmware(unittest.TestCase):
    def test_without_fwupd(self):
        c = scan("resolute-stale-lists")[1]["firmware"]
        self.assertEqual((c["state"], c["reason"], c["tool"], c["machine"]), ("skipped", "tool-missing", "fwupd", "metal"))

    def test_updates_old_metadata_timer_off(self):
        old = 1792400000 - 40 * 86400
        c = scan("resolute-stale-lists", results=fwupd(mtime=old, timer="disabled"))[1]["firmware"]
        self.assertEqual(c["state"], "found")
        self.assertEqual(bare(c["findings"][0]), {"kind": "update", "device": "UEFI dbx", "vendor": "Linux Foundation",
                                            "version": "371", "new": "377", "urgency": "high",
                                            "issues": ["CVE-2026-12345"]})
        kinds = [f["kind"] for f in c["findings"]]
        self.assertEqual(kinds, ["update", "metadata-old", "refresh-off"])
        self.assertGreaterEqual(c["findings"][1]["days"], 40)

    def test_nothing_to_update(self):
        now = int(datetime.strptime("2026-10-19T20:55:00Z", "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp())
        c = scan("resolute-stale-lists", results=fwupd(updates=(2, "No updatable devices\n"), mtime=now - 86400))[1]["firmware"]
        self.assertEqual((c["state"], c["findings"]), ("none", []))
        self.assertEqual(c["timer"], "enabled")

    def test_fwupdmgr_fails(self):
        c = scan("resolute-stale-lists", results=fwupd(updates=(1, "")))[1]["firmware"]
        self.assertEqual(c["state"], "error")

    def test_old_metadata_alone(self):
        """Refresh timer on, nothing to update, metadata 40 days old (fwupd's key `Mtime`): a finding."""
        old = 1792400000 - 40 * 86400
        c = scan("resolute-stale-lists", results=fwupd(updates=(2, "No updatable devices\n"), mtime=old))[1]["firmware"]
        self.assertEqual(c["state"], "found")
        self.assertEqual([(f["kind"], f.get("remote")) for f in c["findings"]], [("metadata-old", "lvfs")])
        self.assertGreaterEqual(c["findings"][0]["days"], 40)
        self.assertGreaterEqual(c["remotes"][0]["age_days"], 40)


NOW_SNAP = "2026-10-19T20:55:00Z"
SNAPD = {
    "/v2/snaps": [
        {"name": "lxd", "type": "app", "base": "core20", "version": "5.0.4", "tracking-channel": "5.0/stable",
         "hold": "2316-10-19T20:00:00Z"},
        {"name": "certbot", "type": "app", "base": "core24", "version": "5.1",
         "refresh-inhibit": {"proceed-time": "2026-10-25T10:00:00.123456789+02:00"}},
        {"name": "core20", "type": "base", "version": "20251001"},
        {"name": "../evil", "type": "app"},
    ],
    "/v2/system-info": {"refresh": {"timer": "00:00~24:00/4", "hold": "2026-04-01T00:00:00Z"}},
    "/v2/changes?select=all": [
        {"id": "41", "kind": "auto-refresh", "status": "Error", "summary": "Auto-refresh snap \"lxd\"",
         "spawn-time": "2026-10-19T08:00:00Z", "err": "cannot refresh"},
        {"id": "12", "kind": "auto-refresh", "status": "Error", "summary": "old", "spawn-time": "2026-09-01T08:00:00Z"},
        {"id": "40", "kind": "auto-refresh", "status": "Done", "spawn-time": "2026-10-19T04:00:00Z"},
    ],
}


def snapfs(snapd=SNAPD):
    fs = FakeSystem("noble-held", snapd=snapd, now=NOW_SNAP)
    fs.meta["dirs"]["/snap"] = ["README", "bin", "certbot", "core20", "lxd"]
    for n in ("certbot", "core20", "lxd"):
        fs.meta["stat"][f"/snap/{n}/current"] = {"type": "link", "mtime": 1792400000, "target": "1"}
    return fs


class Snaps(unittest.TestCase):
    def test_no_snaps_no_snapd(self):
        fs = FakeSystem("noble-held")
        c = {x["check"]: x for x in gapscheck.scan(fs, only={"snaps"})["checks"]}["snaps"]
        self.assertEqual((c["state"], c["installed"], c["snapd"]), ("none", 0, True))
        self.assertFalse([x for x in fs.calls if x.startswith("snapd")], "snapd is not asked: it would start")

    def test_findings(self):
        fs = snapfs()
        c = {x["check"]: x for x in gapscheck.scan(fs, only={"snaps"})["checks"]}["snaps"]
        self.assertEqual((c["state"], c["installed"]), ("found", 3))
        self.assertEqual(bare(c["findings"]), [
            {"kind": "held", "snap": "lxd", "until": None},
            {"kind": "old-base", "snap": "lxd", "base": "core20", "release": "20.04 LTS", "ended": "2025-05-29",
             "esm_until": "2030-04-23"},
            {"kind": "inhibited", "snap": "certbot", "until": "2026-10-25T08:00:00Z"},
            {"kind": "refresh-failed", "id": "41", "when": "2026-10-19T08:00:00Z", "summary": "Auto-refresh snap \"lxd\"",
             "error": "cannot refresh"},
        ])
        self.assertEqual([s["name"] for s in c["snaps"]], ["lxd", "certbot", "core20"], "a bad name is dropped")

    def test_snapd_does_not_answer(self):
        c = {x["check"]: x for x in gapscheck.scan(snapfs(snapd={}), only={"snaps"})["checks"]}["snaps"]
        self.assertEqual(c["state"], "error")
        self.assertIn("snapd", c["error"])


RECORDED = ("noble-held", "resolute-stale-lists", "resolute-nodesource")
UU_LOG = gapscheck.UU_LOG


def dpkg_with(scenario, states):
    """dpkg-query -W of the scenario with the status letters of some packages
    changed (None: the package is not there)."""
    lines = []
    for line in command_text(scenario, "dpkg-query-W").splitlines():
        f = line.split("\t")
        if f[0] in states:
            if states[f[0]] is None:
                continue
            f[3] = states[f[0]]
        lines.append("\t".join(f))
    return gapsproc.Result(0, "\n".join(lines) + "\n", "")


class Dpkg(unittest.TestCase):
    def test_none_on_the_recorded_hosts(self):
        for sc in RECORDED:
            self.assertEqual(scan(sc)[1]["dpkg"]["state"], "none", sc)

    def test_half_done_and_interrupted(self):
        _, c = scan("noble-held", results={"dpkg-query-W": dpkg_with("noble-held", {"openssl": "iU ", "sudo": "iF ",
                                                                                     "systemd": "iiR"})},
                    meta={"dirs": {gapscheck.DPKG_UPDATES: ["0001", "tmp.i"]}})
        d = c["dpkg"]
        self.assertEqual(d["state"], "found")
        self.assertEqual([(f["kind"], f.get("package"), f.get("state")) for f in d["findings"]],
                         [("interrupted", None, None), ("package", "openssl", "unpacked"),
                          ("package", "sudo", "half-configured"), ("package", "systemd", "reinst-required")])

    def test_a_journal_of_dpkg_without_entries(self):
        _, c = scan("noble-held", meta={"dirs": {gapscheck.DPKG_UPDATES: ["tmp.i"]}})
        self.assertEqual(c["dpkg"]["state"], "none", "tmp.i is dpkg's scratch file, no unfinished run")

    def test_the_rest_beyond_the_list_counts_when_the_list_is_acknowledged(self):
        """301 packages half configured: 300 listed, 1 in `more`. Acknowledge the 300 on the page,
        and the one not listed still counts, as a warning with what it is."""
        extra = "".join(f"pkg-{i:03d}\t1.0-1\tpkg-{i:03d}\tiF \tamd64\n" for i in range(301))
        dq = {"dpkg-query-W": gapsproc.Result(0, command_text("noble-held", "dpkg-query-W").rstrip("\n") + "\n" + extra, "")}
        first = gapscheck.scan(FakeSystem("noble-held", results=dq), only={"dpkg"})
        d = first["checks"][0]
        self.assertEqual((d["state"], len(d["findings"]), d["more"], d["findings"][-1]["package"]), ("found", 300, 1, "pkg-299"))
        later = gapscheck.scan(FakeSystem("noble-held", results=dq, files=accepted_for("dpkg", d["findings"])),
                               only={"dpkg"}, previous=first)
        d = later["checks"][0]
        self.assertEqual((d["state"], d["accepted"], d["more"]), ("found", 300, 1))
        i = status_item(later, "dpkg")
        self.assertEqual((i["state"], i["value"], i["detail"]) if i else None,
                         ("warning", "1", "1 more package left half done, not listed; 300 acknowledged"))
        self.assertEqual(status_item(later, "dpkg", "de")["detail"], "1 weiteres Paket halb fertig, nicht aufgeführt; 300 quittiert")


class Boot(unittest.TestCase):
    def test_recorded_hosts(self):
        c = {sc: scan(sc)[1]["boot"] for sc in RECORDED}
        for sc, b in c.items():
            self.assertEqual((b["state"], len(b["kernels"])), ("none", 2), sc)
        # build-host keeps /boot on a RAID partition of 1 GB; its initramfs is 121 MB (a physical server).
        b = c["resolute-stale-lists"]
        self.assertEqual((b["free"], b["size"], b["need"]), (670838784, 1036726272, int((17320328 + 121217463) * 1.5)))

    def test_full_with_old_kernels(self):
        b = scan("noble-held", **upkeep())[1]["boot"]
        self.assertEqual(b["state"], "found")
        self.assertEqual(b["findings"][0]["kind"], "space")
        # The newest kernel has no initramfs (its update ran out of room): the largest pair counts.
        self.assertEqual(b["findings"][0]["need"], int((15067528 + 76568571) * 1.5))
        self.assertEqual(bare(b["findings"][1]), {"kind": "old-kernels", "kernels": ["6.8.0-136-generic", "6.8.0-142-generic"]})

    def test_the_running_kernel_is_never_old(self):
        names = [f"vmlinuz-6.8.0-{n}-generic" for n in (136, 142, 146, 147)]
        _, c = scan("noble-held", meta={"dirs": {"/boot": names}})
        fs = FakeSystem("noble-held")
        fs.meta["dirs"]["/boot"] = names
        fs.meta["kernel"] = "6.8.0-136-generic"
        b = {x["check"]: x for x in gapscheck.scan(fs, only={"boot"})["checks"]}["boot"]
        self.assertEqual(bare(b["findings"]), [{"kind": "old-kernels", "kernels": ["6.8.0-142-generic"]}])
        self.assertEqual(c["boot"]["findings"][0]["kernels"], ["6.8.0-136-generic", "6.8.0-142-generic"])

    def test_room_not_measured_or_no_kernel(self):
        b = scan("noble-held", meta={"statvfs": {"/boot": None}})[1]["boot"]
        self.assertEqual((b["state"], b["missing"], b["free"]), ("partial", ["boot-room"], None))
        b = scan("noble-held", meta={"dirs": {"/boot": []}})[1]["boot"]
        self.assertEqual((b["state"], b["reason"]), ("skipped", "not-applicable"))


class Unattended(unittest.TestCase):
    def test_recorded_hosts(self):
        want = {"noble-held": "2026-10-19T06:20:58Z", "resolute-stale-lists": "2026-10-19T06:08:41Z",
                "resolute-nodesource": "2026-10-19T06:56:57Z"}
        for sc, when in want.items():
            u = scan(sc)[1]["uu"]
            # Their latest runs are apt-daily's download runs (no end in the log): the run before counts.
            self.assertEqual((u["state"], u["last_run"], u["outcome"], u["service"]), ("none", when, "nothing", "success"), sc)

    def test_failed(self):
        u = scan("noble-held", **upkeep())[1]["uu"]
        self.assertEqual((u["state"], [f["kind"] for f in u["findings"]], u["outcome"]), ("found", ["failed"], "failed"))
        self.assertEqual(len(u["findings"][0]["lines"]), 3)
        self.assertIn("linux-image-6.8.0-147-generic", u["upgraded"])

    def test_kept_back_and_conffile(self):
        log = ("2026-10-19 06:20:58,105 INFO Starting unattended upgrades script\n"
               "2026-10-19 06:21:02,410 INFO Packages that will be upgraded: nginx-common openssl\n"
               "2026-10-19 06:21:02,411 INFO Package nginx-common has conffile prompt and needs to be upgraded manually\n"
               "2026-10-19 06:21:02,412 INFO Packages that are kept back: libfoo1\n"
               "2026-10-19 06:22:40,118 INFO All upgrades installed\n")
        u = scan("noble-held", files={UU_LOG: log})[1]["uu"]
        self.assertEqual([(f["kind"], f["packages"]) for f in u["findings"]],
                         [("kept-back", ["libfoo1"]), ("conffile", ["nginx-common"])])

    def test_never_old_and_stopped(self):
        u = scan("noble-held", files={UU_LOG: None})[1]["uu"]
        self.assertEqual(bare(u["findings"]), [{"kind": "never", "log": False}])
        u = scan("noble-held", now="2026-10-25T08:00:00Z")[1]["uu"]
        self.assertEqual([(f["kind"], f.get("hours")) for f in u["findings"]], [("old", 145)])
        u = scan("noble-held", results={"systemctl-show-apt-daily-upgrade": gapsproc.Result(0, "Result=timeout\n", "")})[1]["uu"]
        self.assertEqual([(f["kind"], f.get("result")) for f in u["findings"]], [("service", "timeout")])

    def test_switched_off_or_not_installed(self):
        conf = command_text("noble-held", "apt-config-dump").replace('APT::Periodic::Unattended-Upgrade "1";',
                                                                     'APT::Periodic::Unattended-Upgrade "0";')
        _, c = scan("noble-held", files={UU_LOG: None}, now="2026-10-25T08:00:00Z",
                    results={"apt-config-dump": gapsproc.Result(0, conf, "")})
        self.assertEqual((c["uu"]["state"], c["uu"]["off"]), ("none", True), "off: the card auto says so")
        _, c = scan("noble-held", results={"dpkg-query-W": dpkg_with("noble-held", {"unattended-upgrades": None})})
        self.assertEqual((c["uu"]["state"], c["uu"]["tool"]), ("skipped", "unattended-upgrades"))


AZ_KEY = "pub:-:4096:1:607685C42A3FC9E7:1792102664:{}::-:::scSC::::::23::0:\n"


class Keys(unittest.TestCase):
    def test_recorded_hosts(self):
        for sc in RECORDED:
            fs = FakeSystem(sc)
            k = {x["check"]: x for x in gapscheck.scan(fs)["checks"]}["keys"]
            self.assertEqual(k["state"], "none", sc)
            self.assertEqual({r["expires"] for r in k["keyrings"]}, {"never"}, sc)
            self.assertNotIn("unchecked", k, sc)
            self.assertIn("gpg", fs.unprivileged, "gpg runs without root")
        k = scan("noble-held")[1]["keys"]
        self.assertEqual([r["file"] for r in k["keyrings"]],
                         ["/etc/apt/keyrings/docker.gpg", "/usr/share/keyrings/azentrius.asc",
                          "/usr/share/keyrings/githubcli-archive-keyring.gpg", "/usr/share/keyrings/ubuntu-archive-keyring.gpg"])
        self.assertEqual(k["keyrings"][3]["sources"], ["https://mirror.hetzner.com/ubuntu/packages",
                                                       "https://mirror.hetzner.com/ubuntu/security"])

    def test_expired(self):
        """GitHub CLI's key expired on 2026-09-06; a keyring without the new one (April 2026) is out."""
        k = scan("noble-held", **upkeep())[1]["keys"]
        self.assertEqual(k["state"], "found")
        self.assertEqual([(f["kind"], f["file"], f["sources"], f["expires"]) for f in k["findings"]],
                         [("expired", "/usr/share/keyrings/githubcli-archive-keyring.gpg", ["https://cli.github.com/packages"],
                           "2026-09-05T12:43:48Z")])

    def test_expires_soon(self):
        ts = int(datetime(2026, 11, 18, tzinfo=timezone.utc).timestamp())
        k = scan("noble-held", results={"gpg-azentrius.asc": gapsproc.Result(0, AZ_KEY.format(ts), "")})[1]["keys"]
        self.assertEqual([(f["kind"], f["days"]) for f in k["findings"]], [("expires", 29)])
        ts = int(datetime(2027, 1, 18, tzinfo=timezone.utc).timestamp())
        k = scan("noble-held", results={"gpg-azentrius.asc": gapsproc.Result(0, AZ_KEY.format(ts), "")})[1]["keys"]
        self.assertEqual(k["state"], "none", "more than 60 days")

    def test_missing_and_unreadable(self):
        k = scan("noble-held", meta={"stat": {"/etc/apt/keyrings/docker.gpg": None}})[1]["keys"]
        self.assertEqual([(f["kind"], f["file"]) for f in k["findings"]], [("missing", "/etc/apt/keyrings/docker.gpg")])
        k = scan("resolute-nodesource", results={"gpg-nodesource.gpg": gapsproc.Result(2, "", "gpg: no valid OpenPGP data found.")})[1]["keys"]
        self.assertEqual((k["state"], k["missing"], k["unchecked"]),
                         ("partial", ["keyrings"], [{"file": "/usr/share/keyrings/nodesource.gpg", "reason": "unreadable"}]))
        k = scan("noble-held", files={"/etc/apt/sources.list.d/docker.list": None})[1]["keys"]
        self.assertEqual(k["unchecked"], [{"file": "/etc/apt/sources.list.d/docker.list", "reason": "unreadable"}])

    def test_sources_without_signed_by_use_the_trusted_keyrings(self):
        k = scan("noble-held", files={"/etc/apt/sources.list.d/docker.list":
                                      "deb [arch=amd64] https://download.docker.com/linux/ubuntu noble stable\n"})[1]["keys"]
        trusted = [r for r in k["keyrings"] if r.get("default")]
        self.assertEqual([r["file"] for r in trusted], ["/etc/apt/trusted.gpg.d/ubuntu-keyring-2012-cdimage.gpg",
                                                        "/etc/apt/trusted.gpg.d/ubuntu-keyring-2018-archive.gpg"])
        self.assertEqual(trusted[0]["sources"], ["https://download.docker.com/linux/ubuntu"])

    def test_inline_key_goes_to_gpg_on_stdin(self):
        src = ("Types: deb\nURIs: https://packages.azentrius.com/apt\nSuites: stable\nComponents: main\nSigned-By:\n"
               " -----BEGIN PGP PUBLIC KEY BLOCK-----\n .\n mQINBGZ\n -----END PGP PUBLIC KEY BLOCK-----\n")
        fs = FakeSystem("noble-held", files={"/etc/apt/sources.list.d/azentrius.sources": src},
                        results={"gpg-stdin": gapsproc.Result(0, AZ_KEY.format(""), "")})
        k = {x["check"]: x for x in gapscheck.scan(fs, only={"keys"})["checks"]}["keys"]
        ring = next(r for r in k["keyrings"] if r.get("inline"))
        self.assertEqual((ring["file"], ring["expires"]), ("/etc/apt/sources.list.d/azentrius.sources", "never"))
        self.assertEqual(fs.stdin, [b"-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nmQINBGZ\n-----END PGP PUBLIC KEY BLOCK-----\n"])

    def test_without_gpg(self):
        k = scan("noble-held", missing={"gpg"})[1]["keys"]
        self.assertEqual((k["state"], k["tool"]), ("skipped", "gpg"))


DOCKER_LIST = "/etc/apt/sources.list.d/docker.list"
DOCKER_GPG = "/etc/apt/keyrings/docker.gpg"
DOCKER_SITE = "https://download.docker.com/linux/ubuntu"
DOCKER_LINE = "deb [arch=amd64 signed-by={}] https://download.docker.com/linux/ubuntu noble stable\n"
# The fingerprints of Ubuntu's archive keys in /etc/apt/trusted.gpg.d (2012 CD image, 2018 archive).
UBUNTU_CD_2012, UBUNTU_2018 = "843938DF228D22F7B3742BC0D94AA3F0EFE21092", "F6ECB3762474EDA9D21B7022871920D1991BC93C"


def with_fpr(text, *fprs):
    """gpg's view of a recorded keyring with the fpr record gpg prints after each key."""
    out, it = [], iter(fprs)
    for line in text.splitlines():
        out.append(line)
        if line.startswith(("pub:", "sub:")):
            out.append(f"fpr:::::::::{next(it)}:")
    return "\n".join(out) + "\n"


def docker_keys(sources=None, keyring=TWO_KEYS, **kw):
    """The check keys of noble-held with docker.list as given and docker.gpg holding `keyring`."""
    files = {DOCKER_LIST: sources} if sources else {}
    results = dict({"gpg-docker.gpg": gapsproc.Result(0, keyring, "")}, **kw.pop("results", {}))
    return scan("noble-held", files=files, results=results, **kw)[1]["keys"]


class SignedByFingerprints(unittest.TestCase):
    """Signed-By with fingerprints (sources.list(5)): apt checks the source with the keys they
    select, not with every key of the keyring. docker.gpg holds A, which expired, and B."""

    def rings(self, k, file=DOCKER_GPG):
        return [(r.get("select"), r["sources"], r["expires"]) for r in k["keyrings"] if r["file"] == file]

    def test_without_a_fingerprint_every_key_counts(self):
        k = docker_keys()
        self.assertEqual((k["state"], self.rings(k)), ("none", [(None, [DOCKER_SITE], "never")]))

    def test_the_selected_key_expired(self):
        k = docker_keys(DOCKER_LINE.format(f"{DOCKER_GPG},{FPR_A.lower()}"))
        self.assertEqual(k["state"], "found")
        self.assertEqual([(f["kind"], f["file"], f["select"], f["sources"], f["expires"]) for f in k["findings"]],
                         [("expired", DOCKER_GPG, [FPR_A], [DOCKER_SITE], "2026-09-01T00:00:00Z")])

    def test_the_selected_key_is_valid(self):
        k = docker_keys(DOCKER_LINE.format(f"{DOCKER_GPG},{FPR_B}"))
        self.assertEqual((k["state"], k["findings"], self.rings(k)), ("none", [], [([FPR_B], [DOCKER_SITE], "never")]))

    def test_deb822_with_the_fingerprint_on_a_line_of_its_own(self):
        src = ("Types: deb\nURIs: https://packages.azentrius.com/apt\nSuites: stable\nComponents: main\n"
               f"Signed-By: /usr/share/keyrings/azentrius.asc\n {FPR_A}\n")
        k = scan("noble-held", files={"/etc/apt/sources.list.d/azentrius.sources": src},
                 results={"gpg-azentrius.asc": gapsproc.Result(0, TWO_KEYS, "")})[1]["keys"]
        self.assertEqual([(f["kind"], f["file"], f["select"]) for f in k["findings"]],
                         [("expired", "/usr/share/keyrings/azentrius.asc", [FPR_A])])

    def test_one_keyring_selected_differently_by_three_sources(self):
        src = (DOCKER_LINE.format(f"{DOCKER_GPG},{FPR_A}") +
               f"deb [signed-by={DOCKER_GPG},{FPR_B}] https://mirror.example/docker noble stable\n"
               f"deb [signed-by={DOCKER_GPG}] https://plain.example/docker noble stable\n")
        fs = FakeSystem("noble-held", files={DOCKER_LIST: src}, results={"gpg-docker.gpg": gapsproc.Result(0, TWO_KEYS, "")})
        k = {x["check"]: x for x in gapscheck.scan(fs)["checks"]}["keys"]
        self.assertEqual(self.rings(k), [(None, ["https://plain.example/docker"], "never"),
                                         ([FPR_A], [DOCKER_SITE], "2026-09-01T00:00:00Z"),
                                         ([FPR_B], ["https://mirror.example/docker"], "never")])
        self.assertEqual([(f["kind"], f["select"], f["sources"]) for f in k["findings"]], [("expired", [FPR_A], [DOCKER_SITE])])
        self.assertEqual(fs.calls.count("gpg-docker.gpg"), 1, "gpg reads the file once")

    def test_a_fingerprint_with_its_subkeys_or_alone(self):
        """A fingerprint selects the key and its subkeys; with `!` that key alone. P only certifies,
        its subkey S signed until 2026-09-01."""
        ring = WITH_SUBKEY.replace(":1800000000:", ":1788220800:")
        k = docker_keys(DOCKER_LINE.format(f"{DOCKER_GPG},{FPR_P}"), ring)
        self.assertEqual([(f["kind"], f["select"], f["expires"]) for f in k["findings"]],
                         [("expired", [FPR_P], "2026-09-01T00:00:00Z")])
        k = docker_keys(DOCKER_LINE.format(f"{DOCKER_GPG},{FPR_P}!"), ring)
        self.assertEqual((k["state"], k["findings"], k["unchecked"]),
                         ("partial", [], [{"file": DOCKER_GPG, "reason": "no-selected-key", "select": [FPR_P + "!"]}]))

    def test_a_fingerprint_without_a_file_selects_from_the_trusted_keyrings(self):
        trusted = {"gpg-ubuntu-keyring-2012-cdimage.gpg": gapsproc.Result(0, with_fpr(command_text(
                       "noble-held", "gpg-ubuntu-keyring-2012-cdimage.gpg"), UBUNTU_CD_2012), ""),
                   "gpg-ubuntu-keyring-2018-archive.gpg": gapsproc.Result(0, with_fpr(command_text(
                       "noble-held", "gpg-ubuntu-keyring-2018-archive.gpg"), UBUNTU_2018), "")}
        k = docker_keys(DOCKER_LINE.format(UBUNTU_2018), results=trusted)
        self.assertEqual([(r["file"], r["select"], r.get("default"), r["sources"], r["expires"])
                          for r in k["keyrings"] if r.get("default")],
                         [("/etc/apt/trusted.gpg.d/ubuntu-keyring-2018-archive.gpg", [UBUNTU_2018], True, [DOCKER_SITE], "never")])
        self.assertEqual(k["state"], "none")
        # A fingerprint none of them holds: apt cannot check the source; not checked, and which.
        k = docker_keys(DOCKER_LINE.format("E5" * 20), results=trusted)
        self.assertEqual((k["state"], k["unchecked"]),
                         ("partial", [{"file": gapscheck.TRUSTED_D, "reason": "no-selected-key", "select": ["E5" * 20]}]))

    def test_gpg_is_asked_for_the_fingerprints_of_subkeys(self):
        self.assertIn("--with-subkey-fingerprint", gapscheck.GPG_SHOW)


class Since(unittest.TestCase):
    def test_kept_from_scan_to_scan(self):
        first = gapscheck.scan(FakeSystem("noble-held"))
        later = gapscheck.scan(FakeSystem("noble-held", now="2026-10-25T08:00:00Z"), previous=first)
        c = {x["check"]: x for x in later["checks"]}
        self.assertEqual({f["since"] for f in c["held"]["findings"]}, {"2026-10-19T20:55:00Z"})
        self.assertEqual({f["since"] for f in c["auto"]["findings"]}, {"2026-10-19T20:55:00Z"})
        # New since the first scan: the lists and the last run of unattended-upgrades are old now.
        self.assertEqual([f["since"] for f in c["lists"]["findings"] if f["kind"] == "old"], ["2026-10-25T08:00:00Z"])
        self.assertEqual([f["since"] for f in c["uu"]["findings"]], ["2026-10-25T08:00:00Z"])
        self.assertNotIn("since", json.dumps([x for x in later["checks"] if x["check"] in ("cve", "upstream", "newer")]))

    def test_a_finding_that_changed_its_name(self):
        first = gapscheck.scan(FakeSystem("noble-held"))
        for f in {x["check"]: x for x in first["checks"]}["held"]["findings"]:
            if f["package"] == "docker-ce":
                f["package"] = "docker-ce-old"
        later = gapscheck.scan(FakeSystem("noble-held", now="2026-10-25T08:00:00Z"), previous=first)
        held = {f["package"]: f["since"] for f in {x["check"]: x for x in later["checks"]}["held"]["findings"]}
        self.assertEqual((held["docker-ce"], held["containerd.io"]), ("2026-10-25T08:00:00Z", "2026-10-19T20:55:00Z"))

    def test_odd_previous_documents(self):
        for prev in (None, {}, {"checks": "x"}, {"checks": [None, {"check": "held", "findings": "x"}]},
                     {"checks": [{"check": "held", "findings": [{"package": "docker-ce", "since": "yesterday"}]}]},
                     {"checks": [{"check": "held", "findings": [{"package": "docker-ce", "since": "2099-01-01T00:00:00Z"}]}]}):
            doc = gapscheck.scan(FakeSystem("noble-held"), only={"held"}, previous=prev)
            self.assertEqual({f["since"] for f in doc["checks"][0]["findings"]}, {"2026-10-19T20:55:00Z"}, prev)

    def test_scan_reads_its_previous_file(self):
        spec = importlib.util.spec_from_file_location("gaps_scan", os.path.join(HERE, "..", "lib", "gaps-scan.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "scan.json")
            self.assertIsNone(mod.previous(path))
            for text, want in (('{"format": 1}', {"format": 1}), ("[1]", None), ("{", None)):
                with open(path, "w") as f:
                    f.write(text)
                self.assertEqual(mod.previous(path), want, text)


def ack_scan(entries=NOBLE_ACCEPTED, now=None, edit=None, **kw):
    """noble-held with acknowledgements (fakesys.accepted_files); `edit` changes the file's entries."""
    files = accepted_files("noble-held", entries)
    if edit:
        doc = json.loads(files[gapscheck.ACCEPTED])
        edit(doc["accepted"])
        files = {gapscheck.ACCEPTED: json.dumps(doc)}
    return scan("noble-held", files=files, now=now, **kw)


class Acknowledged(unittest.TestCase):
    def test_marked_and_counted(self):
        doc, c = ack_scan()
        self.assertEqual((c["held"]["accepted"], c["cpu"]["accepted"]), (6, 1))
        for f in c["held"]["findings"]:
            self.assertEqual(f["accepted"], {"until": "2026-11-01", "at": "2026-10-19T08:00:00Z",
                                             "reason": "Docker is updated in the maintenance window on 2026-11-01"})
        self.assertNotIn("accepted", c["pro"])
        # Every finding of the checks with stable findings has its ref; the network data have none.
        for x in doc["checks"]:
            for f in x.get(gapscheck.SINCE[x["check"]][0] if x["check"] in gapscheck.SINCE else "-") or []:
                self.assertRegex(f["ref"], r"^" + x["check"] + r"-[0-9a-f]{12}$")
        self.assertNotIn('"ref"', json.dumps([x for x in doc["checks"] if x["check"] not in gapscheck.SINCE]))

    def test_ended_or_changed_counts_again(self):
        doc, c = ack_scan(now="2026-11-02T06:00:00Z")
        self.assertTrue(all(f["accepted"].get("expired") for f in c["held"]["findings"]))
        self.assertNotIn("accepted", c["held"])
        self.assertEqual(c["cpu"]["accepted"], 1, "tsa until 2027-01-15")

        def changed(items):
            items[0]["pin"] = "0123456789ab"        # acknowledged when it was something else
        _, c = ack_scan(edit=changed)
        held = {f["package"]: f for f in c["held"]["findings"]}
        self.assertTrue(held["containerd.io"]["accepted"].get("changed"))
        self.assertEqual(c["held"]["accepted"], 5)

    def test_a_held_package_with_a_security_fix_counts_again(self):
        """The pin of a held package is whether a newer version comes from a security source."""
        today = L.parse_day("2026-10-19")
        accepted = L.parse_accepted(accepted_files("noble-held", NOBLE_ACCEPTED)[gapscheck.ACCEPTED], today)
        doc, c = scan("noble-held")
        held = {f["package"]: f for f in c["held"]["findings"]}
        held["docker-ce"]["security"] = True
        held["docker-ce"]["candidate"] = "5:29.9.2-1~ubuntu.24.04~noble"       # a new version alone changes nothing
        held["containerd.io"]["candidate"] = "2.4.3-1~ubuntu.24.04~noble"
        gapscheck.mark_accepted(doc, accepted, today)
        self.assertEqual(held["docker-ce"]["accepted"].get("changed"), True)
        self.assertNotIn("changed", held["containerd.io"]["accepted"])
        self.assertEqual(c["held"]["accepted"], 5)

    def test_a_broken_file_is_no_acknowledgement(self):
        for text in ("{", "[]", '{"format": 1, "accepted": "x"}', "x" * (gapscheck.ACCEPTED_MAX + 1)):
            doc, c = scan("noble-held", files={gapscheck.ACCEPTED: text})
            self.assertNotIn("accepted", json.dumps(doc), text[:20])
            self.assertEqual(c["held"]["state"], "found")


def accept_helper():
    spec = importlib.util.spec_from_file_location("gaps_accept", os.path.join(HERE, "..", "lib", "gaps-accept.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class Stream(io.StringIO):
    def __init__(self, text="", tty=False):
        super().__init__(text)
        self.tty = tty

    def isatty(self):
        return self.tty


class AcceptHelper(unittest.TestCase):
    """gaps-accept.py, which gaps-ctl.sh runs as root for the page."""
    NOW = datetime(2026, 10, 19, 21, 0, tzinfo=timezone.utc)

    def setUp(self):
        self.mod = accept_helper()
        self.dir = tempfile.TemporaryDirectory()
        self.state = os.path.join(self.dir.name, "scan.json")
        self.accepted = os.path.join(self.dir.name, "accepted.json")
        with open(os.path.join(HERE, "fixtures", "scan-noble-held.json"), encoding="utf-8") as f:
            self.doc = json.load(f)
        with open(self.state, "w", encoding="utf-8") as f:
            json.dump(self.doc, f)
        held = {x["check"]: x for x in self.doc["checks"]}["held"]
        self.ref = next(f["ref"] for f in held["findings"] if f["package"] == "docker-ce")

    def tearDown(self):
        self.dir.cleanup()

    def call(self, *argv, reason="", tty=False, euid=0, now=None):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            rc = self.mod.main(list(argv), state=self.state, accepted=self.accepted,
                               lock=os.path.join(self.dir.name, "lock"), stdin=Stream(reason, tty), now=now or self.NOW,
                               euid=euid)
        return rc, out.getvalue() + err.getvalue()

    def entries(self):
        with open(self.accepted, encoding="utf-8") as f:
            return json.load(f)["accepted"]

    def test_accept_and_take_back(self):
        rc, out = self.call("accept", self.ref, "2026-11-01", reason="Docker waits for\nthe window")
        self.assertEqual((rc, out.strip()), (0, "Acknowledged until 2026-11-01: docker-ce"))
        self.assertEqual(oct(os.stat(self.accepted).st_mode & 0o777), "0o644")
        e = self.entries()
        self.assertEqual(len(e), 1)
        self.assertEqual({k: e[0][k] for k in ("ref", "check", "label", "until", "reason", "at")},
                         {"ref": self.ref, "check": "held", "label": "docker-ce", "until": "2026-11-01",
                          "reason": "Docker waits for the window", "at": "2026-10-19T21:00:00Z"})
        held = {f["package"]: f for f in {x["check"]: x for x in self.doc["checks"]}["held"]["findings"]}
        self.assertEqual(e[0]["pin"], L.finding_pin("held", held["docker-ce"]))
        # Again: replaced, not added. From a terminal no reason is read.
        self.assertEqual(self.call("accept", self.ref, "2026-12-01", reason="ignored", tty=True)[0], 0)
        self.assertEqual([(x["until"], x["reason"]) for x in self.entries()], [("2026-12-01", "")])
        rc, out = self.call("unaccept", self.ref)
        self.assertEqual((rc, out.strip(), self.entries()), (0, "Acknowledgement taken back: docker-ce", []))
        rc, out = self.call("unaccept", self.ref)
        self.assertEqual((rc, out.strip()), (0, "There was no acknowledgement for this finding."))

    def test_the_scan_marks_what_the_helper_wrote(self):
        self.call("accept", self.ref, "2026-11-01")
        with open(self.accepted, encoding="utf-8") as f:
            _, c = scan("noble-held", files={gapscheck.ACCEPTED: f.read()})
        self.assertEqual([f["package"] for f in c["held"]["findings"] if f.get("accepted")], ["docker-ce"])

    def test_refused(self):
        for argv in (["accept", "nope", "2026-11-01"], ["accept", self.ref], ["accept", self.ref, "2026-13-40"],
                     ["accept", self.ref, "1.11.2026"], ["unaccept"], ["unaccept", self.ref, "x"], ["remove", self.ref], []):
            self.assertEqual(self.call(*argv)[0], 64, argv)
        self.assertEqual(self.call("accept", self.ref, "2026-11-01", euid=1000)[0], 77)
        for day in ("2026-10-18", "2027-01-18"):
            rc, out = self.call("accept", self.ref, day)
            self.assertEqual(rc, 65, day)
            self.assertIn("90 days", out)
        self.assertEqual(self.call("accept", self.ref, "2027-01-17")[0], 0, "90 days ahead is the last day")
        rc, out = self.call("accept", "held-0123456789ab", "2026-11-01")
        self.assertEqual(rc, 65)
        self.assertIn("not in the last state", out)
        self.assertNotEqual(self.call("accept", "cve-0123456789ab", "2026-11-01")[0], 0)

    def test_old_acknowledgements_are_dropped(self):
        self.call("accept", self.ref, "2026-10-20")
        # 40 days later: ended more than 30 days ago, so the next write leaves it out.
        later = datetime(2026, 11, 28, 12, 0, tzinfo=timezone.utc)
        self.doc["generated"] = "2026-11-28T12:00:00Z"
        cli = next(f["ref"] for f in {x["check"]: x for x in self.doc["checks"]}["held"]["findings"]
                   if f["package"] == "docker-ce-cli")
        self.assertEqual(self.call("accept", cli, "2026-12-01", now=later)[0], 0)
        self.assertEqual([x["label"] for x in self.entries()], ["docker-ce-cli"])


AZ_SOURCES = "/etc/apt/sources.list.d/azentrius.sources"


def armored(body):
    return f"Signed-By:\n -----BEGIN PGP PUBLIC KEY BLOCK-----\n .\n {body}\n -----END PGP PUBLIC KEY BLOCK-----\n"


# Two stanzas in one sources file, each with a key of its own in Signed-By.
TWO_INLINE = ("Types: deb\nURIs: https://packages.azentrius.com/apt\nSuites: stable\nComponents: main\n" + armored("mQINBKEYONE") +
              "\nTypes: deb\nURIs: https://packages.example/apt\nSuites: stable\nComponents: main\n" + armored("mQINBKEYTWO"))


def inline_gpg(stdin):
    """gpg's view of the key it gets on stdin: A or B, both expired on 2026-09-01."""
    fpr = FPR_A if b"KEYONE" in stdin else FPR_B
    return gapsproc.Result(0, f"pub:e:4096:1:{fpr[-16:]}:1662463626:1788220800::-:::sc::::::23::0:\nfpr:::::::::{fpr}:\n", "")


class InlineKeys(unittest.TestCase):
    """Two different keys in one sources file, both expired: two findings, each acknowledged on its
    own, from the page (gaps-accept.py) to the status."""

    def fs(self, sources=TWO_INLINE, files=None, now=None):
        return FakeSystem("noble-held", files=dict({AZ_SOURCES: sources}, **(files or {})),
                          results={"gpg-stdin": inline_gpg}, now=now)

    @staticmethod
    def keys(doc):
        return {c["check"]: c for c in doc["checks"]}["keys"]

    def test_two_keys_and_one_acknowledged(self):
        first = gapscheck.scan(self.fs())
        found = self.keys(first)["findings"]
        self.assertEqual(len(found), 2)
        self.assertNotEqual(found[0]["ref"], found[1]["ref"], "two keys, two findings")
        self.assertEqual([(f["kind"], f["file"], f.get("inline"), f.get("fingerprints"), f["sources"]) for f in found],
                         [("expired", AZ_SOURCES, True, [FPR_A], ["https://packages.azentrius.com/apt"]),
                          ("expired", AZ_SOURCES, True, [FPR_B], ["https://packages.example/apt"])])
        # The first acknowledged as the page does it: gaps-accept.py with the last scan.json.
        with tempfile.TemporaryDirectory() as d:
            state, accepted = os.path.join(d, "scan.json"), os.path.join(d, "accepted.json")
            with open(state, "w", encoding="utf-8") as f:
                json.dump(first, f)
            with redirect_stdout(io.StringIO()):
                rc = accept_helper().main(["accept", found[0]["ref"], "2026-11-01"], state=state, accepted=accepted,
                                          lock=os.path.join(d, "lock"), stdin=Stream("the vendor's new key comes"),
                                          now=datetime(2026, 10, 19, 21, 0, tzinfo=timezone.utc), euid=0)
            self.assertEqual(rc, 0)
            with open(accepted, encoding="utf-8") as f:
                files = {gapscheck.ACCEPTED: f.read()}
        later = gapscheck.scan(self.fs(files=files, now="2026-10-20T08:00:00Z"), previous=first)
        k = self.keys(later)
        self.assertEqual([f["ref"] for f in k["findings"]], [f["ref"] for f in found], "the same findings scan after scan")
        self.assertEqual([f["since"] for f in k["findings"]], [first["generated"]] * 2)
        self.assertEqual([(f.get("accepted") or {}).get("reason") for f in k["findings"]], ["the vendor's new key comes", None])
        self.assertEqual(k["accepted"], 1)
        # The status leaves the first out; the second still counts.
        i = status_item(later, "keys")
        self.assertEqual((i["state"], i["value"], i["detail"]) if i else None,
                         ("warning", "1", "expired: azentrius.sources; 1 acknowledged"))

    def test_an_acknowledgement_of_0_7_0_covers_neither(self):
        """0.7.0 named such a finding by kind, file and inline alone: one ref for both keys. An
        acknowledgement given then must not hide both now."""
        old = "keys-" + hashlib.sha256(("keys" + json.dumps(["expired", AZ_SOURCES, True])).encode()).hexdigest()[:12]
        entry = {"ref": old, "check": "keys", "label": AZ_SOURCES, "pin": L.finding_pin("keys", {}),
                 "until": "2026-11-01", "reason": "", "at": "2026-10-19T08:00:00Z"}
        k = self.keys(gapscheck.scan(self.fs(files={gapscheck.ACCEPTED: json.dumps({"format": 1, "accepted": [entry]})})))
        self.assertEqual([f.get("accepted") for f in k["findings"]], [None, None])
        self.assertNotIn("accepted", k)

    def test_one_key_in_two_stanzas_is_one_keyring(self):
        k = self.keys(gapscheck.scan(self.fs(TWO_INLINE.replace("KEYTWO", "KEYONE")), only={"keys"}))
        self.assertEqual([(f["fingerprints"], f["sources"]) for f in k["findings"]],
                         [([FPR_A], ["https://packages.azentrius.com/apt", "https://packages.example/apt"])])


class Settings(unittest.TestCase):
    def fs(self, text, mode="644", uid=0):
        fs = FakeSystem("noble-held", files={"/etc/update-gaps.conf": text})
        fs.meta["stat"]["/etc/update-gaps.conf"] = {"type": "file", "mtime": 1, "mode": mode, "uid": uid}
        return fs

    def test_hidden(self):
        doc = gapscheck.scan(self.fs("HIDE_OUTSIDE=/opt/app1/bin\n"))
        o = {c["check"]: c for c in doc["checks"]}["outside"]
        self.assertEqual(o["state"], "found")
        self.assertEqual(o["hidden"], 9)
        self.assertEqual(o["hidden_paths"], ["/opt/app1/bin"])
        self.assertEqual(o["settings"], "/etc/update-gaps.conf")
        self.assertNotIn("/opt/app1/bin", [d["dir"] for d in o["dirs"]])

    def test_unknown_key(self):
        o = {c["check"]: c for c in gapscheck.scan(self.fs("HIDE=/opt\n"))["checks"]}["outside"]
        self.assertEqual((o["state"], o["reason"]), ("error", "settings"))

    def test_writable_by_others(self):
        o = {c["check"]: c for c in gapscheck.scan(self.fs("HIDE_OUTSIDE=/opt\n", mode="666"))["checks"]}["outside"]
        self.assertEqual((o["state"], o["reason"]), ("error", "settings"))

    def test_not_root_owned(self):
        o = {c["check"]: c for c in gapscheck.scan(self.fs("HIDE_OUTSIDE=/opt\n", uid=1000))["checks"]}["outside"]
        self.assertEqual(o["state"], "error")


class StateFile(unittest.TestCase):
    def test_write_atomic(self):
        spec = importlib.util.spec_from_file_location("gaps_scan", os.path.join(HERE, "..", "lib", "gaps-scan.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "scan.json")
            mod.write_atomic(path, {"format": 1})
            self.assertEqual(oct(os.stat(path).st_mode & 0o777), "0o644")
            with open(path) as f:
                self.assertEqual(json.load(f), {"format": 1})
            self.assertEqual(os.listdir(d), ["scan.json"])


class Fixtures(unittest.TestCase):
    def test_state_files_are_current(self):
        """test/fixtures/scan-*.json (the page tests and the preview read them)
        are what the helper writes for the recorded scenarios today."""
        import subprocess
        r = subprocess.run([sys.executable, os.path.join(HERE, "fixtures", "make_scans.py"), "--check"])
        self.assertEqual(r.returncode, 0)


class Proc(unittest.TestCase):
    def test_run(self):
        r = gapsproc.run(["sh", "-c", "echo out; echo err >&2; exit 3"], 10)
        self.assertEqual((r.rc, r.out, r.err.strip()), (3, "out\n", "err"))
        self.assertFalse(r.ok)

    def test_missing(self):
        self.assertTrue(gapsproc.run(["no-such-command-update-gaps"], 5).missing)

    def test_timeout_kills_the_group(self):
        r = gapsproc.run(["sh", "-c", "sleep 30 & sleep 30"], 1)
        self.assertTrue(r.timeout)

    def test_environment(self):
        r = gapsproc.run(["sh", "-c", 'echo "$PATH|$LC_ALL|$TZ"'], 5)
        self.assertEqual(r.out.strip(), "/usr/sbin:/usr/bin:/sbin:/bin|C|UTC")

    def test_unprivileged(self):
        """As root: nobody without other groups; else the caller. HOME is a
        fresh writable directory that is gone afterwards."""
        import pwd
        r = gapsproc.run_unprivileged(["sh", "-c", 'id -u; id -G; echo "$HOME|$XDG_CACHE_HOME"; touch "$HOME/log"'], 10)
        self.assertEqual(r.rc, 0, r.err)
        uid, groups, homes = r.out.strip().splitlines()
        if os.geteuid() == 0:
            nobody = pwd.getpwnam("nobody")
            self.assertEqual((uid, groups), (str(nobody.pw_uid), str(nobody.pw_gid)))
        else:
            self.assertEqual(uid, str(os.geteuid()))
        home, cache = homes.split("|")
        self.assertEqual(home, cache)
        self.assertFalse(os.path.exists(home))
        r = gapsproc.run_unprivileged(["cat"], 10, b"key")
        self.assertEqual(r.out, "key")

    @unittest.skipUnless(shutil.which("gpg") and os.path.exists(UBUNTU_KEYRING), "no gpg or no Ubuntu keyring")
    def test_gpg_shows_a_keyring_without_root(self):
        """The command check_keys runs, for real: gpg must be able to set up
        its fresh home (--no-options would keep it from that)."""
        with open(UBUNTU_KEYRING, "rb") as f:
            ring = f.read()
        for argv, stdin in ((gapscheck.GPG_SHOW + [UBUNTU_KEYRING], None), (gapscheck.GPG_SHOW, ring)):
            r = gapsproc.run_unprivileged(argv, 30, stdin)
            self.assertEqual(r.rc, 0, r.err)
            self.assertEqual(L.keyring_expiry(r.out), "never")
            # Every key with its fingerprint, so Signed-By can select one (Ubuntu's 2018 archive key).
            keys = L.keyring_keys(r.out)
            self.assertTrue(keys and all(k["fpr"] and len(k["fpr"]) == 40 for k in keys), r.out)
            self.assertEqual(L.keyring_expiry(r.out, [UBUNTU_2018]), "never")
            self.assertEqual(L.keyring_expiry(r.out, [UBUNTU_2018 + "!"]), "never")
            self.assertIsNone(L.keyring_expiry(r.out, ["E5" * 20]))


if __name__ == "__main__":
    unittest.main()
