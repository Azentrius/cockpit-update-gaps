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
broken settings, another distribution."""

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "lib"))
sys.path.insert(0, HERE)
import gapscheck  # noqa: E402
import gapsproc  # noqa: E402
from fakesys import FakeSystem  # noqa: E402

STATES = {"found", "none", "partial", "skipped", "timeout", "error"}
CHECKS = [name for name, _ in gapscheck.CHECKS]


def scan(scenario, **kw):
    doc = gapscheck.scan(FakeSystem(scenario, **kw))
    return doc, {c["check"]: c for c in doc["checks"]}


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
        self.assertEqual(c["findings"], [{"name": "tsa", "text": "Vulnerable: Clear CPU buffers attempted, no microcode",
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
    remotes = json.dumps({"Remotes": [{"Id": "lvfs", "Kind": "download", "Enabled": "true", "ModificationTime": mtime},
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
        self.assertEqual(c["findings"][0], {"kind": "update", "device": "UEFI dbx", "vendor": "Linux Foundation",
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
        self.assertEqual(c["findings"], [
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


if __name__ == "__main__":
    unittest.main()
