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


if __name__ == "__main__":
    unittest.main()
