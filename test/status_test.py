#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""The status of the add-on (status contract of the Azentrius add-ons,
schema 1): gapsstatus.py against the recorded hosts, and gaps-status.py, the
verb the Status Board calls. Offline, no root needed."""

import importlib.util
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout

HERE = os.path.dirname(os.path.abspath(__file__))
LIB = os.path.join(HERE, "..", "lib")
sys.path.insert(0, LIB)
sys.dont_write_bytecode = True
import gapsstatus  # noqa: E402

FIX = os.path.join(HERE, "fixtures")
SCENARIOS = ("noble-held", "resolute-stale-lists", "resolute-nodesource")
GERMAN = re.compile(r"[äöüÄÖÜß]|\b(und|nicht|Paket|Pakete|Neustart|geprüft|Quelle|Dienst|Befunde)\b")
PRIVATE = re.compile(r"\b\d{1,3}(\.\d{1,3}){3}\b|[0-9a-f]{0,4}:[0-9a-f]{0,4}:[0-9a-f:]+|https?:|@|/(etc|var|home|opt|usr)/")


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


helper = load_module("gaps_status", os.path.join(LIB, "gaps-status.py"))


def fixture(name):
    with open(os.path.join(FIX, name), encoding="utf-8") as f:
        return json.load(f)


def call(argv, path):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        rc = helper.main(argv, path)
    return rc, out.getvalue(), err.getvalue()


def texts(doc):
    yield doc["summary"]
    for i in doc["items"]:
        yield i["title"]
        yield i.get("detail") or ""
        yield i.get("value") or ""


class Contract(unittest.TestCase):
    def test_recorded_hosts(self):
        """Every status file of a recorded host keeps the contract in both
        languages: fields, ids, links, states, the overall state."""
        for s in SCENARIOS:
            status = gapsstatus.status_file(fixture(f"scan-{s}.json"), "0.1.0")
            self.assertEqual(gapsstatus.problems(status), [], s)
            for lang in ("en", "de"):
                doc = gapsstatus.localize(status, lang)
                self.assertNotIn("i18n", doc)
                self.assertEqual(gapsstatus.problems(doc), [], (s, lang))
                self.assertEqual((doc["addon"], doc["label"], doc["schema"]), ("update-gaps", "Update Gaps", 1))
                self.assertEqual([i["id"] for i in doc["items"]], [i["id"] for i in status["items"]])
                self.assertEqual([i["state"] for i in doc["items"]], [i["state"] for i in status["items"]])
                for i in doc["items"]:
                    self.assertLessEqual(len(i.get("detail", "")), gapsstatus.MAX_DETAIL, (s, lang, i["id"]))

    def test_findings_of_the_hosts(self):
        """What each recorded host reports (test/fixtures/<scenario>/)."""
        want = {
            # In the two VMs the kernel reports tsa without microcode: only the provider can fix it, so info.
            "noble-held": ("warning", {"held": "warning", "restart": "warning", "cpu": "info", "pro": "info",
                                       "lists": "ok", "eol": "ok", "updates": "ok"}),
            "resolute-stale-lists": ("warning", {"held": "ok", "restart": "warning", "cpu": "ok", "pro": "info",
                                                 "lists": "warning", "eol": "ok", "updates": "ok"}),
            "resolute-nodesource": ("info", {"held": "ok", "restart": "ok", "cpu": "info", "pro": "info",
                                             "lists": "info", "eol": "ok", "updates": "ok"}),
        }
        for s, (state, items) in want.items():
            doc = gapsstatus.document(fixture(f"scan-{s}.json"), "en", "0.1.0")
            self.assertEqual(doc["state"], state, s)
            self.assertEqual({i["id"]: i["state"] for i in doc["items"]}, items, s)
        held = gapsstatus.document(fixture("scan-noble-held.json"), "en", "0.1.0")["items"][0]
        self.assertEqual((held["value"], held["link"]), ("6", "#/held"))
        self.assertIn("docker-ce", held["detail"])

    def test_languages(self):
        for s in SCENARIOS:
            status = gapsstatus.status_file(fixture(f"scan-{s}.json"), "0.1.0")
            en = list(texts(gapsstatus.localize(status, "en")))
            de = list(texts(gapsstatus.localize(status, "de")))
            for x in en:
                self.assertIsNone(GERMAN.search(x), (s, x))
            self.assertTrue(any(GERMAN.search(x) for x in de), s)
        self.assertEqual(set(gapsstatus.T["en"]), set(gapsstatus.T["de"]))
        for k, v in gapsstatus.T["en"].items():
            self.assertEqual(type(v), type(gapsstatus.T["de"][k]), k)
        self.assertNotIn(chr(0x2014), json.dumps(gapsstatus.T, ensure_ascii=False))

    def test_nothing_private(self):
        """Only numbers, states and names: no addresses, URLs, user names or paths."""
        for s in SCENARIOS:
            status = gapsstatus.status_file(fixture(f"scan-{s}.json"), "0.1.0")
            for lang in ("en", "de"):
                for x in texts(gapsstatus.localize(status, lang)):
                    self.assertIsNone(PRIVATE.search(x), (s, lang, x))

    def test_overall_state(self):
        o = gapsstatus.overall
        self.assertEqual(o([]), "none")
        self.assertEqual(o([{"state": "none"}]), "none")
        self.assertEqual(o([{"state": "none"}, {"state": "ok"}]), "ok")
        self.assertEqual(o([{"state": "ok"}, {"state": "info"}]), "info")
        self.assertEqual(o([{"state": "info"}, {"state": "warning"}, {"state": "none"}]), "warning")
        self.assertEqual(o([{"state": "danger"}, {"state": "warning"}]), "danger")

    def test_checks_that_did_not_run(self):
        doc = fixture("scan-noble-held.json")
        for c in doc["checks"]:
            if c["check"] == "held":
                c.clear()
                c.update(check="held", state="error", error="apt-mark exited 1")
            if c["check"] == "restart":
                c.clear()
                c.update(check="restart", state="timeout", limit_s=120, command="needrestart")
            if c["check"] == "pro":
                c.clear()
                c.update(check="pro", state="skipped", reason="tool-missing", tool="pro")
        items = {i["id"]: i for i in gapsstatus.document(doc, "en", "0.1.0")["items"]}
        self.assertEqual((items["held"]["state"], items["held"]["detail"]), ("none", "check failed"))
        self.assertEqual(items["restart"]["state"], "none")
        self.assertEqual((items["pro"]["state"], items["pro"]["detail"]), ("none", "not checked"))

    def test_not_applicable_and_partial(self):
        doc = fixture("scan-resolute-nodesource-user.json")
        st = gapsstatus.document(doc, "en", "0.1.0")
        self.assertEqual(gapsstatus.problems(st), [])
        restart = next(i for i in st["items"] if i["id"] == "restart")
        self.assertIn("partly checked", restart["detail"])
        for c in doc["checks"]:
            if c["check"] == "pro":
                c.clear()
                c.update(check="pro", state="skipped", reason="not-applicable")
        self.assertNotIn("pro", [i["id"] for i in gapsstatus.document(doc, "en", "0.1.0")["items"]])

    def test_held_without_newer_versions_is_ok(self):
        doc = fixture("scan-noble-held.json")
        held = next(c for c in doc["checks"] if c["check"] == "held")
        for f in held["findings"]:
            f["newer"], f["candidate"] = 0, None
        item = gapsstatus.document(doc, "de", "0.1.0")["items"][0]
        self.assertEqual((item["state"], item["value"]), ("ok", "0"))
        self.assertTrue(item["detail"].startswith("gehalten, nichts Neueres: containerd.io"), item["detail"])

    def test_end_of_support(self):
        doc = fixture("scan-noble-held.json")
        eol = next(c for c in doc["checks"] if c["check"] == "eol")
        eol.update(state="found", kind="ended", standard_until="2026-05-31", days_left=-141)
        st = gapsstatus.document(doc, "en", "0.1.0")
        self.assertEqual(st["state"], "danger")
        eol.update(kind="soon", standard_until="2027-01-31", days_left=103)
        item = next(i for i in gapsstatus.document(doc, "en", "0.1.0")["items"] if i["id"] == "eol")
        self.assertEqual((item["state"], item["value"]), ("warning", "103"))

    def test_long_details_end_at_a_word(self):
        doc = fixture("scan-noble-held.json")
        restart = next(c for c in doc["checks"] if c["check"] == "restart")
        restart["services"] = [f"a-rather-long-service-name-{n}.service" for n in range(12)]
        restart["reboot_required"]["packages"] = [f"linux-image-7.0.0-{n}-generic" for n in range(30, 38)]
        for lang in ("en", "de"):
            item = next(i for i in gapsstatus.document(doc, lang, "0.1.0")["items"] if i["id"] == "restart")
            self.assertLessEqual(len(item["detail"]), gapsstatus.MAX_DETAIL)
            self.assertTrue(item["detail"].endswith(" " + chr(0x2026)), item["detail"])
            self.assertNotIn(", " + chr(0x2026), item["detail"])

    def test_old_lists_in_hours_then_days(self):
        doc = fixture("scan-resolute-nodesource.json")
        lists = next(c for c in doc["checks"] if c["check"] == "lists")
        for hours, want in ((50, "older than 50 hours"), (2882, "older than 120 days")):
            lists.update(state="found", findings=[{"kind": "old", "hours": hours}])
            item = next(i for i in gapsstatus.document(doc, "en", "0.1.0")["items"] if i["id"] == "lists")
            self.assertEqual((item["state"], item["detail"]), ("warning", want))

    def test_other_systems(self):
        doc = fixture("scan-noble-held.json")
        doc["pm"] = None
        st = gapsstatus.document(doc, "de", "0.1.0")
        self.assertEqual((st["state"], [i["id"] for i in st["items"]]), ("none", ["scan"]))
        self.assertEqual(gapsstatus.problems(st), [])

    def test_problems_finds_broken_documents(self):
        good = gapsstatus.status_file(fixture("scan-noble-held.json"), "0.1.0")
        for change in (lambda d: d.pop("summary"), lambda d: d.update(state="red"),
                       lambda d: d.update(state="ok"), lambda d: d.update(schema=2),
                       lambda d: d["items"][0].update(id="Held Packages"),
                       lambda d: d["items"][0].update(link="https://example.invalid/"),
                       lambda d: d["items"][0].update(value=6),
                       lambda d: d["items"][0].pop("stale_after"),
                       lambda d: d.update(items={})):
            d = json.loads(json.dumps(good))
            change(d)
            self.assertNotEqual(gapsstatus.problems(d), [], d)

    def test_fixtures_are_what_the_service_writes(self):
        for s in SCENARIOS:
            self.assertEqual(fixture(f"status-{s}.json"),
                             gapsstatus.status_file(fixture(f"scan-{s}.json"), "0.1.0"), s)

    def test_version_from_the_page(self):
        with open(os.path.join(HERE, "..", "plugin", "gaps.js"), encoding="utf-8") as f:
            want = re.search(r'const VERSION = "([^"]+)"', f.read()).group(1)
        self.assertEqual(gapsstatus.version(), want)

    def item(self, doc, cid, lang="en"):
        return next((i for i in gapsstatus.document(doc, lang, "0.1.0")["items"] if i["id"] == cid), None)

    def test_cpu(self):
        doc = fixture("scan-noble-held.json")
        cpu = next(c for c in doc["checks"] if c["check"] == "cpu")
        i = self.item(doc, "cpu")
        self.assertEqual((i["state"], i["value"], i["link"]), ("info", "1", "#/cpu"))
        self.assertEqual(i["detail"], "tsa; only the provider can fix it (virtual machine)")
        self.assertEqual(self.item(doc, "cpu", "de")["detail"], "tsa; beheben kann es nur der Anbieter (virtuelle Maschine)")
        cpu["mitigations_off"] = ["mitigations=off"]
        self.assertEqual(self.item(doc, "cpu")["state"], "warning", "switched off here: this server's to fix")
        cpu["mitigations_off"] = []
        cpu["findings"][0]["fix"] = "here"
        self.assertEqual((self.item(doc, "cpu")["state"], self.item(doc, "cpu")["detail"]), ("warning", "tsa"))
        cpu.update(state="none", findings=[], microcode_package={"name": "amd64-microcode", "installed": None})
        cpu["state"] = "found"
        i = self.item(doc, "cpu")
        self.assertEqual((i["state"], i["detail"]), ("warning", "amd64-microcode is not installed"))
        cpu.clear()
        cpu.update(check="cpu", state="skipped", reason="container")
        self.assertIsNone(self.item(doc, "cpu"), "a container has no CPU item")

    def test_firmware_and_snaps_only_with_a_finding(self):
        doc = fixture("scan-resolute-stale-lists.json")
        self.assertIsNone(self.item(doc, "firmware"), "fwupd missing: no item")
        self.assertIsNone(self.item(doc, "snaps"), "no snaps: no item")
        fw = next(c for c in doc["checks"] if c["check"] == "firmware")
        fw.clear()
        fw.update(check="firmware", state="found", findings=[
            {"kind": "update", "device": "UEFI dbx"}, {"kind": "metadata-old", "days": 40}, {"kind": "refresh-off"}])
        i = self.item(doc, "firmware")
        self.assertEqual((i["state"], i["value"]), ("warning", "1"))
        self.assertEqual(i["detail"], "1 update: UEFI dbx; the metadata of fwupd are 40 days old; fwupd-refresh.timer is off")
        fw["findings"] = [{"kind": "metadata-old", "days": 40}]
        self.assertEqual(self.item(doc, "firmware")["state"], "info")
        sn = next(c for c in doc["checks"] if c["check"] == "snaps")
        sn.update(state="found", findings=[{"kind": "held", "snap": "lxd"},
                                           {"kind": "old-base", "snap": "lxd", "base": "core20"}])
        i = self.item(doc, "snaps")
        self.assertEqual((i["state"], i["detail"]), ("info", "held: lxd; base out of support: lxd (core20)"))
        sn["findings"].append({"kind": "refresh-failed"})
        i = self.item(doc, "snaps", "de")
        self.assertEqual(i["state"], "warning")
        self.assertIn("1 fehlgeschlagene Aktualisierung", i["detail"])
        st = gapsstatus.status_file(doc, "0.1.0")
        self.assertEqual(gapsstatus.problems(st), [])


class Verb(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.dir.name, "status.json")

    def tearDown(self):
        self.dir.cleanup()

    def write(self, content):
        with open(self.path, "w", encoding="utf-8") as f:
            f.write(content if isinstance(content, str) else json.dumps(content, ensure_ascii=False))

    def test_reads_the_file_in_the_language_asked_for(self):
        self.write(fixture("status-noble-held.json"))
        rc, out, _ = call(["status", "--lang", "de"], self.path)
        doc = json.loads(out)
        self.assertEqual((rc, doc["state"]), (0, "warning"))
        self.assertTrue(doc["summary"].startswith("Befunde in 4 Bereichen"), doc["summary"])
        self.assertEqual(doc["version"], gapsstatus.version())
        self.assertNotIn("i18n", doc)
        self.assertEqual(gapsstatus.problems(doc), [])
        rc, out, _ = call(["status"], self.path)
        self.assertTrue(json.loads(out)["summary"].startswith("Findings in 4 areas"))
        for lang, first in (("de-DE", "Befunde"), ("de_AT", "Befunde"), ("--lang=de", "Befunde"),
                            ("fr", "Findings"), ("pt-BR", "Findings")):
            argv = ["status", lang] if lang.startswith("--") else ["status", "--lang", lang]
            rc, out, _ = call(argv, self.path)
            self.assertEqual(rc, 0, lang)
            self.assertTrue(json.loads(out)["summary"].startswith(first), lang)

    def test_findings_are_no_error(self):
        doc = fixture("scan-noble-held.json")
        eol = next(c for c in doc["checks"] if c["check"] == "eol")
        eol.update(state="found", kind="ended", standard_until="2026-05-31", days_left=-141)
        self.write(gapsstatus.status_file(doc, "0.1.0"))
        rc, out, _ = call(["status", "--lang", "en"], self.path)
        self.assertEqual((rc, json.loads(out)["state"]), (0, "danger"))

    def test_without_the_file(self):
        for lang, summary in (("en", "Not checked yet."), ("de", "Noch nicht geprüft.")):
            rc, out, _ = call(["status", "--lang", lang], self.path)
            doc = json.loads(out)
            self.assertEqual((rc, doc["state"], doc["summary"]), (0, "none", summary))
            self.assertEqual(gapsstatus.problems(doc), [])

    def test_a_broken_file_is_none(self):
        for content in ("", "{", "[]", json.dumps({"schema": 2}), json.dumps({"schema": 1, "state": "ok"})):
            self.write(content)
            rc, out, _ = call(["status", "--lang", "en"], self.path)
            doc = json.loads(out)
            self.assertEqual((rc, doc["state"], doc["items"][0]["title"]), (0, "none", "State not readable"), content)

    def test_unreadable_is_77(self):
        rc, out, err = call(["status", "--lang", "en"], self.dir.name)   # a directory: open() fails
        self.assertEqual((rc, out), (77, ""))
        self.assertIn("cannot read", err)

    def test_wrong_calls_are_64(self):
        for argv in ([], ["scan"], ["status", "--lang"], ["status", "--lang", "de", "--now"],
                     ["status", "--lang", "../../etc"], ["status", "--lang", "de;id"], ["status", "de"],
                     ["status", "--language", "de"], ["Status"]):
            rc, out, err = call(argv, self.path)
            self.assertEqual((rc, out), (64, ""), argv)
            self.assertIn("usage", err)

    def test_fast_and_without_root(self):
        """The real script as a separate process: well within 2 seconds, and it
        writes nothing (no bytecode next to it)."""
        before = sorted(os.listdir(LIB))
        t = time.monotonic()
        r = subprocess.run([sys.executable, "-IB", os.path.join(LIB, "gaps-status.py"), "status", "--lang", "de"],
                           capture_output=True, text=True, timeout=10)
        took = time.monotonic() - t
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(r.stdout)["schema"], 1)
        self.assertLess(took, 2.0)
        self.assertEqual(sorted(os.listdir(LIB)), before)


class Scan(unittest.TestCase):
    """gaps-scan.py --output FILE --status FILE, as the service calls it."""

    def test_writes_both_files(self):
        mod = load_module("gaps_scan", os.path.join(LIB, "gaps-scan.py"))
        doc = fixture("scan-noble-held.json")
        mod.gapscheck.scan = lambda: doc
        mod.lock = lambda: None
        with tempfile.TemporaryDirectory() as d:
            scan, status = os.path.join(d, "scan.json"), os.path.join(d, "status.json")
            with redirect_stdout(io.StringIO()):
                self.assertEqual(mod.main(["--output", scan, "--status", status]), 0)
            self.assertEqual(sorted(os.listdir(d)), ["scan.json", "status.json"])
            for p in (scan, status):
                self.assertEqual(oct(os.stat(p).st_mode & 0o777), "0o644")
            with open(status, encoding="utf-8") as f:
                st = json.load(f)
            self.assertEqual(gapsstatus.problems(st), [])
            self.assertEqual(st["checked_at"], doc["generated"])
            with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                mod.main(["--status", status])


if __name__ == "__main__":
    unittest.main()
