#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Stage 2: the radar (gapsradar.py, gaps-radar.py) and the checks that read
its network data (cve, upstream, newer in gapscheck.py). Offline: answers of
the services come from a stub, the recorded hosts from test/fixtures."""

import bz2
import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
import urllib.error

HERE = os.path.dirname(os.path.abspath(__file__))
LIB = os.path.join(HERE, "..", "lib")
sys.path.insert(0, LIB)
sys.path.insert(0, HERE)
sys.dont_write_bytecode = True
import gapscheck  # noqa: E402
import gapsradar as R  # noqa: E402
import gapsstatus  # noqa: E402
from fakesys import FakeSystem  # noqa: E402

FIX = os.path.join(HERE, "fixtures")


def load_radar_module():
    spec = importlib.util.spec_from_file_location("gaps_radar", os.path.join(LIB, "gaps-radar.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


radar_mod = load_radar_module()


def radar_text(scenario):
    with open(os.path.join(FIX, f"radar-{scenario}.json"), encoding="utf-8") as f:
        return f.read()


def checks(scenario, radar=None, only=("cve", "upstream", "newer"), **kw):
    files = {gapscheck.RADAR: radar} if radar is not None else {}
    doc = gapscheck.scan(FakeSystem(scenario, files=files, **kw), only=set(only))
    return {c["check"]: c for c in doc["checks"]}


OVAL = """<?xml version="1.0" encoding="UTF-8"?>
<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5">
 <definitions>
  <definition id="oval:x:def:100" class="inventory"><metadata><title>inventory</title></metadata></definition>
  <definition id="oval:x:def:1" class="vulnerability">
   <metadata><title>CVE-2026-4631 on Ubuntu 26.04 LTS (resolute) - medium</title>
    <reference source="CVE" ref_id="CVE-2026-4631" ref_url="https://www.cve.org/CVERecord?id=CVE-2026-4631" />
    <description>Cockpit's remote login
      passes user-supplied hostnames.</description>
    <advisory><severity>Medium</severity><public_date>2026-04-07T17:16:00Z</public_date>
     <cve priority="medium" cvss_score="9.8">CVE-2026-4631</cve></advisory></metadata>
   <criteria>
    <criterion test_ref="oval:x:tst:1" comment="cockpit source package in resolute, might be affected and may need fixing." />
    <criterion test_ref="oval:x:tst:2" comment="other source package in resolute, might be affected and may need fixing." />
   </criteria>
  </definition>
  <definition id="oval:x:def:2" class="vulnerability">
   <metadata><reference source="CVE" ref_id="CVE-2026-96512" />
    <advisory><severity>High</severity><cve priority="high">CVE-2026-96512</cve></advisory></metadata>
   <criteria>
    <criterion test_ref="oval:x:tst:3" comment="sudo source package in resolute, is affected and has been fixed (note: '1.9.17p2-1ubuntu3.2')." />
    <criterion test_ref="oval:x:tst:4" comment="sudo source package in noble, is affected and has been fixed (note: '1.9.15p5-3ubuntu5.24.04.4')." />
   </criteria>
  </definition>
  <definition id="oval:x:def:3" class="vulnerability">
   <metadata><reference source="CVE" ref_id="CVE-2026-1001" /><advisory><cve priority="low">CVE-2026-1001</cve></advisory></metadata>
   <criteria><criterion comment="cockpit source package in resolute, is affected, but a decision has been made to defer addressing it." /></criteria>
  </definition>
  <definition id="oval:x:def:4" class="vulnerability">
   <metadata><reference source="CVE" ref_id="not-a-cve" /></metadata>
   <criteria><criterion comment="cockpit source package in resolute, might be affected and may need fixing." /></criteria>
  </definition>
 </definitions>
</oval_definitions>
"""


class Response:
    def __init__(self, body, url="https://example.invalid/", etag=None):
        self.body, self.url, self.headers = io.BytesIO(body), url, {"ETag": etag} if etag else {}

    def read(self, n=-1):
        return self.body.read(n)

    def geturl(self):
        return self.url

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def opener_for(answers, seen=None):
    """A stand-in for urlopen: answers[url prefix] is bytes, an HTTP code, or a callable."""
    def open_(req, timeout=None):
        url = req.full_url
        if seen is not None:
            seen.append((url, req.headers.get("If-none-match")))
        for prefix, answer in answers.items():
            if url.startswith(prefix):
                if callable(answer):
                    answer = answer(req)
                if isinstance(answer, int):
                    raise urllib.error.HTTPError(url, answer, "stub", {}, None)
                return Response(answer, url, etag='"e1"')
        raise urllib.error.URLError("no route in the stub")
    return open_


class Parsers(unittest.TestCase):
    def test_versions(self):
        for v, up in (("5:29.8.0-1~ubuntu.24.04~noble", "29.8.0"), ("29.1.3-0ubuntu4.1", "29.1.3"),
                      ("362-1~bpo24.04.1", "362"), ("1:9.6p1-3ubuntu13.5", "9.6p1"),
                      ("1.13.3+ds1-2ubuntu0.24.04.3", "1.13.3"), ("360-1", "360"), ("0.18.1", "0.18.1")):
            self.assertEqual(R.upstream_version(v), up, v)
        for tag, v in (("369", "369"), ("docker-v29.9.1", "29.9.1"), ("v2.4.2", "2.4.2"), ("api/v1.51", None),
                       ("nightly", None)):
            self.assertEqual(R.tag_version(tag), v, tag)

    def test_launchpad(self):
        doc = {"entries": [
            {"source_package_name": "cockpit", "source_package_version": "362-1~bpo24.04.1", "status": "Published",
             "pocket": "Backports", "distro_series_link": "https://api.launchpad.net/1.0/ubuntu/noble",
             "date_published": "2026-07-22T15:22:58.524597+00:00"},
            {"source_package_name": "cockpit-other", "source_package_version": "1", "status": "Published"},
            {"source_package_name": "cockpit", "source_package_version": "300", "status": "Superseded"}]}
        self.assertEqual(R.parse_launchpad(doc, "cockpit"),
                         [{"series": "noble", "pocket": "Backports", "version": "362-1~bpo24.04.1",
                           "published": "2026-07-22T15:22:58"}])
        self.assertEqual(R.parse_launchpad(None, "cockpit"), [])

    def test_releases(self):
        doc = [{"tag_name": "368", "published_at": "2026-09-23T13:52:53Z", "body": "Fixes CVE-2026-91147, CVE-2026-91147 and GHSA-8647-2jxj-p2rc."},
               {"tag_name": "369-rc1", "prerelease": True, "body": "CVE-2026-1"},
               {"tag_name": "draft", "draft": True},
               {"tag_name": "website", "body": ""}]
        self.assertEqual(R.parse_releases(doc), [{"tag": "368", "version": "368", "published": "2026-09-23T13:52:53",
                                                  "fixes": ["CVE-2026-91147", "GHSA-8647-2jxj-p2rc"]}])
        self.assertEqual(R.parse_releases({"message": "rate limited"}), [])

    def test_oval(self):
        out = R.parse_oval(io.BytesIO(OVAL.encode()), ["cockpit", "sudo"], "resolute")
        self.assertEqual(sorted(out), ["cockpit", "sudo"])
        cockpit = out["cockpit"]["open"]
        self.assertEqual([(c["id"], c["priority"], c["status"]) for c in cockpit],
                         [("CVE-2026-4631", "medium", "needs-fixing"), ("CVE-2026-1001", "low", "deferred")])
        self.assertEqual((cockpit[0]["cvss"], cockpit[0]["public"]), ("9.8", "2026-04-07"))
        self.assertEqual(cockpit[0]["description"], "Cockpit's remote login passes user-supplied hostnames.")
        self.assertEqual(out["sudo"]["fixed"], [{"id": "CVE-2026-96512", "priority": "high", "cvss": None, "public": None,
                                                 "description": "", "version": "1.9.17p2-1ubuntu3.2"}])
        self.assertEqual(out["sudo"]["open"], [])

    def test_oval_refuses_a_doctype(self):
        evil = '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><oval_definitions/>'
        with self.assertRaises(ValueError):
            R.parse_oval(io.BytesIO(evil.encode()), ["cockpit"], "resolute")


class Fetch(unittest.TestCase):
    def test_etag_and_unchanged(self):
        seen = []
        body, tag = R.fetch("https://a.invalid/x", opener=opener_for({"https://a.invalid/": b"{}"}, seen))
        self.assertEqual((body, tag), (b"{}", '"e1"'))
        body, tag = R.fetch("https://a.invalid/x", '"e1"', opener=opener_for({"https://a.invalid/": 304}, seen))
        self.assertEqual((body, tag), (None, '"e1"'))
        self.assertEqual(seen[1][1], '"e1"')

    def test_refusals(self):
        with self.assertRaises(R.FetchError):
            R.fetch("http://a.invalid/x")
        with self.assertRaises(R.FetchError):
            R.fetch("https://a.invalid/x", opener=opener_for({"https://a.invalid/": b"x" * 20}), max_bytes=10)
        with self.assertRaises(R.FetchError) as e:
            R.fetch("https://a.invalid/x", opener=opener_for({"https://a.invalid/": 429}))
        self.assertTrue(e.exception.limited)
        with self.assertRaises(R.FetchError) as e:
            R.fetch("https://a.invalid/x", opener=opener_for({"https://a.invalid/": 500}))
        self.assertFalse(e.exception.limited)
        redirected = lambda req: Response(b"{}", "http://a.invalid/elsewhere")  # noqa: E731
        with self.assertRaises(R.FetchError):
            R.fetch("https://a.invalid/x", opener=lambda req, timeout=None: redirected(req))
        with self.assertRaises(R.FetchError):
            R.fetch_json("https://a.invalid/x", opener=opener_for({"https://a.invalid/": b"not json"}))

    def test_collect_keeps_old_answers_and_stops_when_asked_to(self):
        old = {"a": {"published": [1]}, "b": {"published": [2]}, "c": {"published": [3]}}
        asked = []

        def ask(key, prev):
            asked.append(key)
            if key == "a":
                return {"published": ["new"]}
            raise R.FetchError("HTTP 429", limited=True)
        out, state = radar_mod.collect(["a", "b", "c"], old, ask, sleep=lambda s: None)
        self.assertEqual(asked, ["a", "b"])
        self.assertEqual(out["a"], {"published": ["new"]})
        self.assertEqual((out["b"]["stale"], out["c"]["stale"]), (True, True))
        self.assertEqual((state["state"], state["limited"]), ("error", True))


class Radar(unittest.TestCase):
    def run_radar(self, answers, old=None, state_dir=None):
        with tempfile.TemporaryDirectory() as d:
            return radar_mod.radar(system=FakeSystem("resolute-nodesource"), old=old, state_dir=state_dir or d,
                                   opener=opener_for(answers), sleep=lambda s: None)

    def test_all_services(self):
        oval = bz2.compress(OVAL.encode())
        doc = self.run_radar({"https://security-metadata.canonical.com/": oval,
                              "https://api.launchpad.net/": json.dumps({"entries": []}).encode(),
                              "https://api.github.com/": json.dumps([]).encode()})
        self.assertEqual({k: v["state"] for k, v in doc["services"].items()},
                         {"oval": "ok", "launchpad": "ok", "github": "ok"})
        self.assertEqual((doc["distro"], doc["codename"]), ("ubuntu", "resolute"))
        self.assertIn("cockpit", doc["oval"])
        self.assertEqual(sorted(doc["launchpad"]), sorted(doc["selection"]["sources"]))
        json.dumps(doc)

    def test_offline_keeps_the_last_data(self):
        old = json.loads(radar_text("resolute-nodesource"))
        doc = self.run_radar({}, old=old)
        self.assertEqual(doc["services"]["launchpad"]["state"], "error")
        self.assertTrue(all(e.get("stale") for e in doc["launchpad"].values()))
        self.assertEqual(doc["services"]["oval"]["state"], "error")       # no OVAL file in the new state directory

    def test_never_as_root(self):
        if os.geteuid() != 0:
            self.skipTest("needs root to show the refusal")
        self.assertEqual(radar_mod.main(["--dry-run"]), 77)


class Checks(unittest.TestCase):
    def test_off_without_the_radar(self):
        c = checks("noble-held")
        for k in ("cve", "upstream", "newer"):
            self.assertEqual((c[k]["state"], c[k]["reason"]), ("skipped", "radar-off"), k)

    def test_recorded_hosts(self):
        c = checks("noble-held", radar_text("noble-held"))
        self.assertEqual(c["cve"]["state"], "found")
        cockpit = next(f for f in c["cve"]["findings"] if f["source"] == "cockpit")
        self.assertIn("CVE-2026-4631", [x["id"] for x in cockpit["open"]])
        up = {f["repo"]: f for f in c["upstream"]["findings"]}
        self.assertEqual((up["moby/moby"]["upstream"], up["moby/moby"]["distribution"]), ("29.8.0", False))
        self.assertIn("CVE-2026-53493", up["moby/moby"]["fixes"])
        self.assertTrue(up["cockpit-project/cockpit"]["distribution"])
        self.assertEqual(c["newer"]["state"], "found")
        c = checks("resolute-nodesource", radar_text("resolute-nodesource"))
        self.assertEqual(c["cve"]["state"], "found")
        self.assertIn("opencontainers/runc", [f["repo"] for f in c["upstream"]["findings"]])

    def test_another_release_or_broken_data(self):
        doc = json.loads(radar_text("noble-held"))
        doc["codename"] = "jammy"
        c = checks("noble-held", json.dumps(doc))
        self.assertEqual(c["cve"]["reason"], "radar-other-release")
        c = checks("noble-held", "{ not json")
        self.assertEqual((c["cve"]["state"], c["cve"]["reason"]), ("error", "radar"))
        c = checks("noble-held", json.dumps({"format": 2}))
        self.assertEqual(c["upstream"]["reason"], "radar")
        c = checks("noble-held", " " * (gapscheck.RADAR_MAX + 1))
        self.assertEqual(c["newer"]["state"], "error")

    def test_values_are_checked(self):
        doc = json.loads(radar_text("noble-held"))
        doc["oval"]["cockpit"]["open"] = [{"id": "<script>", "priority": "medium"},
                                          {"id": "CVE-2026-1001", "priority": "evil", "description": "x" * 900}]
        doc["github"]["moby/moby"]["releases"] = [{"version": "99; rm -rf /", "fixes": ["CVE-2026-2002"]},
                                                  {"version": "99.0", "fixes": ["CVE-2026-3003", "<b>"]}]
        doc["launchpad"]["sudo"]["published"] = [{"series": "../x", "pocket": "Release", "version": "99"}]
        c = checks("noble-held", json.dumps(doc))
        cockpit = next(f for f in c["cve"]["findings"] if f["source"] == "cockpit")
        self.assertEqual([(x["id"], x["priority"], len(x["description"])) for x in cockpit["open"]],
                         [("CVE-2026-1001", "untriaged", 300)])
        moby = next(f for f in c["upstream"]["findings"] if f["repo"] == "moby/moby")
        self.assertEqual((moby["newest"], moby["fixes"]), ("99.0", ["CVE-2026-3003"]))
        self.assertNotIn("sudo", [f["source"] for f in c["newer"]["findings"]])

    def test_stale_data_say_so(self):
        doc = json.loads(radar_text("noble-held"))
        doc["generated"] = "2026-10-01T00:00:00Z"
        c = checks("noble-held", json.dumps(doc))
        self.assertTrue(c["cve"]["radar"]["stale"])

    def test_only_its_own_selection(self):
        """A package the radar names but the scan did not select is not shown."""
        doc = json.loads(radar_text("noble-held"))
        doc["oval"]["nginx"] = {"open": [{"id": "CVE-2026-9009", "priority": "critical"}], "fixed": []}
        c = checks("noble-held", json.dumps(doc))
        self.assertNotIn("nginx", [f["source"] for f in c["cve"]["findings"]])

    def test_status_item(self):
        doc = gapscheck.scan(FakeSystem("resolute-nodesource", files={gapscheck.RADAR: radar_text("resolute-nodesource")}))
        st = gapsstatus.document(doc, "en", "0.2.0")
        item = next(i for i in st["items"] if i["id"] == "cve")
        self.assertEqual((item["state"], item["link"]), ("info", "#/cve"))
        self.assertTrue(item["detail"].startswith(item["value"] + " open: docker.io-app (24)"), item["detail"])
        self.assertEqual(gapsstatus.problems(st), [])
        self.assertNotIn("cve", [i["id"] for i in gapsstatus.document(gapscheck.scan(FakeSystem("noble-held")), "en", "0.2.0")["items"]])


if __name__ == "__main__":
    unittest.main()
