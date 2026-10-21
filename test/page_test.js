// SPDX-License-Identifier: Apache-2.0
// The page against the state files the helper writes for the recorded hosts
// (test/fixtures/scan-*.json): cards, overview, "No findings", "Not checked",
// page messages, refresh, the timer dialog, escaping, both languages.
const assert = require("assert");
const fs = require("fs");
const path = require("path");
const { boot, settle, scan, proc, text, STATUS, STATE, NOW, PLUGIN, FIX } = require("./page");

const tests = [];
const test = (name, fn) => tests.push({ name, fn });
const ids = (d, sel) => [...d.querySelectorAll(sel)].map((e) => e.id);

// German words and letters that must never show on the English page.
const GERMAN = /[äöüßÄÖÜ]|\b(und|nicht|oder|Pakete|Dienst|Quelle|Neustart|gehalten|Aktualisieren|Stand|Sie)\b/;

test("held host, English: cards in their fixed order, overview, lists", async () => {
    const { d, calls } = boot();
    await settle();
    assert.deepStrictEqual(ids(d, "#ug-cards > section"),
        ["ug-card-held", "ug-card-pro", "ug-card-restart", "ug-card-cpu", "ug-card-local", "ug-card-auto", "ug-card-outside"]);
    assert.strictEqual(d.querySelectorAll("#ug-sum-found .ug-chip").length, 7);
    assert.match(text(d.getElementById("ug-sum-updates")), /No regular updates/);
    assert.match(text(d.getElementById("ug-meta")), /^Checked 5 minutes ago · package lists 7 hours ago$/);
    const held = d.getElementById("ug-card-held");
    assert.strictEqual(held.querySelectorAll("tbody tr").length, 6);
    assert.match(text(held), /docker-ce 5:29\.8\.0-1~ubuntu\.24\.04~noble 5:29\.9\.1-1~ubuntu\.24\.04~noble/);
    assert.match(text(held), /download\.docker\.com Docker, noble/);
    assert.match(text(held), /Why Software Updates does not show it/);
    assert.match(text(d.getElementById("ug-card-pro")), /once attached, the fixes are installed automatically/);
    assert.match(text(d.getElementById("ug-card-restart")), /6\.8\.0-146-generic runs, 6\.8\.0-147-generic is installed/);
    assert.match(text(d.getElementById("ug-card-auto")), /mirror\.hetzner\.com Ubuntu, noble-backports cockpit, cockpit-bridge/);
    const clean = text(d.getElementById("ug-clean-list"));
    assert.match(clean, /Regular updates: none/);
    assert.match(clean, /Package lists: last updated 7 hours ago/);
    assert.match(clean, /Backports/);
    assert.match(clean, /Support: supported until/);
    const un = d.getElementById("ug-unchecked-list");
    assert.ok(un.querySelector("#ug-open-monitor"), "Image Update Monitor is linked when installed");
    assert.match(text(un), /Container images/);
    assert.match(text(un), /needs data from the network/);
    assert.ok(d.getElementById("ug-loading").hidden, "no loading block once the state is there");
    assert.strictEqual(text(d.getElementById("ug-sig-version")), "Update Gaps 0.4.1");
    assert.strictEqual(text(d.getElementById("ug-sig-host")), "server");
    assert.ok(!GERMAN.test(text(d.body)), "no German on the English page: " + (text(d.body).match(GERMAN) || [])[0]);
    assert.deepStrictEqual(calls.spawn.map((c) => c.argv.slice(1).join(" ")), ["status"]);
    assert.strictEqual(calls.spawn[0].opts.superuser, "try");
    assert.ok(calls.spawn[0].opts.environ.includes("GAPS_LANG=en"));
});

test("German: the same page in German, with Sie", async () => {
    const { d, calls } = boot({ language: "de" });
    await settle();
    assert.strictEqual(d.documentElement.lang, "de");
    assert.match(text(d.getElementById("ug-card-held")), /Warum Software-Updates das nicht zeigt/);
    assert.match(text(d.getElementById("ug-card-held")), /Klären Sie/);
    assert.match(text(d.getElementById("ug-meta")), /^Stand vor 5 Minuten · Paketlisten vor 7 Stunden$/);
    assert.match(text(d.getElementById("ug-refresh")), /Aktualisieren/);
    assert.ok(!/\b(chk|card|name|reason|missing)\.[a-z]/.test(text(d.body)), "no raw text keys");
    assert.ok(calls.spawn[0].opts.environ.includes("GAPS_LANG=de"));
});

test("stale lists: missing and orphaned lists, sourceless packages explained", async () => {
    const { d } = boot({ state: scan("resolute-stale-lists") });
    await settle();
    const lists = text(d.getElementById("ug-card-lists"));
    assert.match(lists, /No package lists yet for the source https:\/\/packages\.azentrius\.com\/apt stable \(\/etc\/apt\/sources\.list\.d\/azentrius\.sources:1\)/);
    assert.match(lists, /Old package lists of packages\.azentrius\.de\/apt \(3 files\)/);
    const local = d.getElementById("ug-card-local");
    assert.ok(local.querySelector(".az-alert--warning"), "the lists hint on sourceless packages");
    assert.match(text(d.getElementById("ug-card-auto")), /\^docker\\\.io keeps out: docker\.io/);
});

test("nodesource host: apt-daily's error line, nothing to restart", async () => {
    const { d } = boot({ state: scan("resolute-nodesource") });
    await settle();
    assert.match(text(d.getElementById("ug-card-lists")), /E: Sub-process nm-online returned an error code \(1\)/);
    assert.ok(!d.getElementById("ug-card-restart"));
    assert.match(text(d.getElementById("ug-clean-list")), /Restart/);
});

test("without administrative access: the last state, a hint, no new check", async () => {
    const st = { ...STATUS, root: false };
    const { d, calls } = boot({ state: scan("resolute-nodesource-user"), status: st });
    await settle();
    assert.match(text(d.getElementById("ug-status")), /Shown without administrative access/);
    assert.ok(!d.getElementById("ug-timer-setup"), "no set-up button without admin");
    assert.match(text(d.getElementById("ug-clean-list")), /Package lists: last updated .* partly: Without administrative access the messages of apt-daily\.service were not read\./);
    d.getElementById("ug-refresh").click();
    await settle();
    assert.ok(!calls.spawn.some((c) => c.argv[1] === "scan"), "refresh only reloads the file");
});

test("fresh install with admin: one check by itself, then the state", async () => {
    let release;
    const gate = new Promise((r) => { release = r; });
    const { d, calls, files } = boot({
        state: null,
        onSpawn: (verb, opts, files) => {
            if (verb !== "scan") return null;
            assert.strictEqual(opts.superuser, "require");
            return proc("", { gate: gate.then(() => { files[STATE] = scan("noble-held"); }) });
        },
    });
    await new Promise((r) => setImmediate(r));
    for (let i = 0; i < 20 && !calls.spawn.some((c) => c.argv[1] === "scan"); i++) await new Promise((r) => setImmediate(r));
    assert.strictEqual(calls.spawn.filter((c) => c.argv[1] === "scan").length, 1);
    assert.ok(!d.getElementById("ug-loading").hidden, "the loading block while the first check runs");
    assert.match(text(d.getElementById("ug-refresh")), /Checking/);
    release();
    await settle();
    assert.ok(files[STATE]);
    assert.ok(d.getElementById("ug-loading").hidden);
    assert.ok(d.getElementById("ug-card-held"));
    assert.strictEqual(calls.spawn.filter((c) => c.argv[1] === "scan").length, 1, "only once");
});

test("fresh install without admin: says so, checks nothing", async () => {
    const { d, calls } = boot({ state: null, status: { ...STATUS, root: false, state_file: false } });
    await settle();
    assert.match(text(d.getElementById("ug-status")), /Not checked yet/);
    assert.match(text(d.getElementById("ug-meta")), /Not checked yet/);
    assert.ok(!calls.spawn.some((c) => c.argv[1] === "scan"));
    assert.ok(d.getElementById("ug-summary").hidden);
});

test("an old state and a state older than the last package change get a hint", async () => {
    let r = boot({ now: "2026-10-21T21:00:00Z" });
    await settle();
    assert.match(text(r.d.getElementById("ug-status")), /The last check is 2 days old/);
    r = boot({ status: { ...STATUS, dpkg_status_mtime: "2026-10-19T20:58:00Z" } });
    await settle();
    assert.match(text(r.d.getElementById("ug-status")), /Software changed after the last check/);
});

test("refresh with admin: the service runs, a failure and a running check are told", async () => {
    let mode = "fail";
    const { d, calls } = boot({
        onSpawn: (verb) => {
            if (verb !== "scan") return null;
            return proc("", { fail: mode === "fail" ? { exit_status: 1, message: "failed" } : mode === "busy" ? { exit_status: 75 } : null });
        },
    });
    await settle();
    d.getElementById("ug-refresh").click();
    await settle();
    assert.match(text(d.getElementById("ug-status")), /The check failed.*journalctl -u update-gaps-scan\.service/);
    mode = "busy";
    d.getElementById("ug-refresh").click();
    await settle();
    assert.match(text(d.getElementById("ug-status")), /A check is running already/);
    mode = "ok";
    d.getElementById("ug-refresh").click();
    await settle();
    assert.strictEqual(text(d.getElementById("ug-status")), "");
    assert.strictEqual(calls.spawn.filter((c) => c.argv[1] === "scan").length, 3);
});

test("timer: set up through the dialog, switched off, missing without systemd", async () => {
    let timer = "inactive";
    const { d, calls } = boot({
        status: () => ({ ...STATUS, timer, next: timer === "active" ? "2026-10-20T00:37:00Z" : null }),
        onSpawn: (verb) => {
            if (verb === "install timer") {
                timer = "active";
                return proc("", { chunks: ["+ systemctl enable --now update-gaps-scan.timer\n", "Regular check set up.\n"] });
            }
            return null;
        },
    });
    await settle();
    assert.match(text(d.getElementById("ug-sum-timer")), /Regular check: off\./);
    d.getElementById("ug-timer-setup").click();
    const dlg = d.getElementById("ug-dialog");
    assert.ok(dlg.hasAttribute("open"));
    assert.match(text(d.getElementById("ug-dialog-desc")), /update-gaps-scan\.timer/);
    assert.ok(!calls.spawn.some((c) => c.argv[1] === "install"), "nothing runs before the confirmation");
    d.getElementById("ug-dialog-confirm").click();
    await settle();
    const run = calls.spawn.find((c) => c.argv[1] === "install");
    assert.deepStrictEqual([...run.argv].slice(1), ["install", "timer"]);
    assert.strictEqual(run.opts.superuser, "require");
    assert.match(d.getElementById("ug-dialog-log").textContent, /systemctl enable --now update-gaps-scan\.timer/);
    assert.match(text(d.getElementById("ug-dialog-result")), /Done\./);
    assert.match(text(d.getElementById("ug-sum-timer")), /every 6 hours, next/);
    assert.ok(d.getElementById("ug-timer-off"));
    d.getElementById("ug-dialog-cancel").click();
    assert.ok(!dlg.hasAttribute("open"));
    const m = boot({ status: { ...STATUS, timer: "missing" } });
    await settle();
    assert.match(text(m.d.getElementById("ug-sum-timer")), /not available here/);
    assert.ok(!m.d.getElementById("ug-timer-setup"));
});

test("checks that failed, timed out or were skipped are listed under Not checked", async () => {
    const st = scan("noble-held");
    const by = Object.fromEntries(st.checks.map((c) => [c.check, c]));
    Object.assign(by.held, { state: "error", error: "apt-cache exited 100: E: broken", findings: undefined });
    Object.assign(by.updates, { state: "timeout", limit_s: 120 });
    Object.assign(by.pro, { state: "skipped", reason: "tool-missing", tool: "pro" });
    Object.assign(by.outside, { state: "error", reason: "settings", error: "line 1: unknown setting 'HIDE'", dirs: [] });
    const { d } = boot({ state: st });
    await settle();
    const un = text(d.getElementById("ug-unchecked-list"));
    assert.match(un, /Held packages: the check failed: apt-cache exited 100: E: broken\./);
    assert.match(un, /Regular updates: took longer than 120 s\./);
    assert.match(un, /Ubuntu Pro: pro is not installed\./);
    assert.match(un, /\/etc\/update-gaps\.conf is not valid: line 1: unknown setting 'HIDE'\./);
    assert.ok(!d.getElementById("ug-card-held"));
});

test("values from the system are escaped", async () => {
    const st = scan("noble-held");
    const held = st.checks.find((c) => c.check === "held");
    held.findings[0].package = '<img src=x onerror="window.__xss=1">';
    held.findings[0].origin.host = "evil`<b>`host";
    const { w, d } = boot({ state: st });
    await settle();
    assert.ok(!d.querySelector("#ug-card-held img"));
    assert.ok(!d.querySelector("#ug-card-held b"));
    assert.strictEqual(w.__xss, undefined);
    assert.match(text(d.getElementById("ug-card-held")), /<img src=x onerror=/);
});

test("restart without needrestart: the card says what it could not see", async () => {
    const st = scan("noble-held");
    const r = st.checks.find((c) => c.check === "restart");
    Object.assign(r, { services: [], missing: ["needrestart"] });
    const { d } = boot({ state: st });
    await settle();
    assert.match(text(d.getElementById("ug-card-restart")), /needrestart is not installed/);
});

test("backports, end of support and hidden folders render", async () => {
    const st = scan("resolute-stale-lists");
    const by = Object.fromEntries(st.checks.map((c) => [c.check, c]));
    Object.assign(by.backports, { state: "found", findings: [{ source: "cockpit", packages: ["cockpit", "cockpit-ws"],
        installed: "360-1", backport: "367-1~bpo26.04.1", suite: "resolute-backports" }] });
    Object.assign(by.eol, { state: "found", kind: "soon", days_left: 120, standard_until: "2027-02-16" });
    Object.assign(by.outside, { hidden: 9, hidden_paths: ["/opt/app1/bin"], settings: "/etc/update-gaps.conf" });
    const { d } = boot({ state: st });
    await settle();
    assert.match(text(d.getElementById("ug-card-backports")), /cockpit cockpit, cockpit-ws 360-1 367-1~bpo26\.04\.1 resolute-backports/);
    assert.match(text(d.getElementById("ug-card-eol")), /Standard support for 26\.04 LTS ends on .*, in 120 days\./);
    assert.match(text(d.getElementById("ug-card-outside")), /9 entries hidden by \/etc\/update-gaps\.conf: \/opt\/app1\/bin/);
});

test("other systems and newer formats are told", async () => {
    const st = scan("noble-held");
    st.pm = null;
    st.checks.forEach((c) => { c.state = "skipped"; c.reason = "unsupported-os"; });
    let r = boot({ state: st });
    await settle();
    assert.match(text(r.d.getElementById("ug-status")), /This system is not supported yet/);
    assert.strictEqual(r.d.querySelectorAll("#ug-cards > section").length, 0);
    const nf = scan("noble-held");
    nf.format = 2;
    r = boot({ state: nf });
    await settle();
    assert.match(text(r.d.getElementById("ug-status")), /The state comes from a newer version/);
});

test("links: Software Updates, Image Update Monitor, chips scroll to their card", async () => {
    const { w, d, calls } = boot();
    await settle();
    d.getElementById("ug-open-updates").click();
    d.getElementById("ug-open-monitor").click();
    assert.deepStrictEqual(calls.jumps, ["/updates", "/image-updates"]);
    d.querySelector('#ug-sum-found [data-go="pro"]').click();
    assert.strictEqual(w.__scrolled, "ug-card-pro");
    const r = boot({ monitor: false });
    await settle();
    assert.ok(!r.d.getElementById("ug-open-monitor"), "no link when Image Update Monitor is not installed");
});

test("a link of the status (#/held) scrolls to its card; anything else is ignored", async () => {
    let r = boot({ location: ["held"] });
    await settle();
    assert.strictEqual(r.w.__scrolled, "ug-card-held");
    r.w.cockpit.location = { path: ["pro"] };
    r.listeners.locationchanged.forEach((cb) => cb());
    assert.strictEqual(r.w.__scrolled, "ug-card-pro", "a new link while the page stays loaded");
    r = boot({ location: ["no-such-card"] });
    await settle();
    assert.strictEqual(r.w.__scrolled, undefined);
    r = boot({ location: ["held"], state: null, status: { ...STATUS, root: false, state_file: false } });
    await settle();
    assert.strictEqual(r.w.__scrolled, undefined, "no state, no card");
});

// --- The status icon in Cockpit's menu (menu-status.js) and the hidden start ---
const statusFixture = (name) => JSON.parse(fs.readFileSync(path.join(FIX, "status-" + name + ".json"), "utf8"));
const lastNote = (calls) => (calls.notes.length ? calls.notes[calls.notes.length - 1][1].page_status : "unset");
const TYPES = { danger: "error", warning: "warning", info: "info" };

test("menu icon: the state of status.json, the summary in the page's language", async () => {
    for (const name of ["noble-held", "resolute-nodesource", "resolute-stale-lists"]) {
        const st = statusFixture(name);
        for (const language of ["en", "de"]) {
            // The fixtures' time, an hour on: not out of date.
            const now = new Date(Date.parse(st.checked_at) + 3600e3).toISOString();
            const { calls } = boot({ language, now, statusFile: JSON.stringify(st) });
            await settle();
            const summary = language === "de" ? st.i18n.de.summary : st.summary;
            const want = TYPES[st.state] ? { type: TYPES[st.state], title: summary } : null;
            assert.deepStrictEqual(lastNote(calls), want, `${name} ${language}`);
            assert.strictEqual(calls.notes.length, 1, "sent once");
        }
    }
    const { calls } = boot();
    await settle();
    assert.deepStrictEqual(calls.notes, [["notify", { page_status: null }]], "no status.json: no icon, but sent");
    const broken = boot({ statusFile: "{broken" });
    await settle();
    assert.strictEqual(lastNote(broken.calls), null, "unreadable: no icon");
});

test("menu icon: judged as the Status Board does", async () => {
    const st = statusFixture("noble-held");
    const at = Date.parse(st.checked_at);
    const icon = (doc, hours, language = "en") =>
        boot({ language, now: new Date(at + hours * 3600e3).toISOString() }).w.UpdateGapsMenuStatus.statusOf(doc, at + hours * 3600e3);
    const plain = (o) => JSON.parse(JSON.stringify(o));
    // Never better than an item.
    const worse = plain(st);
    worse.state = "ok";
    worse.items[4].state = "danger";
    assert.deepStrictEqual(plain(icon(worse, 1)), { type: "error", title: st.summary });
    // An item older than its stale_after (24 hours) is at least a warning; the tooltip says since when.
    const ok = plain(st);
    ok.state = "ok";
    ok.items.forEach((i) => { i.state = "ok"; });
    assert.strictEqual(icon(ok, 23), null, "23 hours: nothing to show");
    const when = (loc) => new Date(at).toLocaleString(loc, { dateStyle: "medium", timeStyle: "short" });
    assert.deepStrictEqual(plain(icon(ok, 25)), { type: "warning", title: `${st.summary} (as of ${when("en-GB")}, out of date)` });
    assert.deepStrictEqual(plain(icon(ok, 25, "de")),
                           { type: "warning", title: `${st.i18n.de.summary} (Stand ${when("de-DE")}, veraltet)` });
    const old = plain(st);
    old.state = "danger";
    assert.strictEqual(icon(old, 30).type, "error", "a danger stays a danger when out of date");
    // What the board ignores.
    const odd = plain(ok);
    odd.items.forEach((i) => { i.checked_at = i.checked_at.replace("Z", ""); });
    assert.strictEqual(icon(odd, 48), null, "a time without a zone is not judged");
    [null, 3, "x", { ...st, schema: 2 }, { ...st, items: "x" }].forEach((d) => assert.strictEqual(icon(d, 1), null));
    assert.strictEqual(icon({ ...st, summary: "x".repeat(300), i18n: undefined }, 1).title.length, 200, "cut as the board cuts it");
});

test("menu icon: checked again the moment an item turns out of date", async () => {
    const st = statusFixture("noble-held");
    st.state = "ok";
    st.items.forEach((i) => { i.state = "ok"; });
    const at = Date.parse(st.checked_at);
    const r = boot({ now: new Date(at + 20 * 3600e3).toISOString(), statusFile: JSON.stringify(st) });
    const timers = [];
    r.w.setTimeout = (fn, ms) => { timers.push({ fn, ms }); return timers.length; };
    r.watchers.find((x) => x.p.endsWith("/status.json")).cb(JSON.stringify(st), "tag-2");
    await settle();
    assert.strictEqual(lastNote(r.calls), null);
    assert.deepStrictEqual(timers.map((x) => x.ms), [4 * 3600e3 + 1000], "again when it is 24 hours old");
    r.w.Date.now = () => at + 24 * 3600e3 + 1000;
    timers[0].fn();
    assert.strictEqual(lastNote(r.calls).type, "warning", "out of date: a warning");
});

test("preloaded hidden: only the icon; the page starts once it is shown", async () => {
    const st = statusFixture("noble-held");
    const r = boot({ hidden: true, statusFile: JSON.stringify(st), state: null, status: { ...STATUS, root: true, state_file: false } });
    await settle();
    assert.deepStrictEqual(lastNote(r.calls), { type: "warning", title: st.summary });
    assert.deepStrictEqual([r.calls.spawn.length, r.calls.reads], [0, []], "hidden: no helper, no other file");
    assert.strictEqual(text(r.d.getElementById("ug-sig-version")).includes("0.2.0"), false, "hidden: not started");
    r.hint(false);
    await settle();
    assert.ok(r.calls.spawn.some((c) => c.argv.join(" ").endsWith("gaps-ctl.sh status")), "shown: the page loads");
    assert.ok(r.calls.spawn.some((c) => c.argv.join(" ").endsWith("gaps-ctl.sh scan")), "and only now checks by itself");
    r.hint(true);
    r.hint(false);
    await settle();
    assert.strictEqual(r.calls.spawn.filter((c) => c.argv.join(" ").endsWith("gaps-ctl.sh status")).length, 2,
                       "shown again: no second start (the second status call is the reload after the scan)");
});

test("a link that comes while the page is hidden scrolls once it is shown", async () => {
    const r = boot();
    await settle();
    r.hint(true);
    r.w.cockpit.location = { path: ["restart"] };
    r.listeners.locationchanged.forEach((cb) => cb());
    assert.strictEqual(r.w.__scrolled, undefined, "hidden: nothing scrolls");
    r.hint(false);
    assert.strictEqual(r.w.__scrolled, "ug-card-restart", "shown: the card");
    r.w.__scrolled = undefined;
    r.hint(true);
    r.hint(false);
    assert.strictEqual(r.w.__scrolled, undefined, "shown again: the link was followed already");
});

test("the state file's watch reloads on a new tag only, never twice at once", async () => {
    const { calls, watchers } = boot();
    await settle();
    const reads = () => calls.reads.filter((p) => p === STATE).length;
    const before = reads();
    const wch = watchers.find((x) => x.p === STATE);
    wch.cb(null, "tag-1");
    await settle();
    assert.strictEqual(reads(), before, "same tag: no reload");
    wch.cb(null, "tag-2");
    wch.cb(null, "tag-3");
    await settle();
    assert.ok(reads() - before >= 1 && reads() - before <= 2, "one load plus at most one queued");
});

test("network data: the stage-2 cards, their place in the overview, a link between them", async () => {
    const { d } = boot({ state: scan("noble-held-radar"), status: { ...STATUS, radar: "active", radar_file: NOW } });
    await settle();
    const ids = [...d.querySelectorAll("#ug-cards > section")].map((s) => s.id.replace("ug-card-", ""));
    assert.deepStrictEqual(ids.filter((k) => ["held", "pro", "cve", "upstream", "newer"].includes(k)),
                           ["held", "pro", "cve", "upstream", "newer"]);
    const cve = text(d.getElementById("ug-card-cve"));
    assert.match(cve, /CVE-2026-4631/);
    assert.match(cve, /may need fixing/);
    assert.match(cve, /Checked for \d+ source packages/);
    const up = d.getElementById("ug-card-upstream");
    assert.match(text(up), /moby\/moby/);
    assert.match(text(up), /CVE-2026-53493/);
    assert.ok(up.querySelector(".az-label--warning"), "an upstream fix that is still open in Ubuntu is marked");
    assert.match(text(d.getElementById("ug-card-newer")), /in tenacious|in stonking/);
    assert.match(text(d.getElementById("ug-unchecked")), /only for the selected packages/);
    assert.ok(!/network data are \d/i.test(text(d.getElementById("ug-status"))), "fresh data: no hint");
});

test("network data: a failed fetch without a copy, old data, packages of unclear origin", async () => {
    const radarOn = { ...STATUS, radar: "active", radar_file: NOW };
    const cveOf = (s) => s.checks.find((x) => x.check === "cve");
    // Canonical's list could not be fetched and there is no copy: not "no findings", but not checked.
    let s = scan("noble-held-radar");
    let cve = cveOf(s);
    const radar = { ...cve.radar, service: "error", errors: ["HTTP 503"] };
    Object.keys(cve).forEach((k) => { if (k !== "check") delete cve[k]; });
    Object.assign(cve, { state: "error", reason: "radar-fetch", error: "HTTP 503", radar });
    let { d } = boot({ state: s, status: radarOn });
    await settle();
    assert.ok(!d.getElementById("ug-card-cve"));
    assert.doesNotMatch(text(d.getElementById("ug-clean-list")), /Unfixed security issues/);
    assert.match(text(d.getElementById("ug-unchecked-list")),
        /Unfixed security issues: Canonical's list of security issues could not be fetched, and there is no earlier copy: HTTP 503\./);
    ({ d } = boot({ state: s, status: radarOn, language: "de" }));
    await settle();
    assert.match(text(d.getElementById("ug-unchecked-list")), /Canonicals Liste der Sicherheitslücken ließ sich nicht holen/);
    // A six weeks old copy after failed fetches: still shown, with its age, also at the top of the page.
    s = scan("noble-held-radar");
    cve = cveOf(s);
    Object.assign(cve.radar, { data_at: "2026-09-07T20:55:00Z", stale: true, service: "partial", errors: ["HTTP 503"] });
    ({ d } = boot({ state: s, status: radarOn }));
    await settle();
    const card = text(d.getElementById("ug-card-cve"));
    assert.match(card, /The network data are 42 days old/);
    assert.match(card, /The last fetch failed \(HTTP 503\); these are the data of /);
    assert.match(text(d.getElementById("ug-status")), /The network data are 42 days old/);
    // Nothing found in that old copy: partly checked, and why.
    Object.assign(cve, { state: "partial", findings: [], counts: {}, missing: ["radar-old"] });
    ({ d } = boot({ state: s, status: radarOn }));
    await settle();
    assert.match(text(d.getElementById("ug-clean-list")),
        /Unfixed security issues: partly: The network data are older than three days: what came since is missing\./);
    // Packages the scan could not assign to Ubuntu: named, never dropped.
    s = scan("noble-held-radar");
    cveOf(s).unverified = ["sudo"];
    ({ d } = boot({ state: s, status: radarOn }));
    await settle();
    assert.match(text(d.getElementById("ug-card-cve")),
        /Not checked, because the installed version is in no package list any more and its origin is unclear: sudo\./);
    assert.ok(!GERMAN.test(text(d.body)), "no German on the English page: " + (text(d.body).match(GERMAN) || [])[0]);
});

test("network data: set up through the dialog, fetch now, switched off, old data told", async () => {
    let radar = "inactive";
    const { d, calls } = boot({
        status: () => ({ ...STATUS, radar, radar_file: radar === "active" ? NOW : null }),
        onSpawn: (verb) => {
            if (verb === "install radar") {
                radar = "active";
                return proc("", { chunks: ["+ systemctl enable --now update-gaps-radar.timer\n", "oval ok\n"] });
            }
            return null;
        },
    });
    await settle();
    assert.match(text(d.getElementById("ug-sum-radar")), /Network data: off\./);
    assert.match(text(d.getElementById("ug-unchecked")), /Set up the network data/);
    d.getElementById("ug-radar-setup").click();
    const desc = text(d.getElementById("ug-dialog-desc"));
    assert.match(desc, /security-metadata\.canonical\.com/);
    assert.match(desc, /\(noble\)/);
    assert.match(desc, /No versions, no host names/);
    assert.ok(!calls.spawn.some((c) => c.argv[1] === "install"), "nothing runs before the confirmation");
    d.getElementById("ug-dialog-confirm").click();
    await settle();
    const run = calls.spawn.find((c) => c.argv[1] === "install");
    assert.deepStrictEqual([...run.argv].slice(1), ["install", "radar"]);
    assert.strictEqual(run.opts.superuser, "require");
    d.getElementById("ug-dialog-cancel").click();
    assert.match(text(d.getElementById("ug-sum-radar")), /daily, last fetched/);
    d.getElementById("ug-radar-now").click();
    d.getElementById("ug-dialog-confirm").click();
    await settle();
    assert.ok(calls.spawn.some((c) => c.argv.length === 2 && c.argv[1] === "radar"));
    d.getElementById("ug-dialog-cancel").click();
    d.getElementById("ug-radar-off").click();
    d.getElementById("ug-dialog-confirm").click();
    await settle();
    assert.ok(calls.spawn.some((c) => c.argv[1] === "remove" && c.argv[2] === "radar"));

    // A state of 0.4.1 and older has no data_at: the age then comes from the radar's run.
    const old = scan("noble-held-radar");
    old.checks.forEach((c) => {
        if (c.radar) {
            c.radar = { ...c.radar, stale: true, generated: "2026-10-10T00:00:00Z" };
            delete c.radar.data_at;
        }
    });
    const r = boot({ state: old, status: { ...STATUS, radar: "active", radar_file: "2026-10-10T00:00:00Z" } });
    await settle();
    assert.match(text(r.d.getElementById("ug-status")), /network data are 10 days old/i);
    assert.match(text(r.d.getElementById("ug-card-cve")), /10 days old/);
    const u = boot({ state: scan("noble-held-radar"), status: { ...STATUS, root: false, radar: "inactive" } });
    await settle();
    assert.ok(!u.d.getElementById("ug-radar-setup"), "without administrative access no button");
});

test("cards open and close through their title; the browser keeps which are closed", async () => {
    const r = boot();
    await settle();
    const btn = r.d.querySelector("#ug-card-held .ug-toggle");
    const body = r.d.getElementById("ug-card-held-body");
    assert.strictEqual(btn.getAttribute("aria-expanded"), "true");
    assert.strictEqual(btn.getAttribute("aria-controls"), "ug-card-held-body");
    assert.ok(!body.hidden);
    btn.click();
    assert.strictEqual(btn.getAttribute("aria-expanded"), "false");
    assert.ok(body.hidden);
    assert.ok(r.d.getElementById("ug-card-held").classList.contains("is-collapsed"));
    assert.deepStrictEqual(JSON.parse(r.w.localStorage.getItem("update-gaps:collapsed")), ["held"]);
    r.d.querySelector("#ug-card-pro .ug-toggle").click();
    assert.deepStrictEqual(JSON.parse(r.w.localStorage.getItem("update-gaps:collapsed")), ["held", "pro"]);
    // The overview, "No findings" and "Not checked" do not fold.
    ["ug-summary", "ug-clean", "ug-unchecked"].forEach((id) => assert.ok(!r.d.querySelector(`#${id} .ug-toggle`), id));

    // A new visit (the same browser): closed cards stay closed, a re-render keeps them so.
    const again = boot({ storage: { "update-gaps:collapsed": JSON.stringify(["held", "pro", "nonsense"]) } });
    await settle();
    assert.ok(again.d.getElementById("ug-card-held-body").hidden);
    assert.ok(again.d.getElementById("ug-card-pro-body").hidden);
    assert.ok(!again.d.getElementById("ug-card-restart-body").hidden);
    again.d.getElementById("ug-refresh").click();
    await settle();
    assert.ok(again.d.getElementById("ug-card-held-body").hidden, "still closed after a new check");
    // A chip of the overview and a link of the status open the card they lead to.
    again.d.querySelector('#ug-sum-found [data-go="pro"]').click();
    assert.ok(!again.d.getElementById("ug-card-pro-body").hidden);
    assert.deepStrictEqual(JSON.parse(again.w.localStorage.getItem("update-gaps:collapsed")), ["held"]);
    const linked = boot({ location: ["held"], storage: { "update-gaps:collapsed": '["held"]' } });
    await settle();
    assert.ok(!linked.d.getElementById("ug-card-held-body").hidden);
    assert.strictEqual(linked.w.__scrolled, "ug-card-held");

    // Broken or blocked storage: every card open, nothing fails.
    const broken = boot({ storage: { "update-gaps:collapsed": "{not json" } });
    await settle();
    assert.ok(!broken.d.getElementById("ug-card-held-body").hidden);
});

test("CPU, firmware, snaps: a VM, a physical server, and what the hosts do not have", async () => {
    // public-host (noble-held): a VM where the kernel reports tsa without microcode.
    let { d } = boot();
    await settle();
    const cpu = text(d.getElementById("ug-card-cpu"));
    assert.match(cpu, /Transient Scheduler Attacks \(AMD\)\s*tsa Vulnerable: Clear CPU buffers attempted, no microcode the provider/);
    assert.match(cpu, /Virtual machine \(kvm\): the hypervisor supplies the microcode/);
    assert.match(cpu, /CPU: AMD EPYC-Genoa Processor, 8 threads, microcode 0x1000065\./);
    assert.match(cpu, /ask the provider whether their hosts have it/);
    assert.match(cpu, /4 more with a mitigation, 10 not affected\./);
    assert.match(text(d.getElementById("ug-unchecked-list")),
        /Firmware: fwupd is not installed; in a virtual machine the provider looks after the firmware\./);
    assert.match(text(d.getElementById("ug-clean-list")), /Snaps: no snaps installed/);
    assert.doesNotMatch(text(d.getElementById("ug-unchecked-list")), /Snaps/);
    // build-host (resolute-stale-lists): a physical server, nothing vulnerable.
    ({ d } = boot({ state: scan("resolute-stale-lists") }));
    await settle();
    assert.ok(!d.getElementById("ug-card-cpu"));
    assert.match(text(d.getElementById("ug-clean-list")),
        /CPU vulnerabilities: nothing reported as vulnerable \(6 with a mitigation, 11 not affected\)/);
    assert.match(text(d.getElementById("ug-unchecked-list")), /Firmware: fwupd is not installed, so firmware and BIOS updates are not checked\./);
    // What the hosts do not have: a physical server without the microcode package, protections off,
    // a firmware update, a held snap and a failed refresh.
    const s = scan("resolute-stale-lists");
    const c = (k) => s.checks.find((x) => x.check === k);
    Object.assign(c("cpu"), {
        state: "found", mitigations_off: ["mitigations=off"],
        microcode_package: { name: "amd64-microcode", installed: null, candidate: "3.20251202.1ubuntu2", available: true },
        findings: [{ name: "mds", text: "Mitigation: Clear CPU buffers; SMT vulnerable", kind: "partial", microcode: false, fix: "here" }],
    });
    Object.assign(c("firmware"), {
        state: "found", machine: "metal", reason: undefined, tool: undefined,
        findings: [{ kind: "update", device: "UEFI dbx", vendor: "Linux Foundation", version: "371", new: "<b>377</b>",
                     urgency: "high", issues: ["CVE-2026-12345"] },
                   { kind: "metadata-old", remote: "lvfs", days: 40 }, { kind: "refresh-off", timer: "disabled" }],
        source: ["fwupdmgr get-updates --json"],
    });
    Object.assign(c("snaps"), {
        state: "found", installed: 2,
        findings: [{ kind: "held", snap: "lxd", until: null },
                   { kind: "old-base", snap: "lxd", base: "core20", release: "20.04 LTS", ended: "2025-05-29", esm_until: "2030-04-23" },
                   { kind: "refresh-failed", id: "42", when: "2026-10-19T10:00:00Z", summary: "Auto-refresh snap \"lxd\"",
                     error: "cannot refresh: <x>" }],
        source: ["snapd REST API (/run/snapd.socket)"],
    });
    ({ d } = boot({ state: s }));
    await settle();
    assert.deepStrictEqual(ids(d, "#ug-cards > section").filter((x) => /cpu|firmware|snaps/.test(x)),
        ["ug-card-cpu", "ug-card-firmware", "ug-card-snaps"]);
    const cpu2 = text(d.getElementById("ug-card-cpu"));
    assert.match(cpu2, /Protections switched off The kernel was started with mitigations=off/);
    assert.match(cpu2, /amd64-microcode is not installed Without amd64-microcode the CPU runs the microcode of the BIOS only/);
    assert.match(cpu2, /Microarchitectural Data Sampling \(Intel\)\s*mds Mitigation: Clear CPU buffers; SMT vulnerable this server/);
    assert.match(cpu2, /Physical server: board ASRockRack B450D4U-V1L, BIOS L2\.12 of 30 Aug 2024\./);
    const fw = d.getElementById("ug-card-firmware");
    assert.match(text(fw), /UEFI dbx\s*Linux Foundation 371 <b>377<\/b> high CVE-2026-12345/);
    assert.ok(!fw.querySelector("b"), "values from fwupd are escaped");
    assert.match(text(fw), /The metadata of lvfs are 40 days old/);
    assert.match(text(fw), /fwupd-refresh\.timer is disabled/);
    const sn = d.getElementById("ug-card-snaps");
    assert.match(text(sn), /lxd is held \(snap refresh --hold\) until further notice\./);
    assert.match(text(sn), /lxd builds on core20 \(Ubuntu 20\.04 LTS\), whose standard support ended on 29 May 2025\. With Ubuntu Pro \(ESM\) until 23 Apr 2030\./);
    assert.match(text(sn), /Auto-refresh snap "lxd" \(snap change 42\)/);
    assert.ok(!sn.querySelector("x"), "an error of snapd is escaped");
    assert.match(text(sn), /2 snaps installed\./);
    assert.ok(!GERMAN.test(text(d.body)), "no German on the English page: " + (text(d.body).match(GERMAN) || [])[0]);
    // The same in German.
    ({ d } = boot({ state: s, language: "de" }));
    await settle();
    assert.match(text(d.getElementById("ug-card-cpu")), /Schutz abgeschaltet/);
    assert.match(text(d.getElementById("ug-card-firmware")), /Die Metadaten von lvfs sind 40 Tage alt/);
    assert.match(text(d.getElementById("ug-card-snaps")), /lxd ist zurückgehalten \(snap refresh --hold\) bis auf Weiteres\./);
});

test("texts: every key in both languages, same plural shape, no em dash", () => {
    global.window = {};
    require(path.join(PLUGIN, "i18n.js"));
    const { en, de } = global.window.UpdateGapsI18n;
    assert.deepStrictEqual(Object.keys(en).sort(), Object.keys(de).sort());
    Object.keys(en).forEach((k) => assert.strictEqual(typeof en[k], typeof de[k], k));
    const all = JSON.stringify({ en, de });
    assert.ok(!all.includes(String.fromCharCode(0x2014)), "no em dash (U+2014)");
    ["updates", "held", "pro", "restart", "lists", "local", "auto", "backports", "outside", "eol"].forEach((k) => {
        assert.ok(en["name." + k] && en["chk." + k], k);
    });
    ["needs-root", "tool-missing", "not-applicable", "unsupported-os", "unknown-release", "timeout", "error", "settings"]
        .forEach((k) => assert.ok(en["reason." + k], k));
    ["needrestart", "services", "journal"].forEach((k) => assert.ok(en["missing." + k], k));
    assert.ok(!GERMAN.test(Object.values(en).map((v) => (typeof v === "object" ? v.one + v.other : v)).join(" ")
        .replace(/Image Update Monitor|Update Gaps/g, "")), "no German in I18N.en");
    const source = fs.readFileSync(path.join(PLUGIN, "gaps.js"), "utf8");
    [...source.matchAll(/\bt\("([a-zA-Z.]*[a-zA-Z])"/g)].forEach((m) => assert.ok(m[1] in en, "missing text " + m[1]));
});

(async () => {
    let failed = 0;
    for (const { name, fn } of tests) {
        try {
            await fn();
            console.log("ok   " + name);
        } catch (e) {
            failed++;
            console.log("FAIL " + name + "\n     " + (e.stack || e).toString().split("\n").slice(0, 6).join("\n     "));
        }
    }
    console.log(failed ? `\n${failed} FAILED` : "\nALL PAGE TESTS PASSED");
    process.exit(failed ? 1 : 0);
})();
