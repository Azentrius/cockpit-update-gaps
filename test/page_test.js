// SPDX-License-Identifier: Apache-2.0
// The page against the state files the helper writes for the recorded hosts
// (test/fixtures/scan-*.json): cards, overview, "No findings", "Not checked",
// page messages, refresh, the timer dialog, escaping, both languages.
const assert = require("assert");
const fs = require("fs");
const path = require("path");
const { boot, settle, scan, proc, text, STATUS, STATE, PLUGIN } = require("./page");

const tests = [];
const test = (name, fn) => tests.push({ name, fn });
const ids = (d, sel) => [...d.querySelectorAll(sel)].map((e) => e.id);

// German words and letters that must never show on the English page.
const GERMAN = /[äöüßÄÖÜ]|\b(und|nicht|oder|Pakete|Dienst|Quelle|Neustart|gehalten|Aktualisieren|Stand|Sie)\b/;

test("held host, English: cards in their fixed order, overview, lists", async () => {
    const { d, calls } = boot();
    await settle();
    assert.deepStrictEqual(ids(d, "#ug-cards > section"),
        ["ug-card-held", "ug-card-pro", "ug-card-restart", "ug-card-local", "ug-card-auto", "ug-card-outside"]);
    assert.strictEqual(d.querySelectorAll("#ug-sum-found .ug-chip").length, 6);
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
    assert.strictEqual(text(d.getElementById("ug-sig-version")), "Update Gaps 0.1.0");
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
