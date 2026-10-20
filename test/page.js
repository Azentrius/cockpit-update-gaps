// SPDX-License-Identifier: Apache-2.0
// The real page (i18n.js, menu-status.js, gaps.js) in jsdom with a scripted Cockpit stub, for
// the page tests. boot() returns the window, the calls the page made and a
// handle on the stubbed state file; settle() waits until every stubbed answer
// has arrived and the page has handled it (no fixed delays).
const fs = require("fs");
const path = require("path");
const { JSDOM } = require("jsdom");

const PLUGIN = path.join(__dirname, "..", "plugin");
const FIX = path.join(__dirname, "fixtures");
// jsdom loads no external scripts; the page's own scripts are run below with eval, after the
// script elements are taken out of the document.
const html = fs.readFileSync(path.join(PLUGIN, "index.html"), "utf8");
const js =["icons.js", "i18n.js", "menu-status.js", "gaps.js"].map((f) => fs.readFileSync(path.join(PLUGIN, f), "utf8")).join("\n");
const NOW = "2026-10-19T21:00:00Z";
const STATE = "/var/lib/update-gaps/scan.json";
const STATUS_FILE = "/var/lib/update-gaps/status.json";

function scan(name) {
    return JSON.parse(fs.readFileSync(path.join(FIX, "scan-" + name + ".json"), "utf8"));
}

const STATUS = {
    root: true, timer: "inactive", next: null, running: false, state_file: true,
    dpkg_status_mtime: "2026-10-19T18:42:30Z", settings: null,
};

const pending = new Set();
function track(p) {
    const done = p.then(() => {}, () => {});
    pending.add(done);
    done.then(() => pending.delete(done));
    return p;
}

async function settle() {
    for (let round = 0; round < 500; round++) {
        if (pending.size) await Promise.all([...pending]);
        await new Promise((r) => setImmediate(r));
        if (!pending.size) return;
    }
    throw new Error("the page did not settle: helper calls keep coming");
}

// A stubbed process: resolves (or rejects with `fail`) after streaming `chunks`;
// `gate` (a promise) holds the answer back until the test releases it.
function proc(out, { chunks = [], fail = null, gate = null } = {}) {
    let cb = null;
    const p = new Promise((resolve, reject) => {
        const go = () => setImmediate(() => {
            chunks.forEach((c) => cb && cb(c));
            fail ? reject(fail) : resolve(out);
        });
        if (gate) gate.then(go); else go();
    });
    p.stream = (f) => { cb = f; return p; };
    return track(p);
}

function boot({ language = "en", state = scan("noble-held"), status = STATUS, now = NOW, monitor = true,
                onSpawn = null, location = [], hidden = false, statusFile = null, storage = {} } = {}) {
    const dom = new JSDOM(html, { runScripts: "outside-only", url: "https://localhost:9090/update-gaps/" });
    const w = dom.window;
    w.document.querySelectorAll("script").forEach((s) => s.remove());
    w.HTMLDialogElement.prototype.showModal = function () { this.setAttribute("open", ""); };
    w.HTMLDialogElement.prototype.close = function () { this.removeAttribute("open"); };
    w.Element.prototype.scrollIntoView = function () { w.__scrolled = this.id; };
    w.Date.now = () => Date.parse(now);
    const calls = { spawn: [], reads: [], jumps: [], notes: [] };
    const files = { [STATE]: state, "/etc/hostname": "server\n",
                    "/usr/share/cockpit/image-updates/manifest.json": monitor ? "{}" : null,
                    [STATUS_FILE]: statusFile };
    const watchers = [];
    const listeners = {};
    w.cockpit = {
        language,
        location: { path: location },
        hidden,
        addEventListener(ev, cb) { (listeners[ev] = listeners[ev] || []).push(cb); },
        removeEventListener(ev, cb) { listeners[ev] = (listeners[ev] || []).filter((x) => x !== cb); },
        file(p) {
            return {
                read() {
                    calls.reads.push(p);
                    return track(Promise.resolve(files[p] === undefined ? null : files[p]));
                },
                watch(cb) { watchers.push({ p, cb }); cb(files[p], "tag-1"); },
            };
        },
        spawn(argv, opts) {
            calls.spawn.push({ argv: argv.slice(), opts: opts || {} });
            const verb = argv.slice(1).join(" ");
            if (onSpawn) {
                const r = onSpawn(verb, opts || {}, files);
                if (r) return r;
            }
            if (verb === "status") return proc(JSON.stringify(typeof status === "function" ? status() : status));
            return proc("", { chunks: ["ok\n"] });
        },
        jump(p) { calls.jumps.push(p); },
        transport: { wait() {}, control(c, o) { calls.notes.push([c, JSON.parse(JSON.stringify(o))]); } },
    };
    Object.keys(storage).forEach((k) => w.localStorage.setItem(k, storage[k]));
    w.eval(js);
    // The shell's hint: cockpit.js changes cockpit.hidden and tells its listeners.
    const hint = (h) => { w.cockpit.hidden = h; (listeners.visibilitychange || []).slice().forEach((cb) => cb()); };
    return { w, d: w.document, calls, files, watchers, listeners, hint };
}

// The visible text, with a space between table cells and list items as a reader sees them.
function text(el) {
    if (!el) return "";
    const c = el.cloneNode(true);
    c.querySelectorAll("td, th, li, dt, dd, p, summary").forEach((x) => x.append(" "));
    return c.textContent.replace(/\s+/g, " ").trim();
}

module.exports = { boot, settle, scan, proc, text, STATUS, STATE, STATUS_FILE, NOW, PLUGIN, FIX };
