// SPDX-License-Identifier: Apache-2.0
// Stand-in for Cockpit's base1/cockpit.js so the page runs in a plain browser
// (file:// or any static server) with test data: no Cockpit, no root.
// build.py replaces __FIXTURES__ with test/fixtures/scan-*.json and __NOW__
// with a fixed clock. URL parameters:
//   ?scenario=noble-held | resolute-stale-lists | resolute-nodesource | resolute-nodesource-user | none
//   &admin=0     a user without administrative access
//   &timer=on    the regular check set up
//   &lang=de     German (po.js stand-in)
//   #/held       a link of the status: the page scrolls to that card
(function () {
    "use strict";
    const FX = __FIXTURES__;
    const NOW = Date.parse(__NOW__);
    Date.now = () => NOW;
    const q = new URLSearchParams(location.search);
    const scenario = q.get("scenario") || "noble-held";
    const admin = q.get("admin") !== "0" && !/-user$/.test(scenario);
    const timerOn = q.get("timer") === "on";

    function fakeProcess(out, chunks, fail) {
        let cb = null;
        const p = new Promise((resolve, reject) => {
            let i = 0;
            const next = () => {
                if (i < chunks.length) {
                    if (cb) cb(chunks[i]);
                    i += 1;
                    setTimeout(next, 120);
                } else if (fail) {
                    reject(fail);
                } else {
                    resolve(out);
                }
            };
            setTimeout(next, 40);
        });
        p.stream = (f) => { cb = f; return p; };
        return p;
    }

    const files = {
        "/var/lib/update-gaps/scan.json": scenario === "none" ? null : FX.scans[scenario],
        "/etc/hostname": "server\n",
        "/usr/share/cockpit/image-updates/manifest.json": "{}",
    };

    const path = () => location.hash.replace(/^#\/?/, "").split("/").filter(Boolean);
    const listeners = [];
    window.addEventListener("hashchange", () => {
        window.cockpit.location = { path: path() };
        listeners.forEach((cb) => cb());
    });

    window.cockpit = {
        language: "en",
        location: { path: path() },
        addEventListener(ev, cb) { if (ev === "locationchanged") listeners.push(cb); },
        removeEventListener() {},
        locale(po) {
            if (po && po[""] && po[""].language) this.language = po[""].language;
        },
        file(path) {
            return {
                read: () => Promise.resolve(path in files ? files[path] : null),
                watch: (cb) => cb(files[path], "tag-1"),
            };
        },
        spawn(argv, opts) {
            const verb = argv.slice(1).join(" ");
            if (verb === "status") {
                return fakeProcess(JSON.stringify({
                    root: admin, timer: timerOn ? "active" : "inactive", next: timerOn ? "2026-10-20T00:37:00Z" : null,
                    running: false, state_file: scenario !== "none", dpkg_status_mtime: "2026-10-19T18:42:30Z", settings: null,
                }), []);
            }
            if ((opts || {}).superuser === "require" && !admin) {
                return fakeProcess("", [], { problem: "access-denied" });
            }
            if (verb === "scan") return fakeProcess("", ["Checking this server …\n", "Done.\n"]);
            return fakeProcess("", ["+ systemctl " + (argv[1] === "install" ? "enable" : "disable") + " --now update-gaps-scan.timer\n", "Done.\n"]);
        },
        jump() {},
        // control: the menu icon (menu-status.js), which a plain browser has no menu for.
        transport: { wait() {}, control() {} },
    };
})();
