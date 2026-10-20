// SPDX-License-Identifier: Apache-2.0
/* Update Gaps, a Cockpit add-on: where this server misses updates although
 * Cockpit's "Software Updates" lists none, and for every finding why that page
 * does not show it and what one can do.
 *
 *   state  -> cockpit.file(/var/lib/update-gaps/scan.json)   written by
 *             update-gaps-scan.service (gaps-scan.py, root, no network);
 *             readable without administrative access
 *   status -> cockpit.spawn(gaps-ctl.sh status)              timer, admin, dpkg change
 *   refresh-> cockpit.spawn(gaps-ctl.sh scan)                runs the service, waits
 *   timer  -> cockpit.spawn(gaps-ctl.sh install|remove timer) through the dialog
 *
 * The page only reads. The one change it can make is to set up or switch off
 * the add-on's own timer, shown first and confirmed. Texts: plugin/i18n.js
 * (English and German, following Cockpit's language). Everything from the
 * system reaches the page escaped (esc / tr). No build step, no framework, no
 * external requests.
 */

(function () {
    "use strict";

    // --- Configuration -----------------------------------------------------
    // The one place for the version (SemVer). index.html loads every script and
    // stylesheet of the add-on with ?v=VERSION; tools/check-version.sh keeps
    // them in step.
    const VERSION = "0.3.0";
    const LIB = "/usr/lib/cockpit-update-gaps/";
    const CTL = LIB + "gaps-ctl.sh";
    const STATE_PATH = "/var/lib/update-gaps/scan.json";
    const MONITOR_MANIFEST = "/usr/share/cockpit/image-updates/manifest.json";
    const FORMAT = 1;          // newest scan.json format this page knows
    const STALE_H = 24;        // a state older than this gets a hint
    const CARDS = ["held", "pro", "cve", "upstream", "restart", "lists", "local", "auto", "backports", "newer", "outside", "eol"];
    const RADAR_CHECKS = ["cve", "upstream", "newer"];   // stage 2: they read the radar's network data
    const ALL = ["updates"].concat(CARDS);

    // --- i18n --------------------------------------------------------------
    const I18N = window.UpdateGapsI18n;
    const LANG = /^de([-_]|$)/i.test(String(cockpit.language || "")) ? "de" : "en";
    const LOCALE = LANG === "de" ? "de-DE" : "en-GB";

    function t(key, vars) {
        let s = I18N[LANG][key];
        if (s === undefined) s = I18N.en[key];
        if (s === undefined) return key;
        if (typeof s === "object") s = (vars && vars.n === 1) ? s.one : s.other;
        return s.replace(/\{(\w+)\}/g, (m, k) => (vars && k in vars ? String(vars[k]) : m));
    }
    function esc(s) {
        return String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({
            "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
        }[c]));
    }
    // A translated text as HTML: `…` marks a path or a command (<code>).
    function rich(s) {
        return esc(s).replace(/`([^`]+)`/g, "<code>$1</code>");
    }
    // A translated text with values from the system: escaped as a whole, and a
    // backtick in a value cannot open or close a <code> of the text.
    function tr(key, vars) {
        const v = {};
        Object.keys(vars || {}).forEach((k) => { v[k] = String(vars[k] == null ? "" : vars[k]).replace(/`/g, "'"); });
        return rich(t(key, v));
    }
    function code(s) { return `<code>${esc(s)}</code>`; }

    function icon(name) {
        const def = (window.AzIcons || {})[name];
        if (!def) return "";
        return `<svg class="az-icon" viewBox="${def.viewBox}" aria-hidden="true" focusable="false" data-icon="${name}">` +
               `<path d="${def.d}"></path></svg>`;
    }

    function applyStaticTexts() {
        document.documentElement.lang = LANG;
        document.querySelectorAll("[data-i18n]").forEach((el) => { el.textContent = t(el.dataset.i18n); });
        document.querySelectorAll("span[data-icon]").forEach((el) => { el.outerHTML = icon(el.dataset.icon); });
    }

    const $ = (id) => document.getElementById(id);

    // --- Time --------------------------------------------------------------
    function fmtDate(iso) {
        const d = new Date(iso || "");
        return isNaN(d) ? "?" : d.toLocaleString(LOCALE, { dateStyle: "medium", timeStyle: "short" });
    }
    function fmtDay(iso) {
        const d = new Date(String(iso || "").length === 10 ? iso + "T12:00:00Z" : iso || "");
        return isNaN(d) ? "?" : d.toLocaleDateString(LOCALE, { dateStyle: "medium" });
    }
    function hoursSince(iso) {
        const ts = Date.parse(iso || "");
        return isNaN(ts) ? null : Math.max(0, (Date.now() - ts) / 3600000);
    }
    function ago(iso) {
        const h = hoursSince(iso);
        if (h === null) return "?";
        const min = Math.round(h * 60);
        if (min < 1) return t("ago.now");
        if (min < 60) return t("ago.min", { n: min });
        const hr = Math.round(h);
        if (hr < 48) return t("ago.h", { n: hr });
        return t("ago.d", { n: Math.round(hr / 24) });
    }
    function age(iso) {
        const h = Math.round(hoursSince(iso) || 0);
        return h < 48 ? t("age.h", { n: h }) : t("age.d", { n: Math.round(h / 24) });
    }

    // --- Helpers and the system -------------------------------------------
    function spawn(argv, superuser) {
        return cockpit.spawn(argv, { superuser, err: superuser === "require" ? "out" : "message",
                                     environ: ["GAPS_LANG=" + LANG] });
    }
    function isNoAdmin(ex) {
        ex = ex || {};
        return ex.exit_status === 77 || /access-denied|not-authorized|authentication/.test(ex.problem || "");
    }

    const stateFile = cockpit.file(STATE_PATH, { syntax: JSON });
    let doc = null;        // scan.json
    let status = null;     // gaps-ctl.sh status
    let monitor = false;   // Image Update Monitor installed
    let loadError = null;
    let flash = null;      // a message from the last scan (failed, busy) until the next good one
    let scanning = false;
    let autoScanned = false;

    function isAdmin() { return !!(status && status.root); }
    function checksOf(d) {
        const out = {};
        ((d && d.checks) || []).forEach((c) => { if (c && c.check) out[c.check] = c; });
        return out;
    }

    // --- Page messages -----------------------------------------------------
    function alertHtml(kind, title, bodyHtml) {
        const ic = kind === "danger" ? "exclamation-circle" : kind === "warning" ? "exclamation-triangle" : "info-circle";
        return `<div class="az-alert${kind === "info" ? "" : " az-alert--" + kind}" role="${kind === "danger" ? "alert" : "status"}">` +
               `<span class="az-alert__icon">${icon(ic)}</span>` +
               `<p class="az-alert__title">${esc(title)}</p>` +
               (bodyHtml ? `<p class="az-alert__body">${bodyHtml}</p>` : "") + "</div>";
    }
    function renderStatus() {
        const out = [];
        if (loadError) out.push(alertHtml("danger", t("status.loadErrorTitle"), esc(loadError)));
        if (flash) out.push(alertHtml(flash.kind, t(flash.title), rich(t(flash.body))));
        if (status && !status.root) out.push(alertHtml("info", t("status.noAdminTitle"), rich(t("status.noAdmin"))));
        if (!doc && !loadError && !scanning && (!isAdmin() || autoScanned)) {
            out.push(alertHtml("info", t("status.noStateTitle"), rich(t("status.noState"))));
        }
        if (doc) {
            if (doc.format > FORMAT) out.push(alertHtml("info", t("status.newerTitle"), rich(t("status.newer"))));
            if (doc.pm !== "apt") out.push(alertHtml("info", t("status.unsupportedTitle"), rich(t("status.unsupported"))));
            const h = hoursSince(doc.generated);
            if (h !== null && h > STALE_H) {
                out.push(alertHtml("warning", t("status.oldTitle", { age: age(doc.generated) }), rich(t("status.old"))));
            } else if (status && status.dpkg_status_mtime && Date.parse(status.dpkg_status_mtime) > Date.parse(doc.generated)) {
                out.push(alertHtml("info", t("status.changedTitle"), tr("status.changed", { when: fmtDate(doc.generated) })));
            }
            const c = checksOf(doc);
            const old = RADAR_CHECKS.map((k) => c[k]).find((x) => x && x.radar && x.radar.stale && x.radar.generated);
            if (old && status && status.radar === "active") {
                out.push(alertHtml("warning", t("status.radarOldTitle", { age: age(old.radar.generated) }), rich(t("status.radarOld"))));
            }
        }
        $("ug-status").innerHTML = out.join("");
    }

    // --- Header ------------------------------------------------------------
    function renderMeta() {
        const el = $("ug-meta");
        if (!doc) {
            el.textContent = t("meta.never");
            el.removeAttribute("title");
            return;
        }
        const lists = checksOf(doc).lists;
        const last = lists && lists.last_update && lists.last_update.ts;
        el.textContent = t("meta.checked", { ago: ago(doc.generated) }) + (last ? " · " + t("meta.lists", { ago: ago(last) }) : "");
        el.title = t("meta.tip", { when: fmtDate(doc.generated), secs: Math.round((doc.took_ms || 0) / 100) / 10,
                                  who: t(doc.root ? "meta.root" : "meta.user") });
    }

    // --- Overview ----------------------------------------------------------
    function renderSummary() {
        const sec = $("ug-summary");
        if (!doc || doc.pm !== "apt") {
            sec.hidden = true;
            return;
        }
        sec.hidden = false;
        const c = checksOf(doc);
        const u = c.updates;
        let html = "";
        if (u && u.state !== "skipped" && typeof u.count === "number") {
            html = u.count > 0
                ? esc(t("sum.updates", { n: u.count })) + (u.security ? " " + esc(t("sum.updatesSec", { n: u.security })) : "")
                : esc(t("sum.noUpdates"));
            if (u.phased && u.phased.length) html += " " + esc(t("sum.phased", { n: u.phased.length }));
            html = `<span class="ug-line"><span>${html}</span>` +
                   `<button type="button" class="az-btn az-btn--link az-btn--sm" id="ug-open-updates">${icon("external-link-alt")}<span>${esc(t("btn.openUpdates"))}</span></button></span>`;
        }
        $("ug-sum-updates").innerHTML = html;
        const found = CARDS.filter((k) => c[k] && c[k].state === "found");
        $("ug-sum-found").innerHTML = found.length
            ? `<p>${esc(t("sum.found", { n: found.length }))}</p><div class="ug-chips">` +
              found.map((k) => `<button type="button" class="az-btn az-btn--plain az-btn--sm ug-chip" data-go="${k}">` +
                               `<span class="az-label az-label--info">${icon("info-circle")}${esc(t("chk." + k))}</span></button>`).join("") +
              "</div>"
            : `<p>${esc(t("sum.foundNone"))}</p>`;
        renderTimer();
        renderRadar();
    }

    // The network data (stage 2): off until set up from here, like the timer.
    function renderRadar() {
        const el = $("ug-sum-radar");
        const rd = status && status.radar;
        if (!el) return;
        if (!rd) {
            el.innerHTML = "";
            return;
        }
        let text;
        if (status.radar_running) text = t("radar.running");
        else if (rd === "active") text = status.radar_file ? t("radar.on", { ago: ago(status.radar_file) }) : t("radar.onNever");
        else if (rd === "inactive") text = t("radar.off");
        else text = t("radar.missing");
        const btns = [];
        if (isAdmin() && rd === "inactive") {
            btns.push(`<button type="button" class="az-btn az-btn--secondary az-btn--sm" id="ug-radar-setup">${icon("play")}<span>${esc(t("btn.radarSetup"))}</span></button>`);
        } else if (isAdmin() && rd === "active" && !status.radar_running) {
            btns.push(`<button type="button" class="az-btn az-btn--plain az-btn--sm" id="ug-radar-now">${icon("sync-alt")}<span>${esc(t("btn.radarNow"))}</span></button>`);
            btns.push(`<button type="button" class="az-btn az-btn--plain az-btn--sm" id="ug-radar-off">${icon("stop")}<span>${esc(t("btn.switchOff"))}</span></button>`);
        }
        el.innerHTML = `${icon("exchange-alt")}<span>${esc(text)}</span>${btns.join("")}`;
    }

    function renderTimer() {
        const el = $("ug-sum-timer");
        const tm = status && status.timer;
        if (!tm) {
            el.innerHTML = "";
            return;
        }
        let text;
        if (tm === "active") text = status.next ? t("timer.on", { when: fmtDate(status.next) }) : t("timer.onNoNext");
        else if (tm === "inactive") text = t("timer.off");
        else text = t("timer.missing");
        let btn = "";
        if (isAdmin() && tm === "inactive") {
            btn = `<button type="button" class="az-btn az-btn--secondary az-btn--sm" id="ug-timer-setup">${icon("play")}<span>${esc(t("btn.setup"))}</span></button>`;
        } else if (isAdmin() && tm === "active") {
            btn = `<button type="button" class="az-btn az-btn--plain az-btn--sm" id="ug-timer-off">${icon("stop")}<span>${esc(t("btn.switchOff"))}</span></button>`;
        }
        el.innerHTML = `${icon("clock")}<span>${esc(text)}</span>${btn}`;
    }

    // --- Building blocks of a card -----------------------------------------
    // A card opens and closes through its title (a disclosure button). Which cards are closed is
    // kept in this browser only (localStorage), not on the server; a card is open by default.
    const FOLD_KEY = "update-gaps:collapsed";
    const collapsed = (() => {
        try {
            const v = JSON.parse(window.localStorage.getItem(FOLD_KEY) || "[]");
            return new Set(Array.isArray(v) ? v.filter((k) => CARDS.includes(k)) : []);
        } catch (e) {
            return new Set();
        }
    })();
    function saveFolds() {
        try { window.localStorage.setItem(FOLD_KEY, JSON.stringify([...collapsed].sort())); } catch (e) { /* not kept */ }
    }
    function setOpen(check, open) {
        if (open) collapsed.delete(check); else collapsed.add(check);
        saveFolds();
        const btn = document.querySelector(`#ug-card-${check} .ug-toggle`);
        if (btn) btn.setAttribute("aria-expanded", String(open));
        const body = $(`ug-card-${check}-body`);
        if (body) body.hidden = !open;
        const sec = $("ug-card-" + check);
        if (sec) sec.classList.toggle("is-collapsed", !open);
    }

    function card(check, count, inner) {
        const open = !collapsed.has(check);
        return `<section class="az-card ug-card${open ? "" : " is-collapsed"}" id="ug-card-${check}" aria-labelledby="ug-card-${check}-title">` +
               `<div class="az-card__header"><h2 class="az-card__title" id="ug-card-${check}-title">` +
               `<button type="button" class="ug-toggle" data-fold="${check}" aria-expanded="${open}" aria-controls="ug-card-${check}-body">` +
               `<span class="ug-fold">${icon("angle-right")}</span><span>${esc(t("chk." + check))}</span></button></h2>` +
               (count ? `<span class="az-label az-label--info">${esc(count)}</span>` : "") + "</div>" +
               `<div class="az-card__body" id="ug-card-${check}-body"${open ? "" : " hidden"}>${inner}</div></section>`;
    }
    function explain(check, extraTodo) {
        return `<div class="ug-explain"><p><strong>${esc(t("card.why"))}</strong>${rich(t(check + ".why"))}</p>` +
               `<p><strong>${esc(t("card.todo"))}</strong>${rich(t(check + ".todo"))}${extraTodo ? " " + extraTodo : ""}</p></div>`;
    }
    function sourceLine(c) {
        const src = (c.source || []).map(code).join(", ");
        return src ? `<p class="ug-source">${esc(t("card.source"))}: ${src}</p>` : "";
    }
    function table(cols, rows) {
        const head = cols.map((c) => `<th>${esc(t(c))}</th>`).join("");
        // One element per cell: on a phone the cell is a row of label and value.
        const body = rows.map((cells) => "<tr>" + cells.map((cell, i) =>
            `<td data-label="${esc(t(cols[i]))}"${cell.cls ? ` class="${cell.cls}"` : ""}><span class="ug-v">${cell.html}</span></td>`).join("") + "</tr>").join("");
        return `<div class="az-table-wrap"><table class="az-table az-table--stack"><thead><tr>${head}</tr></thead>` +
               `<tbody>${body}</tbody></table></div>`;
    }
    const cell = (html, cls) => ({ html, cls });
    const ver = (v) => cell(v ? esc(v) : "?", "ug-ver");
    function originText(o) {
        if (!o) return "";
        const host = o.host || o.site || "";
        const what = [o.o, o.a || o.n].filter(Boolean).join(", ");
        return esc(host) + (what ? ` <span class="az-cell-sub">${esc(what)}</span>` : "");
    }
    // When the network data of a stage-2 card are old, the card says from when they are.
    function radarNote(c) {
        const r = c.radar || {};
        return r.stale && r.generated ? `<p class="ug-note">${esc(t("status.radarOldTitle", { age: age(r.generated) }))}</p>` : "";
    }
    function pkgList(names, more) {
        return `<span class="ug-pkgs">${(names || []).map(esc).join(", ")}${more ? " " + esc(t("held.more", { n: more })) : ""}</span>`;
    }

    // --- Cards -------------------------------------------------------------
    const RENDER = {
        held(c) {
            const rows = c.findings.map((f) => [
                cell(esc(f.package)),
                ver(f.installed),
                f.candidate
                    ? cell(esc(f.candidate) + (f.newer > 1 ? ` <span class="az-cell-sub">${esc(t("held.more", { n: f.newer - 1 }))}</span>` : "") +
                           (f.security ? ` <span class="az-label az-label--info">${esc(t("held.security"))}</span>` : ""), "ug-ver")
                    : cell(`<span class="az-cell-sub">${esc(t("held.nothingNewer"))}</span>`),
                cell(originText(f.origin)),
                cell(f.installed_at ? esc(fmtDay(f.installed_at.slice(0, 10))) : "?"),
            ]);
            return card("held", t("held.count", { n: c.findings.length }),
                explain("held") + table(["col.package", "col.installed", "col.available", "col.origin", "col.since"], rows) + sourceLine(c));
        },

        pro(c, all) {
            const auto = all.auto;
            const esm = auto && (auto.allowed || []).concat(auto.patterns || []).some((a) => /ESM/i.test(a));
            const rows = c.findings.map((f) => [
                cell(esc(f.package)),
                ver(f.installed),
                ver(f.version),
                cell(esc(f.service || "") + (f.status ? ` <span class="az-cell-sub">${tr("pro.status." + f.status, { service: f.service || "" })}</span>` : "")),
            ]);
            return card("pro", t("pro.count", { n: c.findings.length }),
                explain("pro", esm ? esc(t("pro.todoAuto")) : "") +
                table(["col.package", "col.installed", "col.fix", "col.service"], rows) + sourceLine(c));
        },

        restart(c) {
            const kv = [];
            const k = c.kernel || {};
            if (k.state === 3) kv.push([t("restart.kernel"), tr("restart.kernelNewer", { running: k.running, expected: k.expected })]);
            else if (k.state === 2) kv.push([t("restart.kernel"), tr("restart.kernelAbi", { running: k.running })]);
            if (c.microcode && c.microcode.state === 2) kv.push([t("restart.microcode"), esc(t("restart.microcodeNewer"))]);
            if (c.reboot_required) {
                kv.push([t("restart.flag"), tr("restart.flagBy", { when: fmtDate(c.reboot_required.since),
                                                                   pkgs: (c.reboot_required.packages || []).join(", ") || "?" })]);
            }
            if (c.services && c.services.length) kv.push([t("restart.services"), c.services.map(code).join(" ")]);
            const notes = (c.missing || []).map((m) => `<p class="ug-note">${rich(t("missing." + m))}</p>`).join("");
            return card("restart", t("restart.count"),
                explain("restart") + `<dl class="ug-kv">${kv.map(([a, b]) => `<dt>${esc(a)}</dt><dd>${b}</dd>`).join("")}</dl>` +
                notes + sourceLine(c));
        },

        lists(c) {
            const items = c.findings.map((f) => {
                if (f.kind === "missing") return tr("lists.missing", { site: f.site, release: f.release, entry: f.entry || "?" });
                if (f.kind === "orphaned") return tr("lists.orphaned", { site: f.site, n: f.files });
                if (f.kind === "old") return tr("lists.old", { ago: ago(c.last_update && c.last_update.ts) });
                if (f.kind === "expired") return tr("lists.expired", { file: f.file, when: fmtDate(f.valid_until) });
                if (f.kind === "apt-daily") {
                    const head = f.result && f.result !== "success" ? tr("lists.aptDailyResult", { result: f.result }) : rich(t("lists.aptDaily"));
                    return head + ((f.lines || []).length ? `<pre class="ug-lines">${esc(f.lines.join("\n"))}</pre>` : "");
                }
                return esc(f.kind);
            });
            const last = c.last_update
                ? `<p class="ug-note">${tr("lists.last", { ago: ago(c.last_update.ts), src: t("lists.src." + c.last_update.src) })}</p>` : "";
            return card("lists", t("lists.count", { n: c.findings.length }),
                explain("lists") + `<ul class="ug-plain-list">${items.map((i) => `<li>${i}</li>`).join("")}</ul>` + last + sourceLine(c));
        },

        local(c) {
            const rows = c.findings.map((f) => [cell(esc(f.package)), ver(f.version), cell(esc(f.arch || ""))]);
            const lm = c.findings.some((f) => f.cause === "lists-missing")
                ? alertHtml("warning", t("chk.lists"), rich(t("local.listsMissing"))) : "";
            const more = c.more ? `<p class="ug-note">${esc(t("held.more", { n: c.more }))}</p>` : "";
            return card("local", t("local.count", { n: c.findings.length + (c.more || 0) }),
                explain("local") + lm + table(["col.package", "col.version", "col.arch"], rows) + more + sourceLine(c));
        },

        auto(c) {
            const parts = [];
            c.findings.filter((f) => f.kind === "disabled").forEach((f) => {
                const key = f.what === "not-installed" ? "auto.notInstalled" : f.what === "periodic-off" ? "auto.periodicOff" : "auto.timerOff";
                parts.push(alertHtml("warning", t("chk.auto"), tr(key, { state: f.timer || "" })));
            });
            const sources = c.findings.filter((f) => f.kind === "source");
            if (sources.length) {
                parts.push(`<p class="ug-sub">${esc(t("auto.sourceTitle"))}</p>` +
                    table(["col.origin", "col.packages"], sources.map((f) => [cell(originText(f)), cell(pkgList(f.packages, f.more))])));
            }
            const bl = c.findings.filter((f) => f.kind === "blacklist");
            if (bl.length) {
                parts.push(`<p class="ug-sub">${rich(t("auto.blacklistTitle"))}</p><ul class="ug-plain-list">` +
                    bl.map((f) => "<li>" + (f.invalid ? tr("auto.blacklistInvalid", { pattern: f.pattern })
                        : tr("auto.blacklistLine", { pattern: f.pattern, pkgs: (f.packages || []).join(", ") })) + "</li>").join("") + "</ul>");
            }
            const held = c.findings.find((f) => f.kind === "held");
            if (held) parts.push(`<p class="ug-sub">${esc(t("auto.heldTitle"))}</p><p>${pkgList(held.packages)}</p>`);
            if ((c.allowed || []).length || (c.patterns || []).length) {
                parts.push(`<p class="ug-note">${tr("auto.allowed", { list: (c.allowed || []).concat(c.patterns || []).join(", ") })}</p>`);
            }
            return card("auto", t("auto.count", { n: c.findings.length }), explain("auto") + parts.join("") + sourceLine(c));
        },

        backports(c) {
            const rows = c.findings.map((f) => [cell(esc(f.source)), cell(pkgList(f.packages)), ver(f.installed),
                                                ver(f.backport), cell(esc(f.suite))]);
            const n = c.findings.reduce((s, f) => s + (f.packages || []).length, 0);
            return card("backports", t("backports.count", { n }),
                explain("backports") + table(["col.source", "col.packages", "col.installed", "col.backport", "col.origin"], rows) + sourceLine(c));
        },

        outside(c) {
            let total = 0;
            const dirs = (c.dirs || []).map((d) => {
                const n = (d.files || []).length + (d.more || 0);
                total += n;
                const rows = (d.files || []).map((f) => [
                    cell(esc(f.name)),
                    cell(esc(f.kind === "script" ? t("outside.kind.script", { interp: f.interpreter || "?" })
                        : f.kind === "link" ? t("outside.kind.link", { target: f.target || "?" })
                        : t("outside.kind." + (f.kind === "binary" ? "binary" : "other")))),
                    cell(esc(fmtDay(f.mtime))),
                ]);
                return `<details class="ug-dir"><summary><span class="ug-fold">${icon("angle-right")}</span>${code(d.dir)}` +
                       `<span class="az-label">${esc(t("outside.files", { n }))}</span></summary>` +
                       table(["col.name", "col.kind", "col.changed"], rows) +
                       (d.more ? `<p class="ug-note">${esc(t("held.more", { n: d.more }))}</p>` : "") + "</details>";
            }).join("");
            const hidden = c.hidden
                ? `<p class="ug-note">${tr("outside.hidden", { n: c.hidden, file: c.settings || "/etc/update-gaps.conf",
                                                                paths: (c.hidden_paths || []).join(", ") })}</p>` : "";
            return card("outside", t("outside.count", { n: total }), explain("outside") + `<div>${dirs}</div>` + hidden + sourceLine(c));
        },

        cve(c) {
            const rows = [];
            c.findings.forEach((f) => {
                (f.open || []).forEach((x) => rows.push([
                    cell(esc(x.id) + `<span class="az-cell-sub">${esc(t("cve.page", { id: x.id }))}</span>`),
                    cell(esc(t("cve.prio." + x.priority)) + (x.cvss ? ` <span class="az-cell-sub">${esc(t("cve.cvss", { score: x.cvss }))}</span>` : "")),
                    cell(esc(f.source) + ` <span class="az-cell-sub">${ver(f.installed).html}</span>`),
                    cell(esc(t("cve.status." + (x.status || "needs-fixing"))) +
                         (x.description ? `<span class="az-cell-sub ug-desc">${esc(x.description)}</span>` : "")),
                    cell(esc(fmtDay(x.public))),
                ]));
                (f.fixed_newer || []).forEach((x) => rows.push([
                    cell(esc(x.id) + `<span class="az-cell-sub">${esc(t("cve.page", { id: x.id }))}</span>`),
                    cell(esc(t("cve.prio." + x.priority)) + (x.cvss ? ` <span class="az-cell-sub">${esc(t("cve.cvss", { score: x.cvss }))}</span>` : "")),
                    cell(esc(f.source) + ` <span class="az-cell-sub">${ver(f.installed).html}</span>`),
                    cell(esc(t("cve.fixedIn", { version: x.version })) + `<span class="az-cell-sub">${esc(t(x.pro ? "cve.pro" : x.offered ? "cve.offered" : "cve.notOffered"))}</span>`),
                    cell(esc(fmtDay(x.public))),
                ]));
            });
            return card("cve", t("cve.count", { n: rows.length }),
                explain("cve") + radarNote(c) + table(["col.cve", "col.priority", "col.source", "col.status", "col.published"], rows) +
                `<p class="ug-note">${esc(t("cve.selected", { n: c.selected || 0 }))}</p>` + sourceLine(c));
        },

        upstream(c, all) {
            const openIds = new Set();
            ((all.cve && all.cve.findings) || []).forEach((f) => (f.open || []).forEach((x) => openIds.add(x.id)));
            const rows = c.findings.map((f) => [
                cell(esc(f.repo) + `<span class="az-cell-sub">${pkgList(f.packages)}</span>`),
                ver(f.installed),
                cell(esc(f.newest) + `<span class="az-cell-sub">${esc(fmtDay(f.newest_published))} · ${esc(t("upstream.releases", { n: f.releases }))}</span>`, "ug-ver"),
                cell((f.fixes || []).length
                    ? f.fixes.map((id) => esc(id) + (openIds.has(id) ? ` <span class="az-label az-label--warning">${esc(t("upstream.openInUbuntu"))}</span>` : "")).join(", ") +
                      (f.fixes_more ? " " + esc(t("held.more", { n: f.fixes_more })) : "")
                    : `<span class="az-cell-sub">${esc(t("upstream.noFixes"))}</span>`),
                cell(f.distribution ? esc(t("upstream.distro")) : ""),
            ]);
            return card("upstream", t("upstream.count", { n: c.findings.length }),
                explain("upstream") + radarNote(c) + table(["col.upstream", "col.installed", "col.newest", "col.fixes", "col.origin"], rows) + sourceLine(c));
        },

        newer(c) {
            const rows = c.findings.map((f) => [
                cell(esc(f.source) + `<span class="az-cell-sub">${pkgList(f.packages)}</span>`),
                ver(f.installed),
                cell(f.here ? esc(t("newer.here", { version: f.here.version, pocket: f.here.pocket })) : "", "ug-ver"),
                cell(f.later ? esc(t(f.later.release ? "newer.laterRelease" : "newer.later",
                                     { version: f.later.version, series: f.later.series, release: f.later.release })) : "", "ug-ver"),
            ]);
            const more = c.more ? `<p class="ug-note">${esc(t("held.more", { n: c.more }))}</p>` : "";
            return card("newer", t("newer.count", { n: c.findings.length + (c.more || 0) }),
                explain("newer") + radarNote(c) + table(["col.source", "col.installed", "col.here", "col.later"], rows) + more + sourceLine(c));
        },

        eol(c) {
            const rel = c.release || c.codename || "?";
            const line = c.kind === "ended" ? tr("eol.ended", { release: rel, date: fmtDay(c.standard_until) })
                : tr("eol.soon", { release: rel, date: fmtDay(c.standard_until), days: c.days_left });
            const ext = c.extended_until ? " " + tr("eol.extended", { date: fmtDay(c.extended_until) }) : "";
            return card("eol", fmtDay(c.standard_until), explain("eol") + `<p>${line}${ext}</p>` + sourceLine(c));
        },
    };

    function renderCards() {
        const box = $("ug-cards");
        if (!doc || doc.pm !== "apt") {
            box.innerHTML = "";
            return;
        }
        const c = checksOf(doc);
        box.innerHTML = CARDS.filter((k) => c[k] && c[k].state === "found" && RENDER[k]).map((k) => {
            try {
                return RENDER[k](c[k], c);
            } catch (e) {
                return card(k, "", alertHtml("danger", t("chk." + k), esc(String(e && e.message || e))));
            }
        }).join("");
    }

    // --- No findings / not checked ------------------------------------------
    function cleanDetail(k, c) {
        const parts = [];
        if (k === "updates") parts.push(esc(t("clean.updates")));
        if (k === "lists" && c.last_update) parts.push(esc(t("clean.lists", { ago: ago(c.last_update.ts) })));
        if (k === "eol" && c.standard_until) parts.push(esc(t("eol.supported", { date: fmtDay(c.standard_until) })));
        if (c.state === "partial") {
            parts.push(esc(t("clean.partly", { what: "" })) + (c.missing || []).map((m) => rich(t("missing." + m))).join(" "));
        }
        return parts.length ? ": " + parts.join("; ") : "";
    }

    function renderClean() {
        const sec = $("ug-clean");
        const c = checksOf(doc);
        const items = doc && doc.pm === "apt"
            ? ALL.filter((k) => c[k] && (c[k].state === "none" ||
                                         (c[k].state === "partial" && !(c[k].findings || []).length)))
            : [];
        sec.hidden = !items.length;
        $("ug-clean-list").innerHTML = items.map((k) =>
            `<li><strong>${esc(t("name." + k))}</strong>${cleanDetail(k, c[k])}</li>`).join("");
    }

    function reasonText(c) {
        if (c.state === "timeout") return tr("reason.timeout", { s: c.limit_s || "?" });
        if (c.state === "error" && c.reason === "settings") return tr("reason.settings", { msg: c.error || "" });
        if (c.state === "error") return tr("reason.error", { msg: c.error || "" });
        return tr("reason." + (c.reason || "error"), { tool: c.tool || "", msg: c.error || "" });
    }

    function renderUnchecked() {
        const items = [];
        const c = checksOf(doc);
        if (doc && doc.pm === "apt") {
            ALL.forEach((k) => {
                const x = c[k];
                if (x && (x.state === "skipped" || x.state === "error" || x.state === "timeout")) {
                    items.push(`<li>${esc(t("name." + k))}: ${reasonText(x)}.</li>`);
                }
            });
        }
        const open = monitor
            ? ` <button type="button" class="az-btn az-btn--link az-btn--sm" id="ug-open-monitor">${icon("external-link-alt")}<span>${esc(t("btn.openMonitor"))}</span></button>`
            : "";
        items.push(`<li>${rich(t("unchecked.images"))}${open}</li>`);
        const radarUsed = RADAR_CHECKS.some((k) => c[k] && !(c[k].state === "skipped" && c[k].reason === "radar-off"));
        [radarUsed ? "networkOn" : "network", "other", "places", "applies"].forEach((k) => items.push(`<li>${rich(t("unchecked." + k))}</li>`));
        $("ug-unchecked-list").innerHTML = items.join("");
    }

    function render() {
        renderMeta();
        renderStatus();
        renderSummary();
        renderCards();
        renderClean();
        renderUnchecked();
        $("ug-loading").hidden = !(scanning && !doc) && !(loading && !doc && !loadedOnce);
    }

    // --- Signature -----------------------------------------------------------
    function renderSignature() {
        $("ug-sig-version").textContent = "Update Gaps " + VERSION;
        Promise.resolve().then(() => cockpit.file("/etc/hostname").read())
            .then((text) => {
                const host = String(text || "").trim().split(/\s+/)[0];
                $("ug-sig-host").textContent = host;
                $("ug-sig-host").hidden = !host;
            })
            .catch(() => { /* no host name: the signature shows the product only */ });
    }

    // --- Load and refresh ----------------------------------------------------
    function load() {
        return Promise.all([
            stateFile.read().then((d) => ({ d }), (e) => ({ e })),
            spawn([CTL, "status"], "try").then((out) => JSON.parse(out)).catch(() => null),
            cockpit.file(MONITOR_MANIFEST).read().then((x) => !!x).catch(() => false),
        ]).then(([st, stat, mon]) => {
            loadError = st.e ? String(st.e.message || st.e.problem || st.e) : null;
            doc = st.e ? doc : (st.d && typeof st.d === "object" ? st.d : null);
            status = stat;
            monitor = mon;
        });
    }

    function setBusy(on) {
        const btn = $("ug-refresh");
        btn.disabled = on;
        btn.classList.toggle("is-busy", on);
        btn.setAttribute("aria-busy", on ? "true" : "false");
        btn.querySelector(".ug-btn-label").textContent = t(on ? (scanning ? "btn.checking" : "btn.loading") : "btn.refresh");
        $("ug-cards").classList.toggle("is-busy", on && !!doc);
        $("ug-summary").classList.toggle("is-busy", on && !!doc);
    }

    // Never run two loads at once; a request during a load is queued once.
    let loading = false;
    let pending = false;
    let loadedOnce = false;
    function safeLoad() {
        if (loading) { pending = true; return Promise.resolve(); }
        loading = true;
        setBusy(true);
        return Promise.resolve().then(load).catch((err) => {
            loadError = String((err && err.message) || err);
        }).finally(() => {
            loading = false;
            loadedOnce = true;
            if (pending) { pending = false; return safeLoad(); }
            setBusy(scanning);
            render();
            goToLinkedCard();
            // A fresh install has no state yet: with administrative access, check once.
            if (!doc && !loadError && isAdmin() && !autoScanned) {
                autoScanned = true;
                scan();
            }
        });
    }

    // The status of the add-on (gaps-status.py) links its items as #/<check>, for
    // the Status Board: once the cards are there and the page is shown, scroll to
    // that card, once per link (Cockpit keeps the page loaded and only changes its
    // location; it may change it while the page is still hidden).
    let linkHandled = false;
    if (typeof cockpit.addEventListener === "function") {
        cockpit.addEventListener("locationchanged", () => { linkHandled = false; goToLinkedCard(); });
        cockpit.addEventListener("visibilitychange", goToLinkedCard);
    }
    function goToLinkedCard() {
        if (linkHandled || !doc || cockpit.hidden) return;
        linkHandled = true;
        const first = ((cockpit.location && cockpit.location.path) || [])[0] || "";
        if (!/^[a-z]{1,20}$/.test(first)) return;
        const card = $("ug-card-" + first);
        if (card) {
            setOpen(first, true);
            card.scrollIntoView({ block: "start" });
        }
    }

    // "Refresh": with administrative access a new check through the service,
    // otherwise only the state file again.
    function scan() {
        if (scanning) return;
        if (!isAdmin()) { flash = null; safeLoad(); return; }
        scanning = true;
        setBusy(true);
        render();
        spawn([CTL, "scan"], "require").then(() => {
            flash = null;
        }).catch((ex) => {
            if (isNoAdmin(ex)) flash = { kind: "info", title: "status.noAdminTitle", body: "status.noAdmin" };
            else if (ex && ex.exit_status === 75) flash = { kind: "info", title: "status.busyTitle", body: "status.busy" };
            else flash = { kind: "danger", title: "status.scanFailedTitle", body: "status.scanFailed" };
        }).finally(() => {
            scanning = false;
            safeLoad();
        });
    }

    // Reload only when the state file really changed (new tag), not when our
    // own read() reports the same content again.
    function reloadOnChange(file) {
        let seen = false;
        let lastTag = null;
        file.watch((content, tag) => {
            if (seen && tag === lastTag) return;
            const first = !seen;
            seen = true;
            lastTag = tag;
            if (!first && !scanning) safeLoad();
        });
    }

    // --- Dialog (the regular check) ----------------------------------------------
    const dlg = {
        running: false,
        argv: null,
        open(title, desc, label, argv) {
            this.argv = argv;
            $("ug-dialog-title").textContent = title;
            $("ug-dialog-desc").innerHTML = rich(desc);
            const log = $("ug-dialog-log");
            log.textContent = "";
            log.hidden = true;
            this.result("", null);
            const btn = $("ug-dialog-confirm");
            btn.hidden = false;
            btn.disabled = false;
            btn.classList.remove("is-busy");
            btn.querySelector(".ug-btn-label").textContent = label;
            const cancel = $("ug-dialog-cancel");
            cancel.textContent = t("dialog.cancel");
            cancel.disabled = false;
            const el = $("ug-dialog");
            if (typeof el.showModal === "function") el.showModal(); else el.setAttribute("open", "");
        },
        result(text, ok) {
            const res = $("ug-dialog-result");
            res.innerHTML = text ? (ok === true ? icon("check-circle") : ok === false ? icon("exclamation-circle") : "") + esc(text) : "";
            res.className = "ug-dialog-result" + (ok === true ? " is-ok" : ok === false ? " is-error" : "");
        },
        close() {
            if (this.running) return;
            const el = $("ug-dialog");
            if (typeof el.close === "function") el.close(); else el.removeAttribute("open");
        },
        run() {
            if (this.running || !this.argv) return;
            this.running = true;
            const log = $("ug-dialog-log");
            log.hidden = false;
            const btn = $("ug-dialog-confirm");
            btn.disabled = true;
            btn.classList.add("is-busy");
            btn.querySelector(".ug-btn-label").textContent = t("dialog.running");
            $("ug-dialog-cancel").disabled = true;
            const finish = (text, ok) => {
                this.running = false;
                btn.hidden = true;
                const cancel = $("ug-dialog-cancel");
                cancel.textContent = t("dialog.close");
                cancel.disabled = false;
                this.result(text, ok);
                safeLoad();
            };
            let proc;
            try {
                proc = spawn(this.argv, "require");
            } catch (ex) {
                finish(t("dialog.error", { msg: (ex && ex.message) || String(ex) }), false);
                return;
            }
            proc.stream((text) => { log.textContent += text; log.scrollTop = log.scrollHeight; });
            proc.then(() => finish(t("dialog.success"), true)).catch((ex) => {
                ex = ex || {};
                if (isNoAdmin(ex)) finish(t("dialog.noAdmin"), false);
                else if (typeof ex.exit_status === "number") finish(t("dialog.failed", { code: ex.exit_status }), false);
                else finish(t("dialog.error", { msg: ex.message || ex.problem || String(ex) }), false);
            });
        },
    };

    // --- Init ------------------------------------------------------------------
    applyStaticTexts();
    $("ug-refresh").addEventListener("click", scan);
    document.addEventListener("click", (e) => {
        const target = e.target instanceof Element ? e.target : null;
        const el = target && target.closest("button");
        if (!el) return;
        if (el.id === "ug-open-updates") cockpit.jump("/updates");
        else if (el.id === "ug-open-monitor") cockpit.jump("/image-updates");
        else if (el.id === "ug-timer-setup") dlg.open(t("dlg.install.title"), t("dlg.install.desc"), t("btn.setup"), [CTL, "install", "timer"]);
        else if (el.id === "ug-timer-off") dlg.open(t("dlg.remove.title"), t("dlg.remove.desc"), t("btn.switchOff"), [CTL, "remove", "timer"]);
        else if (el.id === "ug-radar-setup") {
            dlg.open(t("dlg.radar.install.title"), t("dlg.radar.install.desc", { codename: (doc && doc.os && doc.os.codename) || "?" }),
                     t("btn.radarSetup"), [CTL, "install", "radar"]);
        } else if (el.id === "ug-radar-now") dlg.open(t("dlg.radar.now.title"), t("dlg.radar.now.desc"), t("btn.radarNow"), [CTL, "radar"]);
        else if (el.id === "ug-radar-off") dlg.open(t("dlg.radar.remove.title"), t("dlg.radar.remove.desc"), t("btn.switchOff"), [CTL, "remove", "radar"]);
        else if (el.dataset.fold) setOpen(el.dataset.fold, el.getAttribute("aria-expanded") !== "true");
        else if (el.dataset.go) {
            const card = $("ug-card-" + el.dataset.go);
            if (card) {
                setOpen(el.dataset.go, true);
                card.scrollIntoView({ behavior: "smooth", block: "start" });
            }
        }
    });
    $("ug-dialog-confirm").addEventListener("click", () => dlg.run());
    $("ug-dialog-cancel").addEventListener("click", () => dlg.close());
    $("ug-dialog").addEventListener("cancel", (e) => { if (dlg.running) e.preventDefault(); });
    // Cockpit loads this page hidden right after the login, for the status icon in
    // its menu (menu-status.js). What reads or runs on the server, the first check
    // above all, starts only once the page is shown.
    function start() {
        renderSignature();
        reloadOnChange(stateFile);
        safeLoad();
    }
    const menu = window.UpdateGapsMenuStatus;
    if (menu) menu.shown.then(start);
    else start();

    cockpit.transport.wait(function () {});
})();
