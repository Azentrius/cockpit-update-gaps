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
    const VERSION = "0.7.0";
    const LIB = "/usr/lib/cockpit-update-gaps/";
    const CTL = LIB + "gaps-ctl.sh";
    const STATE_PATH = "/var/lib/update-gaps/scan.json";
    const MONITOR_MANIFEST = "/usr/share/cockpit/image-updates/manifest.json";
    const FORMAT = 1;          // newest scan.json format this page knows
    const STALE_H = 24;        // a state older than this gets a hint
    const CARDS = ["phased", "dpkg", "boot", "held", "pro", "cve", "upstream", "restart", "cpu", "firmware", "snaps", "lists",
                   "keys", "local", "auto", "uu", "backports", "newer", "outside", "eol"];
    const RADAR_CHECKS = ["cve", "upstream", "newer"];   // stage 2: they read the radar's network data
    // The checks whose findings can be acknowledged (gapslib.FINDING_KEYS), with the list they are in.
    const ACK_CHECKS = ["phased", "dpkg", "boot", "held", "pro", "cpu", "firmware", "snaps", "lists", "keys", "local",
                        "auto", "uu", "backports"];
    const ACK_LIST = { phased: "packages" };
    const ACK_MAX_DAYS = 90;
    const ACK_DEFAULT_DAYS = 30;
    const LABEL_FIELDS = ["package", "name", "snap", "device", "source", "file", "pattern", "site", "remote", "kind"];
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
            const used = RADAR_CHECKS.map((k) => c[k]).filter((x) => x && x.radar && x.state !== "skipped");
            const unknown = used.find((x) => radarAgeUnknown(x.radar));
            const old = used.find((x) => x.radar.stale && radarTime(x.radar));
            if (unknown && status && status.radar === "active") {
                out.push(alertHtml("warning", t("status.radarUnknownTitle"), rich(t("status.radarOld"))));
            } else if (old && status && status.radar === "active") {
                out.push(alertHtml("warning", t("status.radarOldTitle", { age: age(radarTime(old.radar)) }), rich(t("status.radarOld"))));
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
        const acked = found.filter((k) => allAcked(k, c[k]));
        const open = found.filter((k) => !acked.includes(k));
        const chips = (list, cls, ic) => `<div class="ug-chips">` +
            list.map((k) => `<button type="button" class="az-btn az-btn--plain az-btn--sm ug-chip" data-go="${k}">` +
                            `<span class="az-label${cls}">${icon(ic)}${esc(t("chk." + k))}</span></button>`).join("") + "</div>";
        $("ug-sum-found").innerHTML = (open.length
            ? `<p>${esc(t("sum.found", { n: open.length }))}</p>` + chips(open, " az-label--info", "info-circle")
            : `<p>${esc(t(acked.length ? "sum.foundAcked" : "sum.foundNone"))}</p>`) +
            (acked.length ? `<p>${esc(t("sum.acked", { n: acked.length }))}</p>` + chips(acked, "", "check-circle") : "");
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
    function explain(check, extraTodo, whyTitle) {
        return `<div class="ug-explain"><p><strong>${esc(t(whyTitle || "card.why"))}</strong>${rich(t(check + ".why"))}</p>` +
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
    // The time of the network data a stage-2 check used: their last good fetch (data_at), which the
    // radar's own runs do not renew. data_at null: a copy without a known time, and the radar's run
    // is no stand-in for it. A state of 0.4.1 and older has no data_at; its run (generated) stands in.
    function radarTime(r) {
        if (!r) return null;
        return Object.prototype.hasOwnProperty.call(r, "data_at") ? r.data_at || null : r.generated || null;
    }
    function radarAgeUnknown(r) { return !!r && Object.prototype.hasOwnProperty.call(r, "data_at") && !r.data_at; }
    // When the network data of a stage-2 card are old or of unknown age, or their last fetch failed,
    // the card says so.
    function radarNote(c) {
        const r = c.radar || {};
        const when = radarTime(r);
        const out = [];
        if (radarAgeUnknown(r)) out.push(esc(t("radar.ageUnknown")));
        else if (r.stale && when) out.push(esc(t("status.radarOldTitle", { age: age(when) })));
        if (r.service === "error" || r.service === "partial") {
            out.push(when ? tr("radar.lastFailed", { when: fmtDate(when), msg: (r.errors || [])[0] || "?" })
                          : tr("radar.lastFailedUnknown", { msg: (r.errors || [])[0] || "?" }));
        }
        const un = c.unverified || [];
        if (un.length) out.push(tr("radar.unverified", { list: un.join(", ") }));
        return out.map((x) => `<p class="ug-note">${x}</p>`).join("");
    }
    function pkgList(names, more) {
        return `<span class="ug-pkgs">${(names || []).map(esc).join(", ")}${more ? " " + esc(t("held.more", { n: more })) : ""}</span>`;
    }
    // A CPU vulnerability: its common name (when the page knows it) and the kernel's name.
    function vulnName(name) {
        const key = "vuln." + name;
        return I18N.en[key] ? esc(t(key)) + `<span class="az-cell-sub">${code(name)}</span>` : code(name);
    }
    function until(iso) { return iso ? fmtDate(iso) : t("snaps.forever"); }
    // When a scan first saw a finding (`since` in scan.json), once an earlier scan saw it as well.
    function seen(f, inList) {
        const s = f && f.since;
        if (!s || !doc || !(Date.parse(s) < Date.parse(doc.generated))) return "";
        return ` <span class="${inList ? "ug-seen" : "az-cell-sub"}">${esc(t("seen.since", { date: fmtDay(s) }))}</span>`;
    }
    function bytes(n) {
        if (typeof n !== "number" || !isFinite(n)) return "?";
        const gb = n >= 1e9;
        return (gb ? n / 1e9 : n / 1e6).toLocaleString(LOCALE, { maximumFractionDigits: gb ? 1 : 0 }) + (gb ? " GB" : " MB");
    }
    const PKG_RE = /^[a-z0-9][a-z0-9+.:-]*$/;

    // --- Acknowledged findings ------------------------------------------------
    // An administrator can acknowledge a finding until a day (at most 90 days ahead): it then no
    // longer counts for the status (the Status Board, the menu icon), and the page marks it. It counts
    // again once the day has passed (`expired`) or what it was acknowledged for changed (`changed`).
    function isAcked(f) {
        const a = f && f.accepted;
        return !!a && !a.expired && !a.changed;
    }
    function ackList(k, c) {
        return ACK_CHECKS.includes(k) ? (c[ACK_LIST[k] || "findings"] || []).filter((f) => f && typeof f === "object") : [];
    }
    // Every finding of a card acknowledged, and nothing else on it that counts.
    function allAcked(k, c) {
        const list = ackList(k, c);
        if (!list.length || !list.every(isAcked)) return false;
        if (k === "cpu") return !(c.mitigations_off || []).length && !(c.microcode_package && !c.microcode_package.installed);
        return true;
    }
    function labelOf(f) {
        const k = LABEL_FIELDS.find((x) => typeof f[x] === "string" && f[x]);
        return k ? f[k] : "";
    }
    function ack(f, inList) {
        if (!f || !/^[a-z]{2,12}-[0-9a-f]{12}$/.test(String(f.ref || ""))) return "";
        const a = f.accepted;
        const wrap = (html) => (inList ? ` <span class="ug-ack">${html}</span>` : ` <span class="az-cell-sub ug-ack">${html}</span>`);
        const btn = (verb) => (isAdmin()
            ? ` <button type="button" class="az-btn az-btn--link az-btn--sm ug-ack-btn" data-${verb}="${esc(f.ref)}" data-label="${esc(labelOf(f))}">` +
              `${esc(t(verb === "accept" ? "btn.accept" : "btn.unaccept"))}</button>` : "");
        if (isAcked(f)) {
            return wrap(`<span class="ug-ack-mark">${icon("check-circle")}${esc(t("ack.until", { date: fmtDay(a.until) }))}` +
                        `${a.reason ? ": " + esc(a.reason) : ""}</span>` + btn("unaccept"));
        }
        const note = a && a.expired ? t("ack.expired", { date: fmtDay(a.until) }) : a && a.changed ? t("ack.changed") : "";
        return note || isAdmin() ? wrap((note ? `<span class="ug-ack-lapsed">${esc(note)}</span>` : "") + btn("accept")) : "";
    }
    // What a finding carries besides its own text: since when it is seen, its acknowledgement.
    function mark(f, inList) { return seen(f, inList) + ack(f, inList); }
    function utcDay(offsetDays) {
        return new Date(Date.now() + offsetDays * 86400000).toISOString().slice(0, 10);
    }
    // Keyrings the scan could not read (not a finding: apt may read them all the same).
    function keysUnchecked(c, bare) {
        const un = c.unchecked || [];
        if (!un.length) return "";
        const html = rich(t("keys.unchecked", { list: un.map((u) => t("keys.reason." + u.reason, { file: String(u.file || "?").replace(/`/g, "'") })).join(", ") }));
        return bare ? " " + html : `<p class="ug-note">${html}</p>`;
    }

    // Commands for a terminal, to copy (the page itself installs nothing): the command, then what it does.
    function commands(list) {
        return `<ul class="ug-cmds">${list.map(([cmd, html]) => `<li><pre class="ug-lines ug-cmd">${esc(cmd)}</pre><p>${html}</p></li>`).join("")}</ul>`;
    }
    const PHASED_ALWAYS = "APT::Get::Always-Include-Phased-Updates";

    // --- Cards -------------------------------------------------------------
    const RENDER = {
        // Software Updates lists what apt defers and fails on it, the other updates with it: the
        // message it shows, the packages, and the ways around it as commands.
        phased(c, all) {
            const pk = c.packages || [];
            const u = all.updates || {};
            const first = pk[0] || {};
            const id = [first.package || "?"].concat(first.version ? [first.version] : []).join(";") + ";…";
            let fail = tr("phased.fail", { id });
            if (u.count > 0) {
                fail += " " + esc(t("phased.blocks", { n: u.count })) + (u.security ? " " + esc(t("sum.updatesSec", { n: u.security })) : "");
            }
            const rows = pk.map((f) => [
                cell(esc(f.package) + mark(f)),
                ver(f.installed),
                ver(f.version),
                cell(typeof f.percent === "number" ? esc(t("phased.percent", { n: f.percent })) : "?"),
            ]);
            const names = pk.map((f) => f.package).filter((n) => PKG_RE.test(String(n || "")));
            const cmds = [["sudo apt-get upgrade", rich(t("phased.cmdUpgrade"))]];
            if (names.length) cmds.push(["sudo apt-get install --only-upgrade " + names.join(" "), rich(t("phased.cmdOnly"))]);
            let setting = "";
            if (c.include === "always") setting = tr("phased.always", { key: c.setting || PHASED_ALWAYS });
            else if (c.include === "never") setting = tr("phased.never", { key: c.setting || "APT::Get::Never-Include-Phased-Updates" });
            else cmds.push([`echo '${PHASED_ALWAYS} "true";' | sudo tee /etc/apt/apt.conf.d/99-phased-updates`, rich(t("phased.cmdAlways"))]);
            const more = c.more ? `<p class="ug-note">${esc(t("held.more", { n: c.more }))}</p>` : "";
            return card("phased", t("phased.count", { n: pk.length + (c.more || 0) }),
                explain("phased", "", "card.whyFails") + alertHtml("warning", t("phased.failTitle"), fail) +
                table(["col.package", "col.installed", "col.deferred", "col.rollout"], rows) + more +
                `<p class="ug-sub">${esc(t("phased.cmdTitle"))}</p>` + commands(cmds) +
                (setting ? `<p class="ug-note">${setting}</p>` : "") + sourceLine(c));
        },

        // dpkg left packages half done or its run was interrupted: every further update fails.
        dpkg(c) {
            const parts = [];
            const stopped = c.findings.find((f) => f.kind === "interrupted");
            if (stopped) parts.push(alertHtml("warning", t("dpkg.interruptedTitle"), rich(t("dpkg.interrupted")) + mark(stopped, true)));
            const pk = c.findings.filter((f) => f.kind === "package");
            if (pk.length) {
                parts.push(table(["col.package", "col.version", "col.state"], pk.map((f) => [
                    cell(esc(f.package) + mark(f)), ver(f.version), cell(esc(t("dpkg.state." + f.state))),
                ])));
            }
            if (c.more) parts.push(`<p class="ug-note">${esc(t("held.more", { n: c.more }))}</p>`);
            const cmds = [["sudo dpkg --configure -a", rich(t("dpkg.cmdConfigure"))], ["sudo apt-get -f install", rich(t("dpkg.cmdFix"))]];
            const broken = pk.filter((f) => f.state === "reinst-required" && PKG_RE.test(String(f.package || ""))).map((f) => f.package);
            if (broken.length) cmds.push(["sudo apt-get install --reinstall " + broken.join(" "), rich(t("dpkg.cmdReinstall"))]);
            const n = pk.length + (c.more || 0);
            return card("dpkg", n ? t("dpkg.count", { n }) : t("dpkg.interruptedLabel"),
                explain("dpkg", "", "card.whyFails") + parts.join("") +
                `<p class="ug-sub">${esc(t("card.cmdTitle"))}</p>` + commands(cmds) + sourceLine(c));
        },

        // /boot cannot take the next kernel, or keeps kernels apt no longer needs.
        boot(c) {
            const parts = [];
            const sp = c.findings.find((f) => f.kind === "space");
            if (sp) parts.push(alertHtml("warning", t("boot.spaceTitle"), tr("boot.space", { free: bytes(sp.free), need: bytes(sp.need) }) + mark(sp, true)));
            const old = c.findings.find((f) => f.kind === "old-kernels");
            if (old) parts.push(`<p>${tr("boot.old", { list: (old.kernels || []).join(", ") })}${mark(old, true)}</p>`);
            const k = c.kernels || [];
            if (k.length) {
                parts.push(`<p class="ug-note">${tr("boot.line", { n: k.length, running: c.running || "?", free: bytes(c.free), size: bytes(c.size) })}</p>`);
            }
            const label = sp ? t("boot.countFree", { free: bytes(sp.free) }) : old ? t("boot.countOld", { n: (old.kernels || []).length }) : "";
            return card("boot", label, explain("boot", "", "card.whyFails") + parts.join("") +
                `<p class="ug-sub">${esc(t("card.cmdTitle"))}</p>` +
                commands([["sudo apt autoremove --purge", rich(t("boot.cmdAutoremove"))]]) + sourceLine(c));
        },

        held(c) {
            const rows = c.findings.map((f) => [
                cell(esc(f.package) + mark(f)),
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
                cell(esc(f.package) + mark(f)),
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

        cpu(c) {
            const parts = [];
            const off = c.mitigations_off || [];
            if (off.length) parts.push(alertHtml("warning", t("cpu.offTitle"), tr("cpu.off", { words: off.join(" ") })));
            const pkg = c.microcode_package;
            if (pkg && !pkg.installed) {
                const debian = ((doc && doc.os && doc.os.id) || "") === "debian";
                const key = pkg.available === false ? (debian ? "cpu.pkgDebian" : "cpu.pkgNone") : "cpu.pkgMissing";
                parts.push(alertHtml("warning", t("cpu.pkgTitle", { name: pkg.name }), tr(key, { name: pkg.name })));
            }
            if ((c.findings || []).length) {
                parts.push(table(["col.vulnerability", "col.kernel", "col.fixBy"], c.findings.map((f) => [
                    cell(vulnName(f.name) + mark(f)),
                    cell(esc(f.text)),
                    cell(esc(t(f.fix === "provider" ? "cpu.fix.provider" : "cpu.fix.here"))),
                ])));
            }
            const cpu = c.cpu || {};
            const fw = c.firmware || {};
            const lines = [];
            if (cpu.model) lines.push(tr("cpu.cpuLine", { model: cpu.model, n: cpu.threads || "?", rev: (cpu.revisions || []).join(", ") || "?" }));
            if (c.machine === "vm") lines.push(tr("cpu.vm", { virt: c.virt || "?" }));
            else if (c.machine === "metal") {
                lines.push(tr("cpu.metal", { board: [fw.board_vendor, fw.board_name].filter(Boolean).join(" ") || fw.sys_vendor || "?",
                                             bios: fw.bios_version || "?", date: fw.bios_date ? fmtDay(fw.bios_date) : "?",
                                             pkg: (pkg && pkg.name) || "intel-microcode / amd64-microcode" }));
            }
            if (c.microcode_pending) lines.push(rich(t("cpu.pending")));
            lines.push(esc(t("cpu.counts", { m: c.mitigated || 0, n: c.not_affected || 0 })));
            const extra = c.machine === "vm" ? esc(t("cpu.todoVm")) : c.machine === "metal" ? rich(t("cpu.todoMetal")) : "";
            return card("cpu", (c.findings || []).length ? t("cpu.count", { n: c.findings.length }) : "",
                explain("cpu", extra) + parts.join("") + lines.map((l) => `<p class="ug-note">${l}</p>`).join("") + sourceLine(c));
        },

        firmware(c) {
            const ups = (c.findings || []).filter((f) => f.kind === "update");
            const parts = [];
            if (ups.length) {
                parts.push(table(["col.device", "col.installed", "col.available", "col.urgency", "col.fixes"], ups.map((f) => [
                    cell(esc(f.device) + (f.vendor ? `<span class="az-cell-sub">${esc(f.vendor)}</span>` : "")),
                    ver(f.version),
                    ver(f.new),
                    cell(f.urgency ? esc(t("firmware.urgency." + f.urgency)) : `<span class="az-cell-sub">${esc(t("firmware.urgency.none"))}</span>`),
                    cell((f.issues || []).length ? f.issues.map(esc).join(", ") : `<span class="az-cell-sub">${esc(t("upstream.noFixes"))}</span>`),
                ])));
            }
            const other = (c.findings || []).filter((f) => f.kind !== "update").map((f) => {
                if (f.kind === "metadata-old") return tr("firmware.metadataOld", { remote: f.remote, n: f.days });
                if (f.kind === "refresh-off") return tr("firmware.refreshOff", { state: f.timer });
                if (f.kind === "no-remote") return rich(t("firmware.noRemote"));
                return esc(f.kind);
            }).map((line, i) => line + mark((c.findings || []).filter((f) => f.kind !== "update")[i], true));
            if (other.length) parts.push(`<ul class="ug-plain-list">${other.map((i) => `<li>${i}</li>`).join("")}</ul>`);
            return card("firmware", ups.length ? t("firmware.count", { n: ups.length }) : "", explain("firmware") + parts.join("") + sourceLine(c));
        },

        snaps(c) {
            const items = (c.findings || []).map((f) => {
                if (f.kind === "held") return tr("snaps.held", { snap: f.snap, until: until(f.until) });
                if (f.kind === "refresh-held") return tr("snaps.allHeld", { until: until(f.until) });
                if (f.kind === "inhibited") return tr("snaps.inhibited", { snap: f.snap, until: f.until ? fmtDate(f.until) : "?" });
                if (f.kind === "old-base") {
                    return tr("snaps.oldBase", { snap: f.snap, base: f.base, release: f.release, date: fmtDay(f.ended) }) +
                           (f.esm_until ? " " + tr("snaps.esm", { date: fmtDay(f.esm_until) }) : "");
                }
                if (f.kind === "refresh-failed") {
                    return tr("snaps.failed", { when: fmtDate(f.when), summary: f.summary, id: f.id }) +
                           (f.error ? `<pre class="ug-lines">${esc(f.error)}</pre>` : "");
                }
                return esc(f.kind);
            }).map((line, i) => line + mark(c.findings[i], true));
            return card("snaps", t("snaps.count", { n: items.length }),
                explain("snaps") + `<ul class="ug-plain-list">${items.map((i) => `<li>${i}</li>`).join("")}</ul>` +
                `<p class="ug-note">${esc(t("snaps.installed", { n: c.installed || 0 }))}</p>` + sourceLine(c));
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
            }).map((line, i) => line + mark(c.findings[i], true));
            const last = c.last_update
                ? `<p class="ug-note">${tr("lists.last", { ago: ago(c.last_update.ts), src: t("lists.src." + c.last_update.src) })}</p>` : "";
            return card("lists", t("lists.count", { n: c.findings.length }),
                explain("lists") + `<ul class="ug-plain-list">${items.map((i) => `<li>${i}</li>`).join("")}</ul>` + last + sourceLine(c));
        },

        // The keys apt checks the sources with: expired, about to expire, or their file is gone.
        keys(c) {
            const rows = c.findings.map((f) => [
                cell(code(f.file) + mark(f) + (f.inline ? `<span class="az-cell-sub">${esc(t("keys.inline"))}</span>` : "") +
                     (f.default ? `<span class="az-cell-sub">${esc(t("keys.default"))}</span>` : "")),
                cell(pkgList(f.sources)),
                cell(f.kind === "missing" ? esc(t("keys.missing"))
                    : f.kind === "expired" ? `<span class="az-label az-label--warning">${esc(t("keys.expired", { date: fmtDay(f.expires) }))}</span>`
                    : esc(t("keys.expires", { date: fmtDay(f.expires), n: f.days }))),
            ]);
            return card("keys", t("keys.count", { n: c.findings.length }),
                explain("keys") + table(["col.keyring", "col.sources", "col.expires"], rows) + keysUnchecked(c) + sourceLine(c));
        },

        local(c) {
            const rows = c.findings.map((f) => [cell(esc(f.package) + mark(f)), ver(f.version), cell(esc(f.arch || ""))]);
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
                parts.push(alertHtml("warning", t("chk.auto"), tr(key, { state: f.timer || "" }) + mark(f, true)));
            });
            const sources = c.findings.filter((f) => f.kind === "source");
            if (sources.length) {
                parts.push(`<p class="ug-sub">${esc(t("auto.sourceTitle"))}</p>` +
                    table(["col.origin", "col.packages"], sources.map((f) => [cell(originText(f) + mark(f)), cell(pkgList(f.packages, f.more))])));
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

        // What the last run of unattended-upgrades did (its configuration is the card "auto").
        uu(c) {
            const items = c.findings.map((f) => {
                let line;
                if (f.kind === "never") line = rich(t(f.log ? "uu.never" : "uu.noLog"));
                else if (f.kind === "old") line = tr("uu.old", { ago: ago(c.last_run) });
                else if (f.kind === "failed") {
                    line = tr("uu.failed", { when: fmtDate(c.last_run) }) +
                           ((f.lines || []).length ? `<pre class="ug-lines">${esc(f.lines.join("\n"))}</pre>` : "");
                } else if (f.kind === "kept-back") line = tr("uu.keptBack", { pkgs: (f.packages || []).join(", ") });
                else if (f.kind === "conffile") line = tr("uu.conffile", { pkgs: (f.packages || []).join(", ") });
                else if (f.kind === "service") line = tr("uu.service", { result: f.result });
                else line = esc(f.kind);
                return line + mark(f, true);
            });
            const last = c.last_run && c.outcome
                ? `<p class="ug-note">${esc(t("uu.last", { ago: ago(c.last_run), outcome: t("uu.outcome." + c.outcome) }))}</p>` : "";
            return card("uu", t("uu.count", { n: items.length }),
                explain("uu") + `<ul class="ug-plain-list">${items.map((i) => `<li>${i}</li>`).join("")}</ul>` + last + sourceLine(c));
        },

        backports(c) {
            const rows = c.findings.map((f) => [cell(esc(f.source) + mark(f)), cell(pkgList(f.packages)), ver(f.installed),
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
        if (k === "phased" && c.state === "none") {
            parts.push(c.include === "always" ? tr("clean.phasedAlways", { key: c.setting || PHASED_ALWAYS })
                : c.include === "never" ? tr("clean.phasedNever", { key: c.setting || "APT::Get::Never-Include-Phased-Updates" })
                : esc(t("clean.phased")));
        }
        if (k === "lists" && c.last_update) parts.push(esc(t("clean.lists", { ago: ago(c.last_update.ts) })));
        if (k === "eol" && c.standard_until) parts.push(esc(t("eol.supported", { date: fmtDay(c.standard_until) })));
        if (k === "cpu" && c.state === "none") parts.push(esc(t("clean.cpu", { m: c.mitigated || 0, n: c.not_affected || 0 })));
        if (k === "firmware" && c.state === "none") parts.push(esc(t("clean.firmware")));
        if (k === "snaps" && c.state === "none" && !c.installed) parts.push(esc(t(c.snapd ? "clean.snapsNone" : "clean.snapdNone")));
        if (k === "dpkg" && c.state === "none") parts.push(esc(t("clean.dpkg")));
        if (k === "boot" && typeof c.free === "number") parts.push(esc(t("clean.boot", { free: bytes(c.free) })));
        if (k === "keys" && (c.keyrings || []).length) parts.push(esc(t("clean.keys", { n: c.keyrings.length })));
        if (k === "uu" && c.last_run && c.outcome) parts.push(esc(t("clean.uu", { ago: ago(c.last_run), outcome: t("uu.outcome." + c.outcome) })));
        if (c.state === "partial") {
            parts.push(esc(t("clean.partly", { what: "" })) + (c.missing || []).map((m) => rich(t("missing." + m))).join(" ") +
                       (k === "keys" ? keysUnchecked(c, true) : ""));
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
        if (c.state === "error" && ["settings", "radar", "radar-fetch"].includes(c.reason)) {
            return tr("reason." + c.reason, { msg: c.error || "" });
        }
        if (c.state === "error") return tr("reason.error", { msg: c.error || "" });
        if (c.check === "firmware" && c.reason === "tool-missing" && c.tool === "fwupd") {
            return rich(t(c.machine === "vm" ? "reason.fwupd-vm" : "reason.fwupd"));
        }
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
        ackRef: null,
        open(title, desc, label, argv, ackRef) {
            this.argv = argv;
            this.ackRef = ackRef || null;
            $("ug-dialog-title").textContent = title;
            $("ug-dialog-desc").innerHTML = rich(desc);
            const form = $("ug-dialog-form");
            form.hidden = !this.ackRef;
            if (this.ackRef) {
                const until = $("ug-ack-until");
                until.min = utcDay(0);
                until.max = utcDay(ACK_MAX_DAYS);
                until.value = utcDay(ACK_DEFAULT_DAYS);
                until.disabled = false;
                $("ug-ack-reason").value = "";
                $("ug-ack-reason").disabled = false;
            }
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
            let argv = this.argv;
            let input = null;
            if (this.ackRef) {
                const day = $("ug-ack-until").value;
                if (!/^\d{4}-\d\d-\d\d$/.test(day) || day < utcDay(0) || day > utcDay(ACK_MAX_DAYS)) {
                    this.result(t("ack.badDay", { n: ACK_MAX_DAYS }), false);
                    return;
                }
                argv = [CTL, "accept", this.ackRef, day];
                input = $("ug-ack-reason").value.slice(0, 200);
                $("ug-ack-until").disabled = true;
                $("ug-ack-reason").disabled = true;
            }
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
                proc = spawn(argv, "require");
                if (input !== null) proc.input(input);
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
        else if (el.dataset.accept) {
            const label = String(el.dataset.label || el.dataset.accept).replace(/`/g, "'");
            dlg.open(t("dlg.accept.title"), t("dlg.accept.desc", { label, n: ACK_MAX_DAYS }), t("btn.accept"), [CTL, "accept"], el.dataset.accept);
        } else if (el.dataset.unaccept) {
            const label = String(el.dataset.label || el.dataset.unaccept).replace(/`/g, "'");
            dlg.open(t("dlg.unaccept.title"), t("dlg.unaccept.desc", { label }), t("btn.unaccept"), [CTL, "unaccept", el.dataset.unaccept]);
        } else if (el.dataset.fold) setOpen(el.dataset.fold, el.getAttribute("aria-expanded") !== "true");
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
