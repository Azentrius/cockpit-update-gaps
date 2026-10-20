#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""The add-on in a real Cockpit session, on a throw-away machine with systemd
(CI, test workflow, job cockpit; never a machine you use). Playwright drives
Chromium through Cockpit's own login and shell:

  0. Cockpit before the add-on is installed: the errors the browser shows for
     Cockpit itself (on Ubuntu e.g. its */po.js), as the baseline;
  1. this build installed with apt;
  2. as an administrator: the page in Cockpit's menu; with no state yet it
     checks by itself, through update-gaps-scan.service (no network); the
     findings of test/cockpit-setup.sh on the page (the held package, the
     reboot flag); the state file 0644;
  3. "Refresh": a new check, a newer state;
  4. the regular check set up from the page (timer on), then switched off;
  5. a user without administrative access (German browser): the last state,
     the hint, no action;
  6. at the end, no JavaScript error and no failed request of the add-on's
     files or frame, and no error of another kind than the baseline's.

Environment: ADMIN_USER, ADMIN_PW (sudo group), PLAIN_USER, PLAIN_PW, NEW_DEB,
NEW_VERSION, HELD (test/cockpit-setup.sh). Writes screenshots, report.json and
report.md to the folder given; exit 1 if a step failed.
"""
import json
import os
import re
import subprocess
import sys
import time

from playwright.sync_api import sync_playwright

URL = "https://localhost:9090"
E = os.environ
OUT = sys.argv[1] if len(sys.argv) > 1 else "cockpit-session"
FRAME = 'iframe[name$="/update-gaps"]'
STATE = "/var/lib/update-gaps/scan.json"
STATUS = "/var/lib/update-gaps/status.json"
os.makedirs(OUT, exist_ok=True)

report = {"environment": {}, "steps": [], "errors": [], "addon_files": []}
failed = False
errors = []          # [kind, text, url, user, phase]
PHASE = {"now": "baseline"}
OURS = "/update-gaps/"
responses = []
shots = 0
LAST = {"page": None}


def note(name, ok, detail=""):
    global failed
    failed |= not ok
    report["steps"].append({"step": name, "ok": bool(ok), "detail": detail})
    print(("OK   " if ok else "FAIL ") + name + (f" ({detail})" if detail else ""), flush=True)
    return ok


def root(*cmd, check=True):
    p = subprocess.run(["sudo", "env", "DEBIAN_FRONTEND=noninteractive", *cmd], capture_output=True, text=True)
    if check and p.returncode:
        raise RuntimeError(f"{' '.join(cmd)} -> {p.returncode}\n{p.stdout}\n{p.stderr}")
    return p.stdout.strip()


def shot(page, name):
    global shots
    shots += 1
    page.screenshot(path=os.path.join(OUT, f"{shots:02d}-{name}.png"), full_page=True)


def watch(page, who):
    page.on("console", lambda m: m.type == "error" and errors.append(
        ["console", m.text, (m.location or {}).get("url", ""), who, PHASE["now"]]))
    page.on("pageerror", lambda e: errors.append(["pageerror", f"{e.message}\n{e.stack or ''}", "", who, PHASE["now"]]))
    page.on("requestfailed", lambda r: errors.append(["requestfailed", r.failure or "", r.url, who, PHASE["now"]]))

    def response(r):
        if OURS in r.url:
            responses.append([r.url, r.status])
        if r.status >= 400:
            errors.append([f"http {r.status}", "", r.url, who, PHASE["now"]])
    page.on("response", response)


BASELINE = set()


def kind(e):
    return (e[0], e[1] if e[0] != "console" else e[1].split(" because ")[0], e[2] if e[0] != "console" else "")


def poll(page, fn, seconds):
    end = time.monotonic() + seconds
    while True:
        v = fn()
        if v or time.monotonic() > end:
            return v
        page.wait_for_timeout(250)


def login(browser, user, pw, locale="en-US"):
    ctx = browser.new_context(ignore_https_errors=True, locale=locale, viewport={"width": 1440, "height": 1000})
    page = ctx.new_page()
    page.set_default_timeout(90000)
    watch(page, user)
    page.goto(URL + "/", wait_until="domcontentloaded")
    page.fill("#login-user-input", user)
    page.fill("#login-password-input", pw)
    page.click("#login-button")
    LAST["page"] = page
    page.wait_for_selector("iframe, #login-error-message:not(:empty)", state="attached")
    if not page.locator("iframe").count():
        raise RuntimeError(f"login of {user} refused: " + page.locator("#login-error-message").inner_text())
    return ctx, page


def admin_access(page, pw):
    btn = page.get_by_role("button", name=re.compile(r"^(Limited|Administrative) access$"))
    btn.first.wait_for()
    if "Limited" in btn.first.inner_text():
        btn.first.click()
        dlg = page.get_by_role("dialog")
        dlg.locator("input[type=password]").fill(pw)
        dlg.get_by_role("button", name=re.compile("Authenticate")).click()
    page.get_by_role("button", name="Administrative access").wait_for()
    return True


def open_page(page):
    link = page.locator('a[href$="/update-gaps"]').first
    link.wait_for()
    label = link.inner_text().strip()
    link.click()
    frame = page.frame_locator(FRAME)
    frame.locator("#ug-sig-version").wait_for()
    poll(page, lambda: "Update Gaps " in (frame.locator("#ug-sig-version").text_content() or ""), 60)
    return frame, label


def state():
    try:
        return json.loads(root("cat", STATE))
    except (RuntimeError, ValueError):
        return None


def environment(browser):
    env = report["environment"]
    env["system"] = root("sh", "-c", ". /etc/os-release && echo \"$PRETTY_NAME\"") + ", kernel " + root("uname", "-r")
    env["cockpit"] = root("dpkg-query", "-W", "-f", "${Version}", "cockpit-ws")
    env["systemd"] = root("systemctl", "--version").splitlines()[0]
    env["python3"] = root("python3", "--version")
    env["browser"] = f"{browser.browser_type.name} {browser.version}"
    env["this build"] = E["NEW_VERSION"]


def run_dialog(page, frame, opener, seconds):
    opener.click()
    confirm = frame.locator("#ug-dialog-confirm")
    poll(page, lambda: confirm.is_visible() and confirm.is_enabled(), 60)
    title = (frame.locator("#ug-dialog-title").text_content() or "").strip()
    confirm.click()
    text = poll(page, lambda: (frame.locator("#ug-dialog-result").text_content() or "").strip(), seconds)
    ok = "is-ok" in (frame.locator("#ug-dialog-result").get_attribute("class") or "")
    log = frame.locator("#ug-dialog-log").text_content() or ""
    frame.locator("#ug-dialog-cancel").click()
    return title, text, ok, log


def main():
    with sync_playwright() as p:
        browser = p.chromium.launch()
        environment(browser)

        # 0. Cockpit on its own: the baseline of errors that are not the add-on's.
        ctx, page = login(browser, E["ADMIN_USER"], E["ADMIN_PW"])
        admin_access(page, E["ADMIN_PW"])
        page.goto(URL + "/system")
        page.wait_for_selector("iframe", state="attached")
        page.wait_for_timeout(3000)
        BASELINE.update(kind(e) for e in errors)
        note("Cockpit without the add-on: login, administrative access, the shell",
             not page.locator('a[href$="/update-gaps"]').count(), f"{len(BASELINE)} kinds of browser errors from Cockpit itself")
        ctx.close()

        # 1. This build.
        PHASE["now"] = "this build"
        root("apt-get", "install", "-y", "-q", E["NEW_DEB"])
        note("this build installed (apt)",
             root("dpkg-query", "-W", "-f", "${Version}", "cockpit-update-gaps").startswith(E["NEW_VERSION"]),
             root("dpkg-query", "-W", "-f", "${Version}", "cockpit-update-gaps"))
        note("the timer comes with the package, off",
             root("systemctl", "is-enabled", "update-gaps-scan.timer", check=False) == "disabled")

        # 2. As an administrator: the first check by itself.
        ctx, page = login(browser, E["ADMIN_USER"], E["ADMIN_PW"])
        note("administrator: administrative access", admin_access(page, E["ADMIN_PW"]))
        frame, label = open_page(page)
        note("the page in the menu, this build's version",
             label == "Update Gaps" and E["NEW_VERSION"] in (frame.locator("#ug-sig-version").text_content() or ""),
             f"menu '{label}'")
        first = poll(page, lambda: state(), 300)
        poll(page, lambda: frame.locator("#ug-loading").is_hidden() and frame.locator("#ug-summary").is_visible(), 120)
        note("no state yet: the page checked by itself, through the service",
             bool(first) and first.get("root") is True and first.get("format") == 1,
             f"{len((first or {}).get('checks', []))} checks in {(first or {}).get('took_ms')} ms")
        mode = root("stat", "-c", "%a %U", STATE)
        note("the state file: root's, readable by everyone (0644)", mode == "644 root", mode)
        unit = root("systemctl", "show", "update-gaps-scan.service", "-p", "PrivateNetwork", "-p", "Result")
        note("the scan service ran without network and succeeded", "PrivateNetwork=yes" in unit and "Result=success" in unit,
             unit.replace("\n", ", "))
        checks = {c["check"]: c for c in (first or {}).get("checks", [])}
        broken = [f"{k}: {c.get('state')} {c.get('error') or c.get('reason') or ''}" for k, c in checks.items()
                  if c.get("state") in ("error", "timeout")]
        note("every check ran (no error, no time-out) in the real service", not broken, "; ".join(broken)[:400])
        held = frame.locator("#ug-card-held")
        note("the held package of the setup in its card", held.count() == 1 and E["HELD"] in (held.text_content() or ""),
             (held.text_content() or "no card")[:160] if held.count() else "no card")
        restart = frame.locator("#ug-card-restart")
        note("the reboot flag of the setup in its card", restart.count() == 1 and "linux-base" in (restart.text_content() or ""))
        shot(page, "first-check")

        # 2b. The status of the add-on (status contract): the command its manifest names, as a user
        # without sudo, from the file the service wrote.
        mode = root("stat", "-c", "%a %U", STATUS)
        manifest = json.loads(root("cat", "/usr/share/cockpit/update-gaps/manifest.json"))
        verb = manifest.get("azentrius", {}).get("status") or ["false"]
        out = root("runuser", "-u", E["PLAIN_USER"], "--", *verb, "--lang", "de", check=False)
        try:
            st = json.loads(out)
        except ValueError:
            st = {}
        items = {i.get("id"): i.get("state") for i in st.get("items", [])}
        note("the status for the Status Board: written by the service (0644), read without root, in German",
             mode == "644 root" and st.get("schema") == 1 and st.get("version") == E["NEW_VERSION"]
             and items.get("restart") == "warning" and st.get("state") in ("warning", "danger")
             and "Neustart" in json.dumps(st, ensure_ascii=False),
             f"{mode}; {st.get('state')}: {st.get('summary')}; {items}"[:400])

        # 3. Refresh: a new check.
        time.sleep(1.5)
        frame.locator("#ug-refresh").click()
        second = poll(page, lambda: (state() or {}).get("generated") != first.get("generated") and state(), 300)
        poll(page, lambda: frame.locator("#ug-refresh").is_enabled(), 120)
        note("Refresh: a new check, the button usable again", bool(second) and frame.locator("#ug-refresh").is_enabled(),
             f"{first.get('generated')} -> {(second or {}).get('generated')}")

        # 4. The regular check, set up from the page and switched off.
        title, text, ok, log = run_dialog(page, frame, frame.locator("#ug-timer-setup"), 300)
        timer = (root("systemctl", "is-enabled", "update-gaps-scan.timer", check=False),
                 root("systemctl", "is-active", "update-gaps-scan.timer", check=False))
        note("regular check set up from the page: timer on", ok and timer == ("enabled", "active"),
             f"{title} -> {text}; timer {timer}; log {log.strip()[:120]}")
        poll(page, lambda: frame.locator("#ug-timer-off").count() == 1, 60)
        shot(page, "timer-on")
        title, text, ok, log = run_dialog(page, frame, frame.locator("#ug-timer-off"), 120)
        timer = root("systemctl", "is-enabled", "update-gaps-scan.timer", check=False)
        note("regular check switched off from the page", ok and timer == "disabled", f"{title} -> {text}; timer {timer}")

        # 4b. Network data (stage 2), set up from the page: a real fetch from this runner, as the
        # unprivileged radar, then a scan that reads its data.
        before = (state() or {}).get("generated")
        title, text, ok, log = run_dialog(page, frame, frame.locator("#ug-radar-setup"), 600)
        radar_timer = root("systemctl", "is-enabled", "update-gaps-radar.timer", check=False)
        mode = root("stat", "-c", "%a %U", "/var/lib/private/update-gaps-radar/radar.json", check=False)
        unit = root("systemctl", "show", "update-gaps-radar.service", "-p", "DynamicUser", "-p", "Result", check=False)
        note("network data set up from the page: unprivileged radar, data 0644", ok and radar_timer == "enabled"
             and mode.startswith("644 ") and "DynamicUser=yes" in unit and "Result=success" in unit,
             f"{title} -> {text}; timer {radar_timer}; {mode}; {unit.replace(chr(10), ', ')}; log {log.strip()[-160:]}")
        after = poll(page, lambda: (state() or {}).get("generated") != before and state(), 120) or {}
        stage2 = {c["check"]: c for c in after.get("checks", []) if c["check"] in ("cve", "upstream", "newer")}
        good = all(c.get("state") in ("found", "none", "partial") for c in stage2.values()) and len(stage2) == 3
        note("the scan reads the network data: cve, upstream, newer checked",
             good, "; ".join(f"{k} {c.get('state')} {c.get('reason') or ''} {(c.get('radar') or {}).get('service')}"
                             for k, c in stage2.items()))
        poll(page, lambda: frame.locator("#ug-radar-off").count() == 1, 60)
        shot(page, "network-data")
        title, text, ok, log = run_dialog(page, frame, frame.locator("#ug-radar-off"), 120)
        radar_timer = root("systemctl", "is-enabled", "update-gaps-radar.timer", check=False)
        note("network data switched off from the page", ok and radar_timer == "disabled", f"{title} -> {text}; timer {radar_timer}")
        ctx.close()

        # 5. Without administrative access (a user without sudo, German browser).
        ctx, page = login(browser, E["PLAIN_USER"], E["PLAIN_PW"], locale="de-DE")
        frame, label = open_page(page)
        poll(page, lambda: "Anzeige ohne administrativen Zugriff" in (frame.locator("#ug-status").text_content() or ""), 60)
        note("without administrative access: the last state, the hint, no action",
             "Anzeige ohne administrativen Zugriff" in (frame.locator("#ug-status").text_content() or "")
             and frame.locator("#ug-card-held").count() == 1 and frame.locator("#ug-timer-setup").count() == 0,
             (frame.locator("#ug-status").text_content() or "")[:160])
        shot(page, "no-admin")

        # 6. A link of the status (#/restart, as the Status Board jumps) opens the page at its card.
        page.goto(URL + "/update-gaps#/restart")
        frame = page.frame_locator(FRAME)
        frame.locator("#ug-card-restart").wait_for()
        at = poll(page, lambda: frame.locator("#ug-card-restart").evaluate(
            "e => e.getBoundingClientRect().top < 150 || scrollY + innerHeight >= document.documentElement.scrollHeight - 2"), 30)
        note("a link of the status (#/restart) opens the page at its card", bool(at))
        shot(page, "linked-card")
        ctx.close()
        browser.close()


try:
    main()
except Exception as e:      # a step that could not even run counts as failed
    note("the session ran to its end", False, f"{type(e).__name__}: {e}"[:600])
    try:
        LAST["page"] and shot(LAST["page"], "failed")
    except Exception:
        pass

build = [x for x in errors if x[4] == "this build"]
ours = [x for x in build if OURS in x[1] + x[2]]
note("no JavaScript error and no failed request of the add-on's files or frame", not ours,
     "; ".join(f"{k} {u} {t[:120]}" for k, t, u, _, _ in ours)[:600])
other = [x for x in build if x not in ours and kind(x) not in BASELINE]
note("no other error in Cockpit than those it shows without the add-on", not other,
     "; ".join(f"{k} {u} {t[:120]}" for k, t, u, _, _ in other)[:600]
     or f"{len(build)} errors with this build, all of kinds Cockpit shows on its own")
report["errors"] = errors
report["addon_files"] = sorted({u.split(OURS, 1)[1] + f" {s}" for u, s in responses})
with open(os.path.join(OUT, "report.json"), "w") as f:
    json.dump(report, f, indent=2, ensure_ascii=False)
md = ["## Update Gaps in a real Cockpit session", "", "| | |", "|---|---|"]
md += [f"| {k} | {v} |" for k, v in report["environment"].items()]
md += ["", "| Step | Result |", "|---|---|"]
md += [f"| {s['step']} | {'ok' if s['ok'] else 'FAILED'}{': ' + s['detail'] if s['detail'] else ''} |"
       for s in report["steps"]]
md += ["", "Errors Cockpit shows on its own, before the add-on is installed (the baseline): "
       + ("; ".join(sorted({f"{k} {u or t[:80]}" for k, t, u in BASELINE})) or "none")]
with open(os.path.join(OUT, "report.md"), "w") as f:
    f.write("\n".join(md) + "\n")
print("\n".join(md))
sys.exit(1 if failed else 0)
