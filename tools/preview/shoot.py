#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Screenshots of the preview in the light and the dark theme, on a desktop
and a phone, e.g. for the README or to check a UI change. The page follows
the browser's colour scheme like Cockpit's "auto" style (azentrius-theme.js).
Needs Playwright with Chromium:

    pip install playwright && python3 -m playwright install chromium
    python3 tools/preview/build.py
    python3 tools/preview/shoot.py [output-dir]      (default: docs/img)

Fails if the page throws a JavaScript error or scrolls horizontally on a
phone-sized screen (any scenario, either theme, also with the dialog open).
"""
import os
import sys

from playwright.sync_api import sync_playwright

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
PAGE = os.path.join(HERE, "out", "update-gaps", "index.html")
OUT = sys.argv[1] if len(sys.argv) > 1 else os.path.join(REPO, "docs", "img")
SCENARIOS = ("noble-held", "resolute-stale-lists", "resolute-nodesource", "resolute-nodesource-user",
             "resolute-nodesource-phased", "noble-held-upkeep", "none")


def main():
    if not os.path.exists(PAGE):
        sys.exit("Build first: python3 tools/preview/build.py")
    os.makedirs(OUT, exist_ok=True)
    errors, widths = [], {}
    with sync_playwright() as p:
        browser = p.chromium.launch()

        def page(width, height, query, scheme="light"):
            pg = browser.new_page(viewport={"width": width, "height": height}, color_scheme=scheme)
            pg.on("pageerror", lambda e: errors.append(f"{query}: {e}"))
            pg.goto(f"file://{PAGE}?{query}")
            pg.wait_for_timeout(600)
            return pg

        def width(pg):
            return pg.evaluate("() => [document.documentElement.scrollWidth, document.documentElement.clientWidth]")

        pg = page(1440, 1000, "scenario=noble-held&lang=en")
        pg.screenshot(path=os.path.join(OUT, "overview.png"))
        pg.screenshot(path=os.path.join(OUT, "overview-full.png"), full_page=True)
        pg = page(1440, 1000, "scenario=noble-held&lang=en", "dark")
        pg.screenshot(path=os.path.join(OUT, "overview-dark.png"))
        pg = page(1440, 1000, "scenario=resolute-stale-lists&lang=en")
        pg.locator("#ug-card-lists").screenshot(path=os.path.join(OUT, "lists.png"))
        # Upkeep gone wrong: the first two cards (dpkg left a kernel half configured, /boot is full).
        pg = page(1440, 1000, "scenario=noble-held-upkeep&lang=en")
        a, b = (pg.locator(f"#ug-card-{k}").bounding_box() for k in ("dpkg", "boot"))
        pg.screenshot(path=os.path.join(OUT, "upkeep.png"), full_page=True,
                      clip={"x": a["x"], "y": a["y"], "width": a["width"], "height": b["y"] + b["height"] - a["y"]})
        pg = page(1440, 900, "scenario=noble-held&lang=en")
        pg.click("#ug-timer-setup")
        pg.wait_for_timeout(300)
        pg.screenshot(path=os.path.join(OUT, "timer-dialog.png"))
        pg.click("#ug-dialog-confirm")
        pg.wait_for_timeout(900)
        pg.screenshot(path=os.path.join(OUT, "timer-done.png"))

        for scheme in ("light", "dark"):
            for sc in SCENARIOS:
                for lang in ("en", "de"):
                    pg = page(390, 1400, f"scenario={sc}&lang={lang}", scheme)
                    widths[f"{sc} {lang} {scheme}"] = width(pg)
                    if sc == "noble-held" and lang == "en":
                        pg.screenshot(path=os.path.join(OUT, f"mobile{'-dark' if scheme == 'dark' else ''}.png"))
        pg = page(390, 844, "scenario=noble-held&lang=de")
        pg.click("#ug-timer-setup")
        pg.wait_for_timeout(300)
        widths["dialog on a phone"] = pg.evaluate("() => { const d = document.getElementById('ug-dialog');"
                                                  " return [d.scrollWidth, d.clientWidth]; }")
        browser.close()

    print("Screenshots:", OUT)
    if errors:
        sys.exit("JavaScript errors: " + "; ".join(errors))
    for what, (scroll, client) in widths.items():
        if scroll > client:
            sys.exit(f"Horizontal scrolling on the phone ({what}): {scroll} > {client}")


if __name__ == "__main__":
    main()
