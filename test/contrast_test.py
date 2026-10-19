#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""WCAG contrast of the colour pairs this page uses, in the light and the dark
theme, with the token values from plugin/azentrius.css: text at least 4.5:1,
borders and icons at least 3:1. A pair that gaps.css starts to use goes here.
    python3 contrast_test.py"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(HERE, "..", "plugin", "azentrius.css"), encoding="utf-8") as f:
    css = f.read()


def block(selector):
    m = re.search(re.escape(selector) + r"\s*\{(.*?)\}", css, re.S)
    return dict(re.findall(r"--([\w-]+):\s*(#[0-9a-fA-F]{6})", m.group(1)))


THEMES = {"light": block(":root"), "dark": block(":root.pf-v6-theme-dark")}


def lum(hexcol):
    r, g, b = (int(hexcol[i:i + 2], 16) / 255 for i in (1, 3, 5))

    def ch(c):
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4
    return 0.2126 * ch(r) + 0.7152 * ch(g) + 0.0722 * ch(b)


def ratio(a, b):
    la, lb = sorted((lum(a), lum(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


# (what, foreground token, background tokens, minimum)
PAIRS = [
    ("count and chip label (text + icon)", "on-tint-info", ["tint-info"], 4.5),
    ("neutral label (folder count)", "on-tint-neutral", ["tint-neutral"], 4.5),
    ("code in cards and alerts", "on-tint-neutral", ["tint-neutral"], 4.5),
    ("text in cards", "text", ["bg-card", "bg-hover"], 4.5),
    ("explanation block (why, what to do)", "text", ["bg-page"], 4.5),
    ("subtle text in cards (notes, sub lines, source)", "text-subtle", ["bg-card", "bg-hover"], 4.5),
    ("subtle text on the page (meta in the header)", "text-subtle", ["bg-page"], 4.5),
    ("apt-daily lines", "text", ["bg-page"], 4.5),
    ("link buttons (Software Updates, monitor)", "link", ["bg-card", "bg-hover"], 4.5),
    ("Refresh (primary)", "on-primary", ["primary"], 4.5),
    ("outlined button (Set up): text", "primary-text", ["bg-card", "bg-hover"], 4.5),
    ("outlined button (Set up): border", "primary", ["bg-card", "bg-hover"], 3.0),
    ("plain button (Switch off)", "text-subtle", ["bg-card", "bg-hover"], 3.0),
    ("clock icon", "text-subtle", ["bg-card"], 3.0),
    ("fold arrow of a folder", "text-subtle", ["bg-card"], 3.0),
    ("alert border and icon: info", "status-info", ["bg-card", "bg-page"], 3.0),
    ("alert border and icon: warning", "status-warning", ["bg-card", "bg-page"], 3.0),
    ("alert border and icon: danger", "status-danger", ["bg-card", "bg-page"], 3.0),
    ("dialog text", "text", ["bg-floating"], 4.5),
    ("dialog note", "text-subtle", ["bg-floating"], 4.5),
    ("dialog result ok", "status-success", ["bg-floating"], 4.5),
    ("dialog result error", "danger-text", ["bg-floating"], 4.5),
    ("dialog link (Cancel)", "link", ["bg-floating"], 4.5),
    ("dialog log", "text", ["bg-page"], 4.5),
    ("spinner arc", "text-subtle", ["bg-card"], 3.0),
    ("focus ring", "focus", ["bg-card", "bg-page"], 3.0),
    ("title dot and signature dot", "signature", ["bg-page"], 3.0),
]

bad = 0
for theme, tok in THEMES.items():
    print(f"== {theme}")
    for what, fg, bgs, need in PAIRS:
        for bg in bgs:
            r = ratio(tok[fg], tok[bg])
            ok = r >= need
            bad += not ok
            print(f"{'OK  ' if ok else 'LOW '} {r:5.2f} (>={need})  {what}: {fg} {tok[fg]} on {bg} {tok[bg]}")
print("\nALL PAIRS PASS" if not bad else f"\n{bad} PAIRS TOO LOW")
sys.exit(1 if bad else 0)
