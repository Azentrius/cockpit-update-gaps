#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Every font the page can ask the browser for ships with the add-on.

A browser fetches an @font-face file only for a family that a font stack in
use names. So for every font-family the stylesheets set (custom properties
such as --az-font-code resolved, in the order index.html loads the files),
each family that has an @font-face must have its file in plugin/, never in
Cockpit's own static files (`../`): what lies there depends on the Cockpit
package (Ubuntu 24.04's Cockpit 314 has no Red Hat Mono)."""
import os
import re
import sys

PLUGIN = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "plugin")
fails = 0


def check(label, got, want):
    global fails
    ok = got == want
    fails += not ok
    print(("OK   " if ok else "FAIL ") + label + ("" if ok else f"\n     got  {got!r}\n     want {want!r}"))


def read(name):
    with open(os.path.join(PLUGIN, name), encoding="utf-8") as f:
        return f.read()


def stylesheets():
    names = re.findall(r'<link rel="stylesheet" href="([^"?]+)', read("index.html"))
    return [(n, re.sub(r"/\*.*?\*/", "", read(n), flags=re.S)) for n in names]


def families(stack, props, depth=0):
    """The family names of a font stack, var() resolved."""
    out = []
    for part in stack.split(","):
        part = part.strip()
        m = re.fullmatch(r"var\((--[\w-]+)\)", part)
        if m and depth < 10:
            out += families(props.get(m.group(1), ""), props, depth + 1)
        elif part:
            out.append(part.strip("\"'"))
    return out


sheets = stylesheets()
check("the page's stylesheets, in the order index.html loads them", [n for n, _ in sheets], ["azentrius.css", "gaps.css"])
faces, props, stacks = {}, {}, []
for name, css in sheets:
    for body in re.findall(r"@font-face\s*\{([^}]*)\}", css):
        fam = re.search(r"font-family:\s*([^;]+);", body).group(1).strip().strip("\"'")
        for url in re.findall(r'url\("?([^")]+)"?\)', body):
            faces.setdefault(fam, []).append(url)
    rest = re.sub(r"@font-face\s*\{[^}]*\}", "", css)
    for prop, value in re.findall(r"(--font[\w-]*|--az-font[\w-]*)\s*:\s*([^;]+);", rest):
        props[prop] = value.strip()
    stacks += [v.strip() for v in re.findall(r"(?<![\w-])font-family\s*:\s*([^;]+);", rest)]
used = {f for s in stacks for f in families(s, props)}
print("     families in use:", ", ".join(sorted(used)))
missing = sorted((fam, url) for fam in used for url in faces.get(fam, [])
                 if url.startswith("..") or not os.path.isfile(os.path.join(PLUGIN, url)))
check("every @font-face family the page uses has its file in plugin/", missing, [])
check("the add-on's fonts in use", sorted(f for f in used if f in faces), ["DM Sans", "DM Serif Display", "Red Hat Mono"])

print("\nALL CHECKS PASSED" if not fails else f"\n{fails} FAILED")
sys.exit(1 if fails else 0)
