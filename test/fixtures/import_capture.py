#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Turns a capture of test/fixtures/capture.sh into a test scenario.

    python3 test/fixtures/import_capture.py CAPTURE_DIR test/fixtures/<scenario> [--now ISO]

CAPTURE_DIR is the unpacked archive capture.sh wrote on a real host. The
scenario gets the outputs the helpers parse, made anonymous:

- the host name becomes "server" everywhere;
- files under /usr/local/{bin,sbin} and /opt/*/bin get neutral names
  (/opt/app1/bin/tool-1, /usr/local/bin/local-1 …) that keep their kind,
  interpreter, mode and time;
- the installed packages are cut to those that say something (held, without
  a source, from other origins or backports, on the Package-Blacklist of
  unattended-upgrades, with an Ubuntu Pro fix, kernels, a fixed set of well
  known ones, the first 25 others), in dpkg-query and apt-cache policy alike;
- apt-get indextargets keeps only the fields the helpers read.

Credentials in URIs were removed by capture.sh already. Look at the result
before committing it: no secrets, no IP addresses, no real host names.
"""

import argparse
import json
import os
import re
import shutil
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "lib"))
import gapslib as L  # noqa: E402

KEEP = {"unattended-upgrades", "needrestart", "openssh-server", "sudo", "restic", "skopeo", "apt", "dpkg",
        "libc6", "systemd", "openssl", "python3-pip", "python3-wheel", "docker.io", "containerd", "runc",
        "linux-generic", "ubuntu-pro-client", "distro-info-data", "nodejs", "intel-microcode", "amd64-microcode",
        "fwupd", "snapd"}
VULN = "/sys/devices/system/cpu/vulnerabilities"
SNAPD = ("snapd-snaps.json", "snapd-system-info.json", "snapd-changes.json")    # answers of snapd's API
KEEP_PREFIX = ("cockpit", "linux-image-", "docker-", "containerd")
TARGET_FIELDS = ("Site", "Release", "Filename", "Sourcesentry", "Identifier", "Component", "Architecture",
                 "Origin", "Label", "Suite", "Codename", "Target-Of", "Optional")


def read(capture, name):
    p = os.path.join(capture, name)
    if not os.path.exists(p):
        return None
    with open(p, encoding="utf-8", errors="replace") as f:
        return f.read()


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("capture")
    ap.add_argument("scenario")
    ap.add_argument("--now", default="2026-10-19T20:55:00Z")
    args = ap.parse_args(argv)
    cap = args.capture
    host = (read(cap, "hostname.txt") or "").strip()

    def anon(text):
        if text and host:
            text = re.sub(r"\b" + re.escape(host) + r"\b", "server", text)
        return text

    out = args.scenario
    shutil.rmtree(out, ignore_errors=True)
    os.makedirs(os.path.join(out, "commands"))
    meta = {"now": args.now, "uid": 0, "kernel": (read(cap, "uname-r.txt") or "").strip(),
            "files": {}, "dirs": {}, "stat": {}, "heads": {}}

    def put(path, kind="file", mtime=1792400000, mode="644", uid=0, target=None):
        meta["stat"][path] = {"type": kind, "mtime": int(mtime), "mode": mode, "uid": uid,
                              **({"target": target} if target else {})}

    meta["files"]["/etc/os-release"] = read(cap, "os-release")
    put("/etc/os-release")
    put("/usr/bin/apt-get", mode="755")

    # Packages: a subset that keeps every finding. Early captures carried ${source:Version} as
    # the fourth field; the helper's format has five fields.
    dq = "".join(("\t".join(f[:3] + f[4:]) if len(f) == 6 else "\t".join(f)) + "\n"
                 for f in (line.split("\t") for line in (read(cap, "dpkg-query.txt") or "").splitlines()))
    installed = L.parse_dpkg_query(dq)
    pol_text = read(cap, "apt-cache-policy-installed.txt") or ""
    pol = L.parse_policy_packages(pol_text)
    sources = L.parse_policy_sources(read(cap, "apt-cache-policy.txt") or "")
    held = set((read(cap, "apt-mark-showhold.txt") or "").split())
    pro = json.loads(read(cap, "pro.json") or "{}")
    pro_pkgs = {p.get("package") for p in pro.get("packages", [])}
    conf = L.parse_apt_config(read(cap, "apt-config.txt") or "")
    black = [re.compile(p) for p in conf.get("Unattended-Upgrade::Package-Blacklist", [])]
    keep = set()
    for name, p in installed.items():
        if not p["installed"]:
            continue
        base = name.split(":")[0]
        entry = L.installed_entry(pol.get(name) or pol.get(base))
        keys = L.entry_sources(entry)
        rel = [(sources.get(k) or {}).get("release", {}) for k in keys]
        if (name in held or base in KEEP or base in pro_pkgs or base.startswith(KEEP_PREFIX)
                or not keys or any(r.get("o") != "Ubuntu" for r in rel)
                or any(r.get("a", "").endswith("-backports") for r in rel)
                or any(rx.match(base) for rx in black)):
            keep.add(name)
            continue
        pkg = pol.get(name) or pol.get(base) or {}
        if any(L.vercmp(v["version"], pkg.get("installed") or "0") > 0
               and any((sources.get(k) or {}).get("release", {}).get("a", "").endswith("-backports")
                       for k in L.entry_sources(v)) for v in pkg.get("versions", [])):
            keep.add(name)
    others = sorted(n for n, p in installed.items() if p["installed"] and n not in keep)[:25]
    keep.update(others)
    with open(os.path.join(out, "commands", "dpkg-query-W.txt"), "w") as f:
        for line in dq.splitlines():
            if line.split("\t")[0] in keep:
                f.write(line + "\n")
    in_policy = keep | {n.split(":")[0] for n in keep}
    with open(os.path.join(out, "commands", "apt-cache-policy-installed.txt"), "w") as f:
        block, name = [], None
        for line in pol_text.splitlines():
            if line and not line.startswith(" ") and line.endswith(":"):
                if name in in_policy:
                    f.write("\n".join(block) + "\n")
                block, name = [line], line[:-1]
            else:
                block.append(line)
        if name in in_policy:
            f.write("\n".join(block) + "\n")

    for src, dst in (("apt-cache-policy.txt", "apt-cache-policy.txt"),
                     ("apt-mark-showhold.txt", "apt-mark-showhold.txt"),
                     ("apt-get-s-dist-upgrade.txt", "apt-get-s-dist-upgrade.txt"),
                     ("apt-config.txt", "apt-config-dump.txt"),
                     ("pro.json", "pro.json"),
                     ("needrestart.txt", "needrestart.txt"),
                     ("journal-apt-daily.txt", "journalctl-apt-daily.txt")):
        text = read(cap, src)
        if text is not None:
            with open(os.path.join(out, "commands", dst), "w") as f:
                f.write(anon(text))
    show = (read(cap, "systemctl-show.txt") or "").split("\n\n")[0]
    with open(os.path.join(out, "commands", "systemctl-show-apt-daily.txt"), "w") as f:
        f.write("\n".join(ln for ln in show.splitlines() if ln.split("=")[0] in ("Result", "ExecMainExitTimestamp")) + "\n")
    enabled = (read(cap, "systemctl-is-enabled.txt") or "").splitlines()
    with open(os.path.join(out, "commands", "systemctl-is-enabled-apt-daily-upgrade.txt"), "w") as f:
        f.write((enabled[1] if len(enabled) > 1 else "enabled") + "\n")
    for kind in ("indextargets.txt", "indextargets-all.txt"):
        recs = L.parse_deb822(read(cap, kind) or "")
        with open(os.path.join(out, "commands", kind), "w") as f:
            for r in recs:
                f.write("".join(f"{k}: {r[k]}\n" for k in TARGET_FIELDS if k in r) + "\n")

    # apt's lists, stamps, reboot flag, kernels, dpkg log, distro info.
    lists = (read(cap, "lists.txt") or "").split()
    meta["dirs"]["/var/lib/apt/lists"] = lists
    for line in (read(cap, "inrelease.txt") or "").splitlines():
        f = line.split("\t")
        if len(f) < 4:
            continue
        path = "/var/lib/apt/lists/" + f[0]
        meta["files"][path] = f"Date: {f[2]}\n" + (f"Valid-Until: {f[3]}\n" if f[3].strip() else "")
        put(path, mtime=f[1])
    for line in (read(cap, "stamps.txt") or "").splitlines():
        path, _, ts = line.partition("\t")
        put(path, kind="dir" if path.endswith("/partial") else "file", mtime=ts)
    pkgs = read(cap, "reboot-required.pkgs")
    if pkgs is not None:
        meta["files"]["/var/run/reboot-required.pkgs"] = pkgs
        meta["files"]["/var/run/reboot-required"] = "*** System restart required ***\n"
    meta["dirs"]["/boot"] = (read(cap, "boot.txt") or "").split()
    held_log = read(cap, "dpkg-log-held.txt") or ""
    meta["dirs"]["/var/log"] = ["dpkg.log"]
    meta["files"]["/var/log/dpkg.log"] = held_log
    put("/var/log/dpkg.log")
    for c in ("ubuntu", "debian"):
        text = read(cap, f"distro-info-{c}.csv")
        if text is not None:
            meta["files"][f"/usr/share/distro-info/{c}.csv"] = text
            put(f"/usr/share/distro-info/{c}.csv")

    # The machine, the CPU, firmware and snaps (stage 3). UUIDs on the kernel command line go.
    def command(name, text, rc=None):
        with open(os.path.join(out, "commands", name), "w") as f:
            f.write(anon(text))
        if rc is not None:
            with open(os.path.join(out, "commands", os.path.splitext(name)[0] + ".rc"), "w") as f:
                f.write(rc)

    for src, path in (("cpuinfo.txt", "/proc/cpuinfo"), ("cmdline.txt", "/proc/cmdline")):
        text = read(cap, src)
        if text is not None:
            meta["files"][path] = re.sub(r"\b(UUID|PARTUUID)=[0-9A-Fa-f-]+", r"\1=0000", text)
    for sub, base in (("vulnerabilities", VULN), ("dmi", "/sys/class/dmi/id")):
        d = os.path.join(cap, sub)
        if os.path.isdir(d):
            names = sorted(os.listdir(d))
            if sub == "vulnerabilities":
                meta["dirs"][base] = names
            for n in names:
                meta["files"][f"{base}/{n}"] = read(cap, f"{sub}/{n}")
    if read(cap, "systemd-detect-virt.txt") is not None:
        command("systemd-detect-virt.txt", read(cap, "systemd-detect-virt.txt"))
    if read(cap, "snap.txt") is not None:
        meta["dirs"]["/snap"] = (read(cap, "snap.txt") or "").split()
        for n in (read(cap, "snap-current.txt") or "").split():
            put(f"/snap/{n}/current", kind="link", target="1")
        put("/usr/bin/snap", mode="755")
    for src in SNAPD:
        if read(cap, src) is not None:
            command(src, read(cap, src))
    if read(cap, "fwupd-updates.json") is not None:
        command("fwupdmgr-get-updates.txt", read(cap, "fwupd-updates.json"), (read(cap, "fwupd-updates.rc") or "0").strip())
        command("fwupdmgr-get-remotes.txt", read(cap, "fwupd-remotes.json") or "")
        command("systemctl-is-enabled-fwupd-refresh.txt", read(cap, "fwupd-refresh.txt") or "")

    # Software outside the package manager, with neutral names.
    names, opt_dirs = {}, []
    meta["dirs"]["/usr/local/bin"], meta["dirs"]["/usr/local/sbin"] = [], []
    for line in (read(cap, "outside.txt") or "").splitlines():
        f = line.split("\t")
        if len(f) < 7:
            continue
        path, ftype, mtime, mode, magic, first, target = f[:7]
        d, base = os.path.split(path)
        if d.startswith("/opt/"):
            app = d.split("/")[2]
            if app not in names:
                names[app] = f"app{len(names) + 1}"
            nd = f"/opt/{names[app]}/bin"
            if names[app] not in opt_dirs:
                opt_dirs.append(names[app])
        else:
            nd = d
        listing = meta["dirs"].setdefault(nd, [])
        prefix = "tool" if nd.startswith("/opt/") else "local"
        nn = f"{prefix}-{len(listing) + 1}" + (".sh" if base.endswith(".sh") else "")
        listing.append(nn)
        np = f"{nd}/{nn}"
        kind = "link" if ftype == "symbolic link" else "file" if ftype == "regular file" else "other"
        put(np, kind=kind, mtime=mtime, mode=mode, target=target or None)
        if first:
            meta["heads"][np] = first
        elif magic.startswith("7f454c46"):
            meta["heads"][np] = "\x7fELF"
    meta["dirs"]["/opt"] = opt_dirs
    for app in opt_dirs:
        put(f"/opt/{app}/bin", kind="dir", mode="755")
    with open(os.path.join(out, "commands", "dpkg-query-S.txt"), "w") as f:
        f.write("")
    with open(os.path.join(out, "meta.json"), "w") as f:
        json.dump(meta, f, ensure_ascii=False, indent=1, sort_keys=True)
        f.write("\n")
    print(f"{out}: {len(keep)} packages, {len(lists)} list files, "
          f"{sum(len(v) for k, v in meta['dirs'].items() if k.startswith(('/usr/local', '/opt/')))} files outside apt")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
