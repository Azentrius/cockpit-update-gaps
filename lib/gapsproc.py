# SPDX-License-Identifier: Apache-2.0
"""Commands with a time limit, for the helpers of Update Gaps.

Lives in /usr/lib/cockpit-update-gaps next to the scripts that import it
(root-owned). Standard library only, no side effects on import.

Every command runs in a process group of its own, with a fixed PATH that
leaves /usr/local out (software there must never stand in for apt or dpkg),
LC_ALL=C (the parsers read English, untranslated output) and TZ=UTC. The limit is a
deadline for the whole command; when it passes, the group gets SIGTERM, a
moment later SIGKILL, and the process is always waited for. The text handed
to the parsers is cut at MAX_OUTPUT bytes per stream.

run_unprivileged() runs a command without root: as nobody when the caller is
root, with an empty private HOME that is removed afterwards.
"""

import os
import pwd
import shutil
import signal
import subprocess
import tempfile
import time

PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
GRACE = 3              # seconds between SIGTERM and SIGKILL
MAX_OUTPUT = 64 << 20  # bytes kept of stdout and of stderr each


class Result:
    """What a command did: exit code (None when it could not start or was
    stopped), its output as text, and whether it ran out of time."""

    def __init__(self, rc, out="", err="", timeout=False, missing=False):
        self.rc, self.out, self.err = rc, out, err
        self.timeout, self.missing = timeout, missing

    @property
    def ok(self):
        return self.rc == 0 and not self.timeout

    def __repr__(self):
        return f"Result(rc={self.rc!r}, timeout={self.timeout}, missing={self.missing})"


def env(home=None):
    # TZ=UTC: systemctl and journalctl print their times in UTC, so the parsers never guess a
    # zone.
    e = {"PATH": PATH, "LC_ALL": "C", "LANG": "C", "LANGUAGE": "C", "TZ": "UTC", "HOME": "/root",
         "DEBIAN_FRONTEND": "noninteractive"}
    if home:
        e["HOME"] = e["XDG_CACHE_HOME"] = home
    return e


def _stop(proc):
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        proc.wait(timeout=GRACE)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait()


def run(argv, limit, stdin=None, user=None, home=None):
    """Run argv (a list, never a shell string) with a deadline of `limit`
    seconds, as `user` (uid, gid) when given. Returns a Result; never raises
    for a command that is missing, fails or hangs."""
    def drop():
        os.setgroups([])
        os.setgid(user[1])
        os.setuid(user[0])
    try:
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL if stdin is None else subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env(home),
                                start_new_session=True, close_fds=True, preexec_fn=drop if user else None)
    except FileNotFoundError:
        return Result(None, missing=True)
    except (OSError, subprocess.SubprocessError) as e:
        return Result(None, err=str(e))
    deadline = time.monotonic() + limit
    try:
        out, err = proc.communicate(input=stdin, timeout=limit)
    except subprocess.TimeoutExpired:
        _stop(proc)
        try:
            out, err = proc.communicate(timeout=GRACE)
        except (subprocess.TimeoutExpired, ValueError):
            out, err = b"", b""
        return Result(None, _text(out), _text(err), timeout=True)
    except BaseException:
        _stop(proc)
        raise
    if time.monotonic() > deadline:
        return Result(proc.returncode, _text(out), _text(err), timeout=True)
    return Result(proc.returncode, _text(out), _text(err))


def run_unprivileged(argv, limit):
    """argv without root, for tools that write a log or cache of their own.
    `pro` as root always writes /var/log/ubuntu-advantage.log and takes its
    lock in /var/lib/ubuntu-advantage, which the read-only scan service does
    not allow; without root it reads the same public state and logs to
    $XDG_CACHE_HOME. HOME is a fresh directory (in the service's private /tmp)
    that is removed afterwards."""
    user = None
    if os.geteuid() == 0:
        try:
            pw = pwd.getpwnam("nobody")
        except KeyError:
            return Result(None, err="there is no user nobody")
        user = (pw.pw_uid, pw.pw_gid)
    home = tempfile.mkdtemp(prefix="update-gaps-")
    try:
        if user:
            os.chown(home, *user)
        return run(argv, limit, user=user, home=home)
    finally:
        shutil.rmtree(home, ignore_errors=True)


def _text(data):
    if not data:
        return ""
    return data[:MAX_OUTPUT].decode("utf-8", "replace")
