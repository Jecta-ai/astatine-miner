#!/usr/bin/env python3
"""Exercise the real Astatine application across actual loopback SSH sessions.

This qualification harness is intentionally test-only. It creates a randomized
disposable Linux account, a loopback-only sshd with public-key authentication,
and a private persistent D-Bus session plus an unlocked GNOME Keyring Secret
Service owned by that account. It then drives the production executable over
real SSH connections:

  A. PTY: production `init` creates a synthetic wallet, journal, and checkpoint.
  B. PTY: production `init` pauses at a prompt; resize the local PTY, verify
     local PTY dimensions and application responsiveness (not remote size
     propagation), then SIGKILL the local SSH client.
  C. No PTY: run production `recover` twice and require authentication success.
  D. No PTY: point the session at an unavailable Secret Service socket and
     require fail-closed behavior with unchanged journal bytes.

It never logs a recovery phrase, wallet password, keyring password, private key,
or Secret Service secret. The wallet is disposable and receives no funds. Only
the local loopback sshd is contacted; no public RPC, release, signing, or paid
mining operation is performed.

Usage:
    python3 support/linux/ssh-application-lifecycle.py target/debug/astatine

This refuses to run outside Linux. It also refuses to create a disposable system
account unless RUNNER_ENVIRONMENT=github-hosted or
ASTATINE_ALLOW_SSH_LIFECYCLE=1 is set. GITHUB_ACTIONS=true alone is not enough.
The caller must be non-root and have passwordless sudo.
"""

from __future__ import annotations

import errno
import fcntl
import hashlib
import os
import pty
import pwd
import re
import secrets
import select
import shlex
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import termios
import time
from dataclasses import dataclass
from pathlib import Path


# Exact production arguments required for the lifecycle evidence.
INIT_ARGS = [
    "init",
    "--network",
    "testnet",
    "--threads",
    "1",
    "--minimum-reserve-inj",
    "1",
    "--spending-limit-inj",
    "0.1",
    "--per-run-sessions",
    "--rpc",
    "default",
    "--confirmation-blocks",
    "1",
]

# Bound each interactive stage. The test is deliberately bounded so a stuck
# prompt cannot leave a disposable account and sshd behind indefinitely.
PROMPT_TIMEOUT = 90.0
EXIT_TIMEOUT = 180.0
DISCONNECT_EXIT_WAIT = 5.0


class HarnessError(Exception):
    """A controlled qualification failure with a safe diagnostic string."""


class HarnessCancelled(Exception):
    """Raised cooperatively after a cancellation signal is recorded."""

    def __init__(self, signum: int):
        super().__init__(signum)
        self.signum = signum


@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    uid: int
    starttime: int
    marker: str


_SIGNAL_REQUESTED: int | None = None
_CLEANUP_IN_PROGRESS = False


# Run as root through sudo. Every signal to a tracked daemon or enumerated user
# process is sent through a pidfd after checking its uid, start time, and
# command marker. Launcher descendants use a dedicated process group whose
# unreaped direct-child leader pins the group ID during cleanup.
_PIDFD_HELPER = r'''
import errno
import os
import select
import signal
import sys


def snapshot(pid):
    try:
        raw_stat = open(f"/proc/{pid}/stat", "rb").read()
        close = raw_stat.rfind(b")")
        if close < 0:
            return None
        fields = raw_stat[close + 2 :].split()
        if len(fields) <= 19:
            return None
        state = fields[0].decode("ascii", "strict")
        pgrp = int(fields[2])
        session = int(fields[3])
        starttime = int(fields[19])
        uid_values = None
        with open(f"/proc/{pid}/status", "rt", encoding="ascii") as source:
            for line in source:
                if line.startswith("Uid:"):
                    uid_values = tuple(int(value) for value in line.split()[1:5])
                    break
        if uid_values is None or len(uid_values) != 4:
            return None
        cmdline = open(f"/proc/{pid}/cmdline", "rb").read()
        return state, starttime, pgrp, session, uid_values, cmdline
    except (OSError, ValueError, UnicodeError, IndexError):
        return None


def pidfd_pid(fd):
    try:
        with open(f"/proc/self/fdinfo/{fd}", "rt", encoding="ascii") as source:
            for line in source:
                if line.startswith("Pid:"):
                    return int(line.split()[1])
    except (OSError, ValueError, IndexError):
        return None
    return None


def pin(pid):
    # Acquire the pidfd first. It pins the task_struct/PID identity so a later
    # /proc snapshot cannot silently describe a replacement that reused the
    # numeric PID after an earlier name or UID check.
    try:
        fd = os.pidfd_open(pid, 0)
    except ProcessLookupError:
        return None, None
    except OSError as error:
        if error.errno in (errno.ESRCH, errno.ENOENT):
            return None, None
        raise
    info = snapshot(pid)
    if info is None or pidfd_pid(fd) != pid:
        os.close(fd)
        return None, None
    return fd, info


def wait_exited(fd, milliseconds):
    poller = select.poll()
    poller.register(fd, select.POLLIN | select.POLLHUP | select.POLLERR)
    return bool(poller.poll(milliseconds))


action = sys.argv[1]
if action == "capture":
    pid = int(sys.argv[2])
    uid = int(sys.argv[3])
    marker = os.fsencode(sys.argv[4])
    fd, info = pin(pid)
    if fd is None:
        sys.exit(2)
    try:
        if info[4][1] != uid or info[4][3] != uid or marker not in info[5]:
            sys.exit(3)
        if info[0] in ("Z", "X", "x"):
            sys.exit(2)
        print(info[1])
    finally:
        os.close(fd)
elif action in ("state", "stop"):
    pid = int(sys.argv[2])
    if action == "stop":
        signum = int(sys.argv[3])
        uid = int(sys.argv[4])
        starttime = int(sys.argv[5])
        marker = os.fsencode(sys.argv[6])
    else:
        uid = int(sys.argv[3])
        starttime = int(sys.argv[4])
        marker = os.fsencode(sys.argv[5])
    fd, info = pin(pid)
    if fd is None:
        sys.exit(2)
    try:
        if info[1] != starttime:
            sys.exit(2)
        if info[4][1] != uid or info[4][3] != uid or marker not in info[5]:
            sys.exit(3)
        if info[0] in ("Z", "X", "x"):
            if action == "state":
                print(info[0])
            sys.exit(0)
        if action == "state":
            print(info[0])
            sys.exit(0)
        try:
            signal.pidfd_send_signal(fd, signum)
        except ProcessLookupError:
            sys.exit(0)
        if wait_exited(fd, 5000):
            sys.exit(0)
        try:
            signal.pidfd_send_signal(fd, signal.SIGKILL)
        except ProcessLookupError:
            sys.exit(0)
        if wait_exited(fd, 5000):
            sys.exit(0)
        sys.exit(4)
    finally:
        os.close(fd)
elif action == "kill-uid":
    uid = int(sys.argv[2])
    failed = False
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        pid = int(name)
        fd, info = pin(pid)
        if fd is None:
            continue
        try:
            if info[4] != (uid, uid, uid, uid):
                continue
            if info[0] in ("Z", "X", "x"):
                continue
            try:
                signal.pidfd_send_signal(fd, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except OSError:
                failed = True
        finally:
            os.close(fd)
    if failed:
        sys.exit(4)
elif action == "group-signal":
    pgid = int(sys.argv[2])
    signum = int(sys.argv[3])
    leader = snapshot(pgid)
    if leader is None or leader[2] != pgid or leader[3] != pgid:
        sys.exit(3)
    try:
        os.killpg(pgid, signum)
    except ProcessLookupError:
        pass
    except OSError:
        sys.exit(4)
else:
    sys.exit(5)
'''


def _record_signal(signum: int, _frame: object) -> None:
    """Record signals without raising, so cleanup cannot be interrupted."""
    global _SIGNAL_REQUESTED
    if _SIGNAL_REQUESTED is None:
        _SIGNAL_REQUESTED = signum


def _check_cancelled() -> None:
    if _SIGNAL_REQUESTED is not None and not _CLEANUP_IN_PROGRESS:
        raise HarnessCancelled(_SIGNAL_REQUESTED)


def _protect_cleanup_from_signals() -> None:
    """Stop subsequent cancellation signals from interrupting cleanup."""
    global _CLEANUP_IN_PROGRESS
    _CLEANUP_IN_PROGRESS = True
    for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(signum, signal.SIG_IGN)


def _which(name: str, *, fixed: str | None = None) -> str:
    if fixed is not None:
        candidate = Path(fixed)
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
        raise HarnessError(f"required trusted executable is missing: {fixed}")
    found = shutil.which(name)
    if not found:
        # Non-login environments sometimes omit /usr/sbin from PATH.
        for directory in ("/usr/sbin", "/usr/bin", "/sbin", "/bin"):
            candidate = Path(directory) / name
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return str(candidate)
        raise HarnessError(f"required executable is missing: {name}")
    return found


def _preflight() -> None:
    if sys.platform != "linux":
        raise HarnessError("Linux is required; macOS is not evidence")
    if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
        raise HarnessError("Linux pidfd APIs are required for race-safe process cleanup")
    if os.geteuid() == 0:
        raise HarnessError("a non-root caller is required")
    if (
        os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
        and os.environ.get("ASTATINE_ALLOW_SSH_LIFECYCLE") != "1"
    ):
        raise HarnessError(
            "refusing to create a disposable user outside a GitHub-hosted runner; "
            "set ASTATINE_ALLOW_SSH_LIFECYCLE=1 to override"
        )

    _which("ssh")
    _which("ssh-keygen")
    _which("sudo")
    _which("dbus-daemon")
    _which("gnome-keyring-daemon")
    _which("gdbus")
    _which("timeout")
    _which("setsid")
    _which("useradd")
    _which("userdel")
    _which("chpasswd")
    _which("passwd")
    _which("env")
    _which("sshd", fixed="/usr/sbin/sshd")

    probe = subprocess.run(
        ["sudo", "-n", "true"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=10,
        check=False,
    )
    if probe.returncode != 0:
        raise HarnessError("passwordless sudo is required")


def _sanitize(text: str) -> str:
    """Best-effort redaction for diagnostics. Never use this as a log sink."""
    text = re.sub(r"SHA256:[A-Za-z0-9+/=]+", "SHA256:[REDACTED]", text)
    text = re.sub(
        r"(ssh-(?:ed25519|rsa)|ecdsa-sha2-[A-Za-z0-9-]+)[ \t]+[A-Za-z0-9+/=]+",
        r"\1 [REDACTED]",
        text,
    )
    text = re.sub(
        r"(?i)(password|passphrase|secret|mnemonic|recovery phrase)"
        r"([ \t]*[:=][ \t]*)[^\s]+",
        r"\1\2[REDACTED]",
        text,
    )
    # A BIP-39 phrase is a run of 12 or 24 short lowercase words. The actual
    # phrase is never intentionally written to a diagnostic, but this is a
    # second boundary in case a caller asks to print terminal output.
    text = re.sub(
        r"\b(?:[a-z]{3,8}[ \t]+){11,}[a-z]{3,8}\b",
        "[REDACTED MNEMONIC]",
        text,
    )
    text = re.sub(r"\b[0-9a-fA-F]{64,}\b", "[REDACTED HEX]", text)
    return text


def _bounded_tail(data: bytes, limit: int = 4000) -> str:
    return _sanitize(data[-limit:].decode("utf-8", "replace"))


class PtyProcess:
    """A local controlling PTY running the actual SSH client."""

    def __init__(self) -> None:
        self.pid: int | None = None
        self.master: int | None = None
        self.buffer = bytearray()
        self.search_pos = 0
        self.status: int | None = None
        self.eof = False
        # Set while production wallet creation may have written a recovery
        # phrase to the terminal. The session clears this only after matching
        # the BACKED UP prompt and scrubbing the buffer.
        self.withhold_output = False

    def start(self, argv: list[str], env: dict[str, str]) -> None:
        pid, master = pty.fork()
        if pid == 0:
            try:
                os.umask(0o077)
                os.execve(argv[0], argv, env)
            except BaseException:
                try:
                    os.write(2, b"failed to execute ssh client\n")
                except OSError:
                    pass
                os._exit(127)
        self.pid = pid
        self.master = master
        flags = fcntl.fcntl(master, fcntl.F_GETFL)
        fcntl.fcntl(master, fcntl.F_SETFL, flags | os.O_NONBLOCK)

    def scrub(self) -> None:
        for index in range(len(self.buffer)):
            self.buffer[index] = 0
        self.buffer.clear()
        self.search_pos = 0

    def _read_available(self, wait: float) -> bool:
        assert self.master is not None
        readable, _, _ = select.select([self.master], [], [], wait)
        if not readable:
            return False
        try:
            chunk = os.read(self.master, 8192)
        except BlockingIOError:
            return False
        except OSError as error:
            if error.errno == errno.EIO:
                self.eof = True
                return False
            raise
        if not chunk:
            self.eof = True
            return False
        self.buffer.extend(chunk)
        return True

    def expect_any(self, needles: list[bytes], timeout: float) -> bytes:
        deadline = time.monotonic() + timeout
        while True:
            _check_cancelled()
            best: tuple[int, bytes] | None = None
            for needle in needles:
                index = self.buffer.find(needle, self.search_pos)
                if index >= 0 and (best is None or index < best[0]):
                    best = (index, needle)
            if best is not None:
                self.search_pos = best[0] + len(best[1])
                return best[1]
            if self.eof:
                raise HarnessError("remote session ended before the expected prompt")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise HarnessError("timed out waiting for the expected prompt")
            self._read_available(min(0.2, remaining))

    def expect(self, needle: bytes, timeout: float) -> None:
        self.expect_any([needle], timeout)

    def send(self, data: bytes) -> None:
        assert self.master is not None
        view = memoryview(data)
        while view:
            _check_cancelled()
            try:
                written = os.write(self.master, view)
            except BlockingIOError:
                time.sleep(0.01)
                continue
            if written <= 0:
                raise HarnessError("local PTY write returned no progress")
            view = view[written:]

    def resize(self, rows: int, cols: int) -> tuple[int, int]:
        assert self.master is not None
        fcntl.ioctl(
            self.master,
            termios.TIOCSWINSZ,
            struct.pack("HHHH", rows, cols, 0, 0),
        )
        actual = fcntl.ioctl(self.master, termios.TIOCGWINSZ, b"\0" * 8)
        got_rows, got_cols, _, _ = struct.unpack("HHHH", actual)
        return got_rows, got_cols

    def alive(self) -> bool:
        if self.pid is None or self.status is not None:
            return False
        try:
            waited, status = os.waitpid(self.pid, os.WNOHANG)
        except ChildProcessError:
            return False
        if waited == self.pid:
            self.status = status
            return False
        return True

    def wait_local_exit(self, timeout: float) -> int | None:
        if self.pid is None:
            return self.status
        deadline = time.monotonic() + timeout
        while self.status is None:
            try:
                waited, status = os.waitpid(self.pid, os.WNOHANG)
            except ChildProcessError:
                return self.status
            if waited == self.pid:
                self.status = status
                break
            if time.monotonic() >= deadline:
                return None
            time.sleep(0.05)
        return self.status

    def wait_exit(self, timeout: float) -> tuple[int, bytes]:
        if self.pid is None:
            raise HarnessError("PTY process was not started")
        deadline = time.monotonic() + timeout
        while True:
            _check_cancelled()
            self._read_available(0.05)
            if self.status is None:
                try:
                    waited, status = os.waitpid(self.pid, os.WNOHANG)
                except ChildProcessError:
                    waited, status = self.pid, 0
                if waited == self.pid:
                    self.status = status
            if self.status is not None:
                # Drain output that was already buffered when the child exited.
                idle = 0
                while idle < 2 and not self.eof:
                    if self._read_available(0.05):
                        idle = 0
                    else:
                        idle += 1
                break
            if time.monotonic() >= deadline:
                self.kill(signal.SIGKILL)
                self.wait_local_exit(5.0)
                raise HarnessError("timed out waiting for the remote application to exit")
        if os.WIFEXITED(self.status):
            code = os.WEXITSTATUS(self.status)
        elif os.WIFSIGNALED(self.status):
            code = 128 + os.WTERMSIG(self.status)
        else:
            code = -1
        return code, bytes(self.buffer)

    def kill(self, signum: int) -> None:
        if self.pid is None or self.status is not None:
            return
        # This PID belongs to our unreaped direct child. Reap an already-exited
        # child before signaling; while alive() returns true, the child remains
        # waitable by us and its PID cannot be recycled for another process.
        if not self.alive():
            return
        try:
            os.kill(self.pid, signum)
        except ProcessLookupError:
            pass

    def close(self) -> None:
        try:
            if self.master is not None:
                try:
                    os.close(self.master)
                except OSError:
                    pass
                self.master = None
        finally:
            # The PTY may contain the recovery phrase even when an exception
            # interrupted the backup prompt. Scrub on every close path.
            self.scrub()


class Harness:
    def __init__(self, app_source: Path) -> None:
        self.app_source = app_source
        self.tools = {
            name: _which(name)
            for name in (
                "ssh",
                "ssh-keygen",
                "sudo",
                "dbus-daemon",
                "gnome-keyring-daemon",
                "gdbus",
                "timeout",
                "setsid",
                "useradd",
                "userdel",
                "chpasswd",
                "passwd",
            )
        }
        self.tools["sshd"] = "/usr/sbin/sshd"
        self.tools["env"] = _which("env")

        self.work: Path | None = None
        self.auth_dir: Path | None = None
        self.app_dir: Path | None = None
        self.state: Path | None = None
        self.target_home: Path | None = None

        self.user: str | None = None
        self.uid: int | None = None
        self.created_user = False
        self.wallet_password = bytearray(secrets.token_hex(24).encode())

        self.sshd_launcher: subprocess.Popen[bytes] | None = None
        self.sshd_pid: int | None = None
        self.sshd_identity: ProcessIdentity | None = None
        self.sshd_log: Path | None = None
        self.bus_pid: int | None = None
        self.bus_identity: ProcessIdentity | None = None
        self.keyring_pid: int | None = None
        self.keyring_identity: ProcessIdentity | None = None
        self.keyring_wrapper: subprocess.Popen[bytes] | None = None
        self.keyring_password_file: Path | None = None
        self.bus_address: str | None = None
        self.env_file: Path | None = None
        self.default_collection: str | None = None
        self.app_path: Path | None = None
        self.port: int | None = None
        self.ssh_options: list[str] = []
        self.journal_path: Path | None = None
        self.journal_initial: bytes | None = None
        self.cleanup_errors: list[str] = []
        self.success = False

    # ------------------------------------------------------------------
    # Process and file helpers
    # ------------------------------------------------------------------

    def run(
        self,
        argv: list[str],
        *,
        input_bytes: bytes | None = None,
        timeout: float = 60.0,
        check: bool = False,
        env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        _check_cancelled()
        try:
            completed = subprocess.run(
                argv,
                input=input_bytes,
                stdin=subprocess.DEVNULL if input_bytes is None else None,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                env=env,
                check=False,
            )
        except subprocess.TimeoutExpired as error:
            raise HarnessError(f"command timed out: {Path(argv[0]).name}") from error
        except OSError as error:
            raise HarnessError(f"could not execute {Path(argv[0]).name}: {error}") from error
        if check and completed.returncode != 0:
            detail = _bounded_tail(completed.stderr) or _bounded_tail(completed.stdout)
            raise HarnessError(
                f"command failed ({completed.returncode}): {Path(argv[0]).name}: {detail}"
            )
        return completed

    def run_root(
        self,
        argv: list[str],
        *,
        input_bytes: bytes | None = None,
        timeout: float = 60.0,
        check: bool = False,
    ) -> subprocess.CompletedProcess[bytes]:
        return self.run(
            [self.tools["sudo"], "-n", "--", *argv],
            input_bytes=input_bytes,
            timeout=timeout,
            check=check,
        )

    def capture_process_identity(
        self, pid: int, *, uid: int, marker: str, label: str
    ) -> ProcessIdentity:
        completed = self.run_root(
            [
                sys.executable,
                "-c",
                _PIDFD_HELPER,
                "capture",
                str(pid),
                str(uid),
                marker,
            ],
            timeout=10,
        )
        if completed.returncode != 0:
            raise HarnessError(f"could not validate the {label} process identity")
        try:
            starttime = int(completed.stdout.decode("ascii").strip())
        except (UnicodeDecodeError, ValueError) as error:
            raise HarnessError(f"could not record the {label} process identity") from error
        return ProcessIdentity(pid, uid, starttime, marker)

    def process_identity_action(
        self, action: str, identity: ProcessIdentity, *, signum: int | None = None
    ) -> subprocess.CompletedProcess[bytes]:
        arguments = [
            sys.executable,
            "-c",
            _PIDFD_HELPER,
            action,
            str(identity.pid),
        ]
        if action == "stop":
            if signum is None:
                raise HarnessError("pidfd stop action requires a signal")
            arguments.append(str(signum))
        arguments.extend(
            (str(identity.uid), str(identity.starttime), identity.marker)
        )
        return self.run_root(arguments, timeout=15)

    def process_identity_state(self, identity: ProcessIdentity) -> str | None:
        completed = self.process_identity_action("state", identity)
        if completed.returncode == 2:
            return None
        if completed.returncode != 0:
            raise HarnessError("could not safely inspect the tracked process")
        state = completed.stdout.decode("ascii", "replace").strip()
        if len(state) != 1:
            raise HarnessError("pidfd process inspection returned an invalid state")
        return state

    def run_as_user(
        self,
        argv: list[str],
        *,
        env: dict[str, str] | None = None,
        input_bytes: bytes | None = None,
        timeout: float = 60.0,
        check: bool = False,
    ) -> subprocess.CompletedProcess[bytes]:
        if self.user is None:
            raise HarnessError("the disposable user has not been created")
        command = [self.tools["sudo"], "-n", "-u", self.user, "--"]
        if env:
            command.append(self.tools["env"])
            command.extend(f"{key}={value}" for key, value in env.items())
        command.extend(argv)
        return self.run(
            command,
            input_bytes=input_bytes,
            timeout=timeout,
            check=check,
        )

    def user_env(self) -> dict[str, str]:
        assert self.state is not None
        assert self.bus_address is not None
        return {
            "HOME": str(self.state / "home"),
            "XDG_CONFIG_HOME": str(self.state / "config"),
            "XDG_DATA_HOME": str(self.state / "data"),
            "XDG_CACHE_HOME": str(self.state / "cache"),
            "XDG_RUNTIME_DIR": str(self.state / "runtime"),
            "TMPDIR": str(self.state / "tmp"),
            "DBUS_SESSION_BUS_ADDRESS": self.bus_address,
            "PATH": "/usr/local/bin:/usr/bin:/bin",
        }

    def write_as_user(self, path: Path, data: bytes, mode: int) -> None:
        script = 'umask 077; cat > "$1" && chmod "$2" "$1"'
        self.run_as_user(
            ["/bin/sh", "-c", script, "sh", str(path), f"{mode:o}"],
            input_bytes=data,
            timeout=15,
            check=True,
        )

    def read_as_user(self, path: Path) -> bytes:
        completed = self.run_as_user(["cat", str(path)], timeout=15)
        if completed.returncode != 0:
            raise HarnessError(f"could not read required state file: {path.name}")
        return completed.stdout

    def read_root(self, path: Path) -> bytes:
        completed = self.run_root(["cat", str(path)], timeout=15)
        if completed.returncode != 0:
            return b""
        return completed.stdout

    def remove_as_user(self, path: Path) -> None:
        self.run_as_user(["rm", "-f", "--", str(path)], timeout=15)

    def discard_secret_file(self, path: Path) -> None:
        # Truncate before unlinking so a failed cleanup does not leave the
        # startup password readable in the disposable state directory.
        self.run_as_user(
            [
                "/bin/sh",
                "-c",
                'if [ -e "$1" ]; then : > "$1"; fi; rm -f -- "$1"',
                "sh",
                str(path),
            ],
            timeout=15,
            check=True,
        )

    def redact_secrets(self, data: bytes) -> bytes:
        secret = bytes(self.wallet_password)
        if secret:
            data = data.replace(secret, b"[REDACTED]")
        return data

    # ------------------------------------------------------------------
    # Disposable user, state, and persistent provider
    # ------------------------------------------------------------------

    def create_user(self) -> None:
        for _ in range(10):
            candidate = "astatine-life-" + secrets.token_hex(4)
            try:
                pwd.getpwnam(candidate)
            except KeyError:
                self.user = candidate
                break
        if self.user is None:
            raise HarnessError("could not choose an unused disposable user name")

        completed = self.run_root(
            [self.tools["useradd"], "-m", "-s", "/bin/bash", self.user],
            timeout=30,
        )
        if completed.returncode != 0:
            raise HarnessError("could not create the disposable user")
        self.created_user = True
        record = pwd.getpwnam(self.user)
        self.uid = record.pw_uid
        self.target_home = Path(record.pw_dir)

        # Password authentication remains disabled in sshd. A random password
        # marker keeps the account non-locked for sshd's account checks without
        # making that password usable for login.
        password = bytearray(secrets.token_hex(32).encode())
        payload = bytearray(self.user.encode() + b":" + password + b"\n")
        try:
            completed = self.run_root(
                [self.tools["chpasswd"]],
                input_bytes=bytes(payload),
                timeout=30,
            )
        finally:
            for index in range(len(password)):
                password[index] = 0
            for index in range(len(payload)):
                payload[index] = 0
        if completed.returncode != 0:
            raise HarnessError("could not set the disposable password marker")
        state = self.run_root([self.tools["passwd"], "-S", self.user], timeout=15)
        fields = state.stdout.decode("utf-8", "replace").split()
        if state.returncode != 0 or len(fields) < 2 or fields[1] != "P":
            raise HarnessError("the disposable account is not in the expected unlocked marker state")

    def create_state(self) -> None:
        assert self.user is not None
        assert self.target_home is not None
        state = self.target_home / f".astatine-ssh-lifecycle-{secrets.token_hex(4)}"
        # The target home is intentionally not caller-traversable. Check for a
        # collision as root while creating the state as the target user.
        collision = self.run_root(
            ["/bin/sh", "-c", 'test -e "$1"', "sh", str(state)],
            timeout=10,
        )
        if collision.returncode == 0:
            raise HarnessError("refusing to reuse an existing state directory")
        script = 'umask 077; mkdir -p "$@" && chmod 700 "$@"'
        self.run_as_user(
            ["/bin/sh", "-c", script, "sh", str(state)],
            timeout=20,
            check=True,
        )
        for name in ("home", "config", "data", "cache", "runtime", "tmp", "bus"):
            path = state / name
            self.run_as_user(["mkdir", "-p", str(path)], timeout=15, check=True)
            self.run_as_user(["chmod", "700", str(path)], timeout=15, check=True)
        self.state = state

    def start_bus(self) -> None:
        assert self.state is not None
        assert self.uid is not None
        bus_config = self.state / "session.conf"
        config = f"""<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>session</type>
  <listen>unix:dir={self.state / "bus"}</listen>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow send_destination="*" eavesdrop="true"/>
    <allow eavesdrop="true"/>
    <allow own="*"/>
  </policy>
</busconfig>
"""
        self.write_as_user(bus_config, config.encode(), 0o600)
        address_file = self.state / "bus-address"
        pid_file = self.state / "bus-pid"
        script = (
            'umask 077; exec dbus-daemon --config-file="$1" --fork '
            '--print-address=3 --print-pid=4 3>"$2" 4>"$3"'
        )
        completed = self.run_as_user(
            [
                "/bin/sh",
                "-c",
                script,
                "sh",
                str(bus_config),
                str(address_file),
                str(pid_file),
            ],
            timeout=30,
        )
        if completed.returncode != 0:
            detail = _bounded_tail(completed.stderr)
            raise HarnessError(f"private D-Bus session failed to start: {detail}")
        address = self.read_as_user(address_file).decode("utf-8", "replace").strip()
        pid_text = self.read_as_user(pid_file).decode("ascii", "replace").strip()
        if not address.startswith("unix:") or not pid_text.isdigit():
            raise HarnessError("private D-Bus session did not report a usable address and pid")
        self.bus_address = address
        self.bus_pid = int(pid_text)
        self.bus_identity = self.capture_process_identity(
            self.bus_pid,
            uid=self.uid,
            marker=str(bus_config),
            label="private D-Bus daemon",
        )

    def start_keyring(self) -> None:
        assert self.state is not None
        assert self.bus_address is not None
        assert self.uid is not None
        password_file = self.state / "keyring-password"
        log_file = self.state / "keyring.log"
        pid_file = self.state / "keyring-pid"
        password = bytearray(secrets.token_hex(32).encode())
        try:
            self.write_as_user(password_file, bytes(password) + b"\n", 0o600)
        finally:
            for index in range(len(password)):
                password[index] = 0
        self.keyring_password_file = password_file

        script = (
            'umask 077; setsid gnome-keyring-daemon --components=secrets '
            '--foreground --unlock < "$1" >/dev/null 2>"$2" & '
            'echo $! > "$3"; wait'
        )
        try:
            self.keyring_wrapper = subprocess.Popen(
                [
                    self.tools["sudo"],
                    "-n",
                    "-u",
                    self.user or "",
                    "--",
                    self.tools["env"],
                    *[f"{key}={value}" for key, value in self.user_env().items()],
                    "/bin/sh",
                    "-c",
                    script,
                    "sh",
                    str(password_file),
                    str(log_file),
                    str(pid_file),
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
        except OSError as error:
            raise HarnessError(f"could not start the persistent Secret Service: {error}") from error

        deadline = time.monotonic() + 25.0
        while time.monotonic() < deadline:
            if self.service_owned():
                break
            if self.keyring_wrapper.poll() is not None and not self.service_owned():
                detail = _bounded_tail(self.read_as_user(log_file)) if self.path_exists(log_file) else ""
                raise HarnessError(f"persistent Secret Service exited during startup: {detail}")
            time.sleep(0.1)
        else:
            detail = _bounded_tail(self.read_as_user(log_file)) if self.path_exists(log_file) else ""
            raise HarnessError(f"persistent Secret Service did not appear: {detail}")

        pid_from_file: int | None = None
        try:
            pid_text = self.read_as_user(pid_file).decode("ascii", "replace").strip()
        except HarnessError:
            pid_text = ""
        if pid_text.isdigit():
            pid_from_file = int(pid_text)
        # `setsid` forks only when it is already a process-group leader. Ask the
        # bus for the actual service PID instead of trusting a stale wrapper
        # PID, and fall back to the recorded PID when the bus query is unavailable.
        pid_from_bus = self.secret_service_pid()
        self.keyring_pid = pid_from_bus or pid_from_file
        if self.keyring_pid is None:
            raise HarnessError("persistent Secret Service is not running")
        self.keyring_identity = self.capture_process_identity(
            self.keyring_pid,
            uid=self.uid,
            marker="gnome-keyring-daemon",
            label="persistent Secret Service",
        )

        # Verify the provider before discarding the startup password file.
        self.verify_provider()
        self.discard_secret_file(password_file)
        if self.path_exists(password_file):
            raise HarnessError("Secret Service startup password file was not removed")
        self.keyring_password_file = None

    def service_owned(self) -> bool:
        if self.bus_address is None:
            return False
        completed = self.run_as_user(
            [
                self.tools["gdbus"],
                "call",
                "--session",
                "--dest",
                "org.freedesktop.DBus",
                "--object-path",
                "/org/freedesktop/DBus",
                "--method",
                "org.freedesktop.DBus.NameHasOwner",
                "org.freedesktop.secrets",
            ],
            env=self.user_env(),
            timeout=10,
        )
        return completed.returncode == 0 and b"true" in completed.stdout

    def secret_service_pid(self) -> int | None:
        if self.bus_address is None:
            return None
        completed = self.run_as_user(
            [
                self.tools["gdbus"],
                "call",
                "--session",
                "--dest",
                "org.freedesktop.DBus",
                "--object-path",
                "/org/freedesktop/DBus",
                "--method",
                "org.freedesktop.DBus.GetConnectionUnixProcessID",
                "org.freedesktop.secrets",
            ],
            env=self.user_env(),
            timeout=10,
        )
        if completed.returncode != 0:
            return None
        match = re.search(rb"uint32\s+(\d+)", completed.stdout)
        return int(match.group(1)) if match is not None else None

    def verify_provider(self) -> None:
        assert self.bus_address is not None
        owned = self.run_as_user(
            [
                self.tools["gdbus"],
                "call",
                "--session",
                "--dest",
                "org.freedesktop.DBus",
                "--object-path",
                "/org/freedesktop/DBus",
                "--method",
                "org.freedesktop.DBus.NameHasOwner",
                "org.freedesktop.secrets",
            ],
            env=self.user_env(),
            timeout=10,
        )
        if owned.returncode != 0 or b"true" not in owned.stdout:
            raise HarnessError("org.freedesktop.secrets has no owner on the private bus")

        alias = self.run_as_user(
            [
                self.tools["gdbus"],
                "call",
                "--session",
                "--dest",
                "org.freedesktop.secrets",
                "--object-path",
                "/org/freedesktop/secrets",
                "--method",
                "org.freedesktop.Secret.Service.ReadAlias",
                "default",
            ],
            env=self.user_env(),
            timeout=10,
        )
        match = re.search(rb"objectpath '([^']*)'", alias.stdout)
        if alias.returncode != 0 or match is None:
            raise HarnessError("could not read the Secret Service default collection")
        path = match.group(1).decode("utf-8", "replace")
        if not path or path == "/":
            raise HarnessError("the private Secret Service has no default collection")
        self.default_collection = path

        locked = self.run_as_user(
            [
                self.tools["gdbus"],
                "call",
                "--session",
                "--dest",
                "org.freedesktop.secrets",
                "--object-path",
                path,
                "--method",
                "org.freedesktop.DBus.Properties.Get",
                "org.freedesktop.Secret.Collection",
                "Locked",
            ],
            env=self.user_env(),
            timeout=10,
        )
        if locked.returncode != 0 or b"false" not in locked.stdout:
            raise HarnessError("the default Secret Service collection is not unlocked")

    def write_env_file(self) -> None:
        assert self.state is not None
        assert self.bus_address is not None
        self.env_file = self.state / "ssh-env"
        line = "export DBUS_SESSION_BUS_ADDRESS=" + shlex.quote(self.bus_address) + "\n"
        self.write_as_user(self.env_file, line.encode(), 0o600)

    def prepare_app(self) -> None:
        self.app_dir = Path(tempfile.mkdtemp(prefix="astatine-ssh-app-", dir="/tmp"))
        os.chmod(self.app_dir, 0o755)
        destination = self.app_dir / "astatine"
        try:
            shutil.copyfile(self.app_source, destination)
        except OSError as error:
            raise HarnessError(f"could not copy the application executable: {error}") from error
        os.chmod(destination, 0o755)
        self.app_path = destination
        if destination.stat().st_size <= 0:
            raise HarnessError("the copied application executable is empty")

    # ------------------------------------------------------------------
    # Loopback sshd
    # ------------------------------------------------------------------

    def pick_port(self) -> int:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.bind(("127.0.0.1", 0))
            return int(sock.getsockname()[1])
        finally:
            sock.close()

    def prepare_ssh(self) -> None:
        assert self.work is not None
        assert self.user is not None
        assert self.app_path is not None

        host_key = self.work / "host_ed25519"
        user_key = self.work / "user_ed25519"
        for key in (host_key, user_key):
            completed = self.run(
                [self.tools["ssh-keygen"], "-q", "-t", "ed25519", "-N", "", "-f", str(key)],
                timeout=30,
                env=self.local_ssh_env(),
            )
            if completed.returncode != 0:
                raise HarnessError(f"ssh-keygen failed: {_bounded_tail(completed.stderr)}")

        self.auth_dir = Path(tempfile.mkdtemp(prefix="astatine-ssh-auth-", dir="/tmp"))
        os.chmod(self.auth_dir, 0o755)
        authorized = self.auth_dir / "authorized_keys"
        authorized.write_bytes((user_key.with_suffix(".pub")).read_bytes())
        os.chmod(authorized, 0o644)

        self.port = self.pick_port()
        known_hosts = self.work / "known_hosts"
        host_public = (host_key.with_suffix(".pub")).read_text(encoding="ascii").strip()
        known_hosts.write_text(f"[127.0.0.1]:{self.port} {host_public}\n", encoding="ascii")
        os.chmod(known_hosts, 0o600)
        self.ssh_options = [
            "-F",
            "/dev/null",
            "-p",
            str(self.port),
            "-i",
            str(user_key),
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            f"UserKnownHostsFile={known_hosts}",
            "-o",
            "ConnectTimeout=5",
            "-o",
            "ConnectionAttempts=1",
            "-o",
            "PasswordAuthentication=no",
            "-o",
            "KbdInteractiveAuthentication=no",
            "-o",
            "PreferredAuthentications=publickey",
            "-o",
            "ClearAllForwardings=yes",
            "-o",
            "LogLevel=ERROR",
        ]

        config = self.work / "sshd_config"
        config.write_text(
            f"""Port {self.port}
ListenAddress 127.0.0.1
HostKey {host_key}
PidFile {self.work / "sshd.pid"}
AuthorizedKeysFile {authorized}
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
PubkeyAuthentication yes
PermitEmptyPasswords no
UsePAM no
PermitRootLogin no
AllowUsers {self.user}
StrictModes no
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
AllowStreamLocalForwarding no
PermitTunnel no
GatewayPorts no
LogLevel VERBOSE
""",
            encoding="ascii",
        )
        os.chmod(config, 0o600)

        self.run_root(["mkdir", "-p", "/run/sshd"], timeout=15, check=True)
        self.run_root(
            [self.tools["sshd"], "-t", "-f", str(config)],
            timeout=20,
            check=True,
        )
        self.sshd_log = self.work / "sshd.log"
        log_handle = open(self.sshd_log, "wb")
        try:
            self.sshd_launcher = subprocess.Popen(
                [
                    self.tools["sudo"],
                    "-n",
                    "--",
                    self.tools["sshd"],
                    "-D",
                    "-e",
                    "-f",
                    str(config),
                ],
                stdin=subprocess.DEVNULL,
                stdout=log_handle,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        finally:
            log_handle.close()

        pid_file = self.work / "sshd.pid"
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            if pid_file.exists():
                text = pid_file.read_text(encoding="ascii", errors="replace").strip()
                if text.isdigit():
                    self.sshd_pid = int(text)
                    break
            if self.sshd_launcher.poll() is not None:
                break
            time.sleep(0.1)
        if self.sshd_pid is None:
            detail = _bounded_tail(self.read_root(self.sshd_log))
            raise HarnessError(f"disposable sshd did not start: {detail}")
        self.sshd_identity = self.capture_process_identity(
            self.sshd_pid,
            uid=0,
            marker=str(config),
            label="disposable sshd",
        )

    def wait_ssh_ready(self) -> None:
        assert self.user is not None
        target = f"{self.user}@127.0.0.1"
        deadline = time.monotonic() + 15.0
        while time.monotonic() < deadline:
            completed = self.run(
                [self.tools["ssh"], *self.ssh_options, "-n", target, "true"],
                timeout=10,
                env=self.local_ssh_env(),
            )
            if completed.returncode == 0:
                return
            time.sleep(0.2)
        detail = _bounded_tail(self.read_root(self.sshd_log) if self.sshd_log else b"")
        raise HarnessError(f"disposable sshd did not accept a loopback public-key login: {detail}")

    # ------------------------------------------------------------------
    # SSH command construction
    # ------------------------------------------------------------------

    def local_ssh_env(self) -> dict[str, str]:
        assert self.work is not None
        return {
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "HOME": str(self.work),
            "TMPDIR": str(self.work),
            "TERM": "xterm",
            "LC_ALL": "C",
        }

    def remote_environment_lines(self, dbus_override: str | None = None) -> list[str]:
        assert self.state is not None
        assert self.env_file is not None
        lines = [
            "set -eu",
            "umask 077",
            f". {shlex.quote(str(self.env_file))}",
            "export PATH=/usr/local/bin:/usr/bin:/bin",
            f"export HOME={shlex.quote(str(self.state / 'home'))}",
            f"export XDG_CONFIG_HOME={shlex.quote(str(self.state / 'config'))}",
            f"export XDG_DATA_HOME={shlex.quote(str(self.state / 'data'))}",
            f"export XDG_CACHE_HOME={shlex.quote(str(self.state / 'cache'))}",
            f"export XDG_RUNTIME_DIR={shlex.quote(str(self.state / 'runtime'))}",
            f"export TMPDIR={shlex.quote(str(self.state / 'tmp'))}",
            "unset DBUS_STARTER_ADDRESS DBUS_STARTER_BUS_TYPE",
            "unset GNOME_KEYRING_CONTROL GNOME_KEYRING_PID SSH_AUTH_SOCK SSH_AGENT_PID",
        ]
        if dbus_override is not None:
            lines.append(
                "export DBUS_SESSION_BUS_ADDRESS=" + shlex.quote(dbus_override)
            )
        return lines

    def remote_app_command(
        self,
        args: list[str],
        *,
        pid_file: Path | None = None,
        starttime_file: Path | None = None,
        use_timeout: bool = False,
        timeout_seconds: int = 60,
        dbus_override: str | None = None,
    ) -> str:
        assert self.app_path is not None
        lines = self.remote_environment_lines(dbus_override)
        if pid_file is not None:
            lines.append(f"echo $$ > {shlex.quote(str(pid_file))}")
        if starttime_file is not None:
            lines.append(
                f"awk '{{print $22}}' /proc/$$/stat > {shlex.quote(str(starttime_file))}"
            )
        command = [shlex.quote(str(self.app_path)), *(shlex.quote(arg) for arg in args)]
        if use_timeout:
            command = [
                "timeout",
                "--signal=TERM",
                "--kill-after=5s",
                f"{timeout_seconds}s",
                *command,
            ]
        lines.append("exec " + " ".join(command))
        return "\n".join(lines) + "\n"

    def ssh_target(self) -> str:
        assert self.user is not None
        return f"{self.user}@127.0.0.1"

    def ssh_no_pty(self, command: str, timeout: float) -> subprocess.CompletedProcess[bytes]:
        return self.run(
            [
                self.tools["ssh"],
                *self.ssh_options,
                "-T",
                self.ssh_target(),
                command,
            ],
            timeout=timeout,
            env=self.local_ssh_env(),
        )

    # ------------------------------------------------------------------
    # Sessions
    # ------------------------------------------------------------------

    def session_a(self) -> None:
        command = self.remote_app_command(INIT_ARGS)
        process = PtyProcess()
        process.withhold_output = True
        process.start(
            [
                self.tools["ssh"],
                *self.ssh_options,
                "-tt",
                self.ssh_target(),
                command,
            ],
            self.local_ssh_env(),
        )
        try:
            # Production wallet creation deliberately displays a freshly
            # generated recovery phrase before this confirmation. Do not print,
            # retain, or write that terminal output. Once the prompt is matched
            # the buffer is overwritten and cleared.
            process.expect(b"Choose 1, 2, or 3 [1]: ", PROMPT_TIMEOUT)
            process.send(b"1\n")
            try:
                process.expect(
                    b"Type BACKED UP after writing the phrase down: ",
                    PROMPT_TIMEOUT,
                )
            except HarnessError as error:
                raise HarnessError(
                    "wallet creation prompt failed; terminal output withheld because "
                    "it may contain a recovery phrase"
                ) from error
            process.scrub()
            process.withhold_output = False
            process.send(b"BACKED UP\n")

            process.expect(
                b"Create keystore password (input hidden; use at least 12 characters): ",
                PROMPT_TIMEOUT,
            )
            process.send(bytes(self.wallet_password) + b"\n")
            process.expect(b"Confirm keystore password (input hidden): ", PROMPT_TIMEOUT)
            process.send(bytes(self.wallet_password) + b"\n")
            process.expect(
                b"Use the selected wallet for future per-run spending sessions? (y/N)",
                PROMPT_TIMEOUT,
            )
            process.send(b"y\n")
            process.expect(
                b"Persist and approve this per-run policy for the selected wallet and network? (y/N)",
                PROMPT_TIMEOUT,
            )
            process.send(b"y\n")
            code, output = process.wait_exit(EXIT_TIMEOUT)
        except BaseException:
            process.kill(signal.SIGKILL)
            process.wait_local_exit(5.0)
            process.close()
            raise
        process.close()

        if code != 0:
            detail = (
                "terminal output withheld because it may contain a recovery phrase"
                if process.withhold_output
                else _bounded_tail(self.redact_secrets(output))
            )
            raise HarnessError(f"production init over SSH failed (exit {code}): {detail}")
        if b"Configured Testnet" not in output:
            raise HarnessError("production init did not reach its configured success output")
        print("ssh-pty=ok", flush=True)

    def session_b(self) -> None:
        assert self.state is not None
        assert self.uid is not None
        assert self.app_path is not None
        pid_file = self.state / "session-b.pid"
        starttime_file = self.state / "session-b.starttime"
        self.remove_as_user(pid_file)
        self.remove_as_user(starttime_file)
        command = self.remote_app_command(
            INIT_ARGS,
            pid_file=pid_file,
            starttime_file=starttime_file,
        )
        process = PtyProcess()
        process.start(
            [
                self.tools["ssh"],
                *self.ssh_options,
                "-tt",
                self.ssh_target(),
                command,
            ],
            self.local_ssh_env(),
        )
        try:
            process.expect(b"Keep the selected wallet? (Y/n)", PROMPT_TIMEOUT)

            # Resize and read back only the local controlling PTY. We do not
            # inspect the remote PTY dimensions, so this is not evidence that
            # an SSH window-change request reached the server.
            rows, cols = 40, 120
            got_rows, got_cols = process.resize(rows, cols)
            if (got_rows, got_cols) != (rows, cols):
                raise HarnessError(
                    f"local PTY resize was not applied: {got_rows}x{got_cols}"
                )
            # A neutral invalid answer proves the application still reads and
            # writes its terminal after the resize. It must emit the parser's
            # error and then re-prompt.
            process.send(b"not-a-valid-choice\n")
            process.expect(b"Answer y or n.", PROMPT_TIMEOUT)
            process.expect(b"Keep the selected wallet? (Y/n)", PROMPT_TIMEOUT)
            print("ssh-resize=local-pty-responsive", flush=True)

            if not process.alive():
                raise HarnessError("local SSH client exited before the deliberate SIGKILL")
            if process.pid is None:
                raise HarnessError("local SSH client lost its child-process identity")
            process.kill(signal.SIGKILL)
            print("ssh-client-sigkill=observed", flush=True)
            status = process.wait_local_exit(5.0)
            if status is None:
                raise HarnessError("local SSH client did not exit after SIGKILL")
            if not os.WIFSIGNALED(status) or os.WTERMSIG(status) != signal.SIGKILL:
                raise HarnessError("local SSH client was not terminated by SIGKILL")
        except BaseException:
            process.kill(signal.SIGKILL)
            process.wait_local_exit(5.0)
            process.close()
            raise
        process.close()

        # Only filtered disconnect evidence is ever read from the sshd log.
        self.report_disconnect_log()

        remote_pid_text = self.read_as_user(pid_file).decode("ascii", "replace").strip()
        starttime_text = (
            self.read_as_user(starttime_file).decode("ascii", "replace").strip()
        )
        if not remote_pid_text.isdigit() or not starttime_text.isdigit():
            raise HarnessError(
                "remote application did not record its process identity before disconnect"
            )
        remote_identity = ProcessIdentity(
            int(remote_pid_text),
            self.uid,
            int(starttime_text),
            str(self.app_path),
        )

        deadline = time.monotonic() + DISCONNECT_EXIT_WAIT
        last_state: str | None = None
        while time.monotonic() < deadline:
            last_state = self.process_state(remote_identity)
            if last_state is None or last_state == "Z":
                break
            time.sleep(0.1)

        if last_state is None or last_state == "Z":
            print("ssh-disconnect-process=exited", flush=True)
            return

        # The application survived the real PTY hangup. Record evidence, then
        # terminate it explicitly; the harness never injects SIGHUP. Keep extra
        # diagnostics on stderr so stdout contains only the required machine
        # lines.
        print("ssh-disconnect-process=survived", flush=True)
        print(
            f"ssh-disconnect-pid={remote_identity.pid}",
            file=sys.stderr,
            flush=True,
        )
        print(f"ssh-disconnect-state={last_state}", file=sys.stderr, flush=True)
        self.stop_pid(remote_identity, "application")
        if self.process_state(remote_identity) not in (None, "Z", "X", "x"):
            raise HarnessError("surviving remote application did not terminate")
        print("ssh-disconnect-cleanup=terminated", file=sys.stderr, flush=True)

    def session_c(self) -> None:
        assert self.journal_path is not None
        baseline = self.hash_journal()
        for iteration in (1, 2):
            completed = self.ssh_no_pty(
                self.remote_app_command(["recover"], use_timeout=True, timeout_seconds=60),
                timeout=90,
            )
            if completed.returncode != 0:
                detail = _bounded_tail(completed.stderr) or _bounded_tail(completed.stdout)
                raise HarnessError(
                    f"recover over SSH failed on pass {iteration} "
                    f"(exit {completed.returncode}): {detail}"
                )
            combined = completed.stdout + completed.stderr
            if b"No unresolved transaction remains." not in combined:
                raise HarnessError(
                    f"recover over SSH did not authenticate the journal on pass {iteration}"
                )
            if self.hash_journal() != baseline:
                raise HarnessError(
                    "read-only recover unexpectedly changed the authenticated journal bytes"
                )
        print("ssh-no-pty=ok", flush=True)
        print("ssh-reconnect-recover=ok", flush=True)

    def session_d(self) -> None:
        assert self.state is not None
        before = self.hash_journal()
        unavailable = self.state / "unavailable-secret-service.sock"
        if self.path_exists(unavailable):
            self.remove_as_user(unavailable)
        completed = self.ssh_no_pty(
            self.remote_app_command(
                ["recover"],
                use_timeout=True,
                timeout_seconds=60,
                dbus_override=f"unix:path={unavailable}",
            ),
            timeout=90,
        )
        combined = completed.stdout + completed.stderr
        if completed.returncode == 0:
            raise HarnessError("recover succeeded with an unavailable Secret Service")
        lowered = combined.lower()
        if not any(
            marker in lowered
            for marker in (b"checkpoint", b"credential store", b"secret service", b"d-bus")
        ):
            raise HarnessError(
                "recover failed for an unexpected reason with an unavailable Secret Service: "
                + _bounded_tail(combined)
            )
        after = self.hash_journal()
        if after != before:
            raise HarnessError(
                "fail-closed maintainability check failed: journal bytes changed when the "
                "Secret Service was unavailable"
            )
        if self.path_exists(unavailable):
            raise HarnessError("unavailable Secret Service socket unexpectedly exists")
        print("ssh-unavailable-secret-service=fail-closed", flush=True)

    # ------------------------------------------------------------------
    # Evidence and cleanup
    # ------------------------------------------------------------------

    def hash_journal(self) -> bytes:
        assert self.journal_path is not None
        data = self.read_as_user(self.journal_path)
        if not data:
            raise HarnessError("authenticated transaction journal is missing or empty")
        return hashlib.sha256(data).digest()

    def process_state(self, identity: ProcessIdentity) -> str | None:
        return self.process_identity_state(identity)

    def report_disconnect_log(self) -> None:
        if self.sshd_log is None:
            print("ssh-disconnect-log=none", file=sys.stderr, flush=True)
            return
        data = self.read_root(self.sshd_log).decode("utf-8", "replace").splitlines()
        evidence = [
            line
            for line in data
            if re.search(
                r"(?i)(disconnect|connection closed|closed by|session closed|"
                r"received disconnect|client not responding)",
                line,
            )
        ]
        if not evidence:
            print("ssh-disconnect-log=none", file=sys.stderr, flush=True)
            return
        print("ssh-disconnect-log=observed", file=sys.stderr, flush=True)
        for line in evidence[-5:]:
            print(f"sshd-filtered: {_sanitize(line)}", file=sys.stderr, flush=True)

    def stop_pid(self, identity: ProcessIdentity | None, label: str) -> None:
        if identity is None or identity.pid <= 1:
            return
        completed = self.process_identity_action(
            "stop", identity, signum=signal.SIGTERM
        )
        if completed.returncode in (0, 2):
            return
        if completed.returncode == 3:
            self.cleanup_errors.append(
                f"refused to signal {label}: tracked process identity changed"
            )
        else:
            self.cleanup_errors.append(
                f"could not stop {label} through its validated pidfd"
            )

    def path_exists(self, path: Path) -> bool:
        # The state directory lives under the target home, which the caller
        # must not be able to traverse. Use a root check so PermissionError is
        # never mistaken for "exists".
        try:
            completed = self.run_root(
                ["/bin/sh", "-c", 'test -e "$1"', "sh", str(path)],
                timeout=10,
            )
        except HarnessError:
            return False
        return completed.returncode == 0

    def kill_all_user_processes(self) -> None:
        if self.uid is None:
            return
        completed = self.run_root(
            [sys.executable, "-c", _PIDFD_HELPER, "kill-uid", str(self.uid)],
            timeout=15,
        )
        if completed.returncode != 0:
            raise HarnessError(
                "could not safely terminate every disposable-user process through pidfds"
            )
        time.sleep(0.2)

    def wait_popen_exit_without_reaping(
        self, process: subprocess.Popen[bytes], timeout: float
    ) -> bool:
        """Wait on a direct child's pidfd while retaining its process-group ID."""
        if process.returncode is not None:
            return True
        try:
            pidfd = os.pidfd_open(process.pid, 0)
        except OSError:
            return False
        try:
            poller = select.poll()
            poller.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
            return bool(poller.poll(max(0, int(timeout * 1000))))
        finally:
            os.close(pidfd)

    def signal_popen_group(
        self, process: subprocess.Popen[bytes], signum: int
    ) -> bool:
        # Both launchers use start_new_session=True. Their unreaped Popen child
        # is therefore the session/process-group leader, which pins its PGID
        # against reuse until these scoped signals finish. Do not call poll or
        # wait until after the group has been signaled.
        if process.returncode is not None:
            return False
        completed = self.run_root(
            [
                sys.executable,
                "-c",
                _PIDFD_HELPER,
                "group-signal",
                str(process.pid),
                str(signum),
            ],
            timeout=10,
        )
        return completed.returncode == 0

    def stop_popen_group(
        self, process: subprocess.Popen[bytes] | None, label: str
    ) -> None:
        if process is None:
            return
        if process.returncode is not None:
            # The direct child has already been reaped, so its numeric PGID is
            # no longer a safe handle. Other tracked daemons and disposable-UID
            # processes are still stopped separately via pidfds.
            return
        try:
            if not self.signal_popen_group(process, signal.SIGTERM):
                raise HarnessError("could not signal the pinned launcher process group")
            # pidfd polling does not reap the group leader, so its PID/PGID
            # remains reserved even if it exits before the grace period.
            self.wait_popen_exit_without_reaping(process, 2.0)
            if not self.signal_popen_group(process, signal.SIGKILL):
                raise HarnessError("could not force-stop the pinned launcher process group")
        except HarnessError as error:
            self.cleanup_errors.append(f"could not stop {label} process scope: {error}")
            try:
                process.terminate()
            except OSError:
                pass
        try:
            process.wait(timeout=2)
        except (OSError, subprocess.TimeoutExpired):
            try:
                process.kill()
                process.wait(timeout=2)
            except (OSError, subprocess.TimeoutExpired):
                self.cleanup_errors.append(f"could not stop {label} launcher")

    def cleanup(self) -> None:
        # Stop the known fixture processes before deleting the account. Every
        # step is independently bounded and recorded so one failed sudo call
        # cannot skip the remaining cleanup.
        try:
            if self.sshd_identity is None and self.work is not None:
                if self.sshd_pid is None:
                    text = self.read_root(self.work / "sshd.pid").decode(
                        "ascii", "replace"
                    ).strip()
                    if text.isdigit():
                        self.sshd_pid = int(text)
                if self.sshd_pid is not None:
                    config = self.work / "sshd_config"
                    self.sshd_identity = self.capture_process_identity(
                        self.sshd_pid,
                        uid=0,
                        marker=str(config),
                        label="disposable sshd",
                    )
        except HarnessError as error:
            self.cleanup_errors.append(f"could not validate sshd cleanup identity: {error}")
        try:
            self.stop_pid(self.sshd_identity, "sshd")
        except HarnessError as error:
            self.cleanup_errors.append(f"sshd cleanup: {error}")
        self.stop_popen_group(self.sshd_launcher, "sshd")

        try:
            self.stop_pid(self.keyring_identity, "keyring")
        except HarnessError as error:
            self.cleanup_errors.append(f"keyring cleanup: {error}")
        self.stop_popen_group(self.keyring_wrapper, "keyring")

        try:
            self.stop_pid(self.bus_identity, "dbus-daemon")
        except HarnessError as error:
            self.cleanup_errors.append(f"dbus cleanup: {error}")
        try:
            self.kill_all_user_processes()
        except HarnessError as error:
            self.cleanup_errors.append(f"user process cleanup: {error}")

        if self.keyring_password_file is not None:
            try:
                self.discard_secret_file(self.keyring_password_file)
            except HarnessError as error:
                self.cleanup_errors.append(
                    f"could not discard Secret Service startup password: {error}"
                )
        for path in (self.state,):
            if path is not None:
                self.safe_remove(path, as_root=True)
        for path in (self.auth_dir, self.app_dir, self.work):
            if path is not None:
                self.safe_remove(path, as_root=False)

        if self.created_user and self.user is not None:
            try:
                completed = self.run_root(
                    [self.tools["userdel"], "-r", self.user],
                    timeout=30,
                )
                if completed.returncode != 0:
                    self.run_root(
                        [self.tools["userdel"], "-f", "-r", self.user],
                        timeout=30,
                    )
            except HarnessError as error:
                self.cleanup_errors.append(f"userdel: {error}")
            try:
                pwd.getpwnam(self.user)
            except KeyError:
                self.created_user = False
            else:
                self.cleanup_errors.append("disposable user still exists after userdel")

        # The wallet password is no longer needed once the session has ended.
        for index in range(len(self.wallet_password)):
            self.wallet_password[index] = 0

    def safe_remove(self, path: Path, *, as_root: bool) -> None:
        try:
            if as_root:
                completed = self.run_root(
                    ["rm", "-rf", "--", str(path)], timeout=20
                )
                if completed.returncode != 0:
                    raise HarnessError("root cleanup command failed")
            else:
                shutil.rmtree(path)
            if self.path_exists(path):
                raise HarnessError("path remains after cleanup")
        except (OSError, HarnessError):
            self.cleanup_errors.append(f"could not remove {path}")

    # ------------------------------------------------------------------
    # Main
    # ------------------------------------------------------------------

    def run_lifecycle(self) -> None:
        _check_cancelled()
        self.work = Path(
            tempfile.mkdtemp(
                prefix="astatine-ssh-lifecycle-",
                dir=os.environ.get("RUNNER_TEMP") or tempfile.gettempdir(),
            )
        )
        os.chmod(self.work, 0o700)

        self.create_user()
        self.create_state()
        self.start_bus()
        self.start_keyring()
        self.write_env_file()
        self.prepare_app()
        self.prepare_ssh()
        self.wait_ssh_ready()

        self.session_a()
        assert self.state is not None
        self.journal_path = (
            self.state / "config" / "astatine" / "transactions" / "journal.json"
        )
        self.journal_initial = self.hash_journal()

        self.session_b()
        self.session_c()
        self.session_d()

        if self.hash_journal() != self.journal_initial:
            raise HarnessError("authenticated journal bytes changed during the lifecycle")
        print("journal-consistent=ok", flush=True)


def main(argv: list[str]) -> int:
    global _SIGNAL_REQUESTED, _CLEANUP_IN_PROGRESS

    if len(argv) != 2:
        print(
            "usage: support/linux/ssh-application-lifecycle.py "
            "path/to/target/debug/astatine",
            file=sys.stderr,
        )
        return 2
    app_source = Path(argv[1]).expanduser()
    if not app_source.is_file():
        print(f"ssh-lifecycle: application executable is missing: {app_source}", file=sys.stderr)
        return 2

    _SIGNAL_REQUESTED = None
    _CLEANUP_IN_PROGRESS = False
    for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(signum, _record_signal)

    harness: Harness | None = None
    result = 1
    try:
        _check_cancelled()
        _preflight()
        _check_cancelled()
        harness = Harness(app_source.resolve())
        harness.run_lifecycle()
        _check_cancelled()
        harness.success = True
        result = 0
    except HarnessCancelled as error:
        result = 128 + error.signum
    except HarnessError as error:
        print(f"ssh-lifecycle: {_sanitize(str(error))}", file=sys.stderr)
        result = 1
    except KeyboardInterrupt:
        print("ssh-lifecycle: interrupted", file=sys.stderr)
        result = 130
    except BaseException as error:  # pragma: no cover - safety boundary
        print(
            f"ssh-lifecycle: unexpected failure: {type(error).__name__}: "
            f"{_sanitize(str(error))}",
            file=sys.stderr,
        )
        result = 1
    finally:
        # Signal handlers only record requests; setting this flag before any
        # cleanup work makes cooperative cancellation checks inert throughout
        # cleanup. Repeated TERM/HUP/INT signals cannot raise through cleanup.
        _protect_cleanup_from_signals()
        if harness is not None:
            try:
                harness.cleanup()
            except BaseException as error:  # pragma: no cover - cleanup boundary
                harness.cleanup_errors.append(
                    f"unexpected cleanup failure: {type(error).__name__}: {error}"
                )
            finally:
                for index in range(len(harness.wallet_password)):
                    harness.wallet_password[index] = 0
            if harness.cleanup_errors:
                for error in harness.cleanup_errors:
                    print(f"ssh-lifecycle: cleanup: {_sanitize(error)}", file=sys.stderr)
                result = 1
        if _SIGNAL_REQUESTED is not None:
            try:
                name = signal.Signals(_SIGNAL_REQUESTED).name
            except ValueError:
                name = f"signal {_SIGNAL_REQUESTED}"
            print(f"ssh-lifecycle: interrupted by {name}", file=sys.stderr)
            if not (harness and harness.cleanup_errors):
                result = 128 + _SIGNAL_REQUESTED

    return result


if __name__ == "__main__":
    sys.exit(main(sys.argv))
