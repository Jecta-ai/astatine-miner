#!/usr/bin/env python3
"""Qualify production-created journal and native Secret Service checkpoint.

Run this only through the disposable private-session harness:

    bash support/linux/run-private-session.sh provider -- \
        python3 support/linux/qualify-production-journal.py target/debug/astatine

The harness supplies an isolated private D-Bus session, HOME/XDG/TMPDIR, and an
unlocked disposable GNOME Keyring, and exports
ASTATINE_DISPOSABLE_CREDENTIAL_STORE=1 and
ASTATINE_QUALIFICATION_MODE=provider. This script refuses to run without those
markers, outside Linux, or unless the D-Bus socket and private HOME/XDG layout
match the wrapper's owned mode-0700 temporary directory. Caller-supplied markers
and an arbitrary unix D-Bus address are not sufficient.

The production executable itself creates the journal and checkpoint during a
real interactive `init`; no test backend, checkpoint bridge, seeded journal, or
fabricated checkpoint is used. A v10 authenticated journal cannot be inspected
without reading its matching OS credential-store entry, so successful production
`recover` processes establish native checkpoint presence. The copied-root
negative control establishes that the checkpoint lookup is scoped by the
canonical data-root identity.

Secrets are generated or emitted only in memory. The generated mnemonic and the
keystore password are never written to disk, stdout, stderr, or the report. PTY
output is kept in memory and is never dumped; diagnostics report only bounded,
script-authored reasons and child exit statuses.
"""

from __future__ import annotations

import errno
import fcntl
import json
import os
import pty
import re
import secrets
import select
import shutil
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import termios
import time
import urllib.parse

PROMPT_TIMEOUT_SECONDS = 45.0
PROCESS_TIMEOUT_SECONDS = 120.0
RECOVER_TIMEOUT_SECONDS = 60.0
MAX_CHILD_OUTPUT_BYTES = 8 * 1024 * 1024
UNRESOLVED_STATUSES = {"prepared", "broadcast", "unknown", "included"}

INIT_SPENDING_LIMIT_01 = "0.1"
INIT_SPENDING_LIMIT_02 = "0.2"


def _init_args(spending_limit: str) -> list[str]:
    """Return the exact production init invocation for one spending ceiling."""
    return [
        "init",
        "--network",
        "testnet",
        "--threads",
        "1",
        "--minimum-reserve-inj",
        "1",
        "--spending-limit-inj",
        spending_limit,
        "--per-run-sessions",
        "--rpc",
        "default",
        "--confirmation-blocks",
        "1",
    ]


_ANSI_ESCAPE = re.compile(
    r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\)|[@-_])"
)
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


class QualificationError(RuntimeError):
    """A sanitized qualification failure safe to print."""


def _require(condition: object, reason: str) -> None:
    if not condition:
        raise QualificationError(reason)


def _normalize(text: str) -> str:
    """Collapse terminal output so prompt matching tolerates wrapping."""
    text = _ANSI_ESCAPE.sub("", text)
    text = text.replace("\r", "\n").replace("\b", "")
    text = _CONTROL.sub("", text)
    return " ".join(text.split())


def _describe_status(status: int) -> str:
    if os.WIFSIGNALED(status):
        return f"signal {os.WTERMSIG(status)}"
    if os.WIFEXITED(status):
        return f"exit {os.WEXITSTATUS(status)}"
    return f"wait status {status}"


def _assert_private_mode(path: str, expected: int, label: str, directory: bool) -> None:
    metadata = os.lstat(path)
    _require(not stat.S_ISLNK(metadata.st_mode), f"{label} is a symlink")
    if directory:
        _require(stat.S_ISDIR(metadata.st_mode), f"{label} is not a directory")
    else:
        _require(stat.S_ISREG(metadata.st_mode), f"{label} is not a regular file")
    actual = stat.S_IMODE(metadata.st_mode)
    _require(
        actual == expected,
        f"{label} mode is {actual:03o}, expected {expected:03o}",
    )


def _read_bytes(path: str) -> bytes:
    with open(path, "rb") as handle:
        return handle.read()


def _read_text(path: str) -> str:
    return _read_bytes(path).decode("utf-8")


def _config_spending_limit(path: str) -> str:
    text = _read_text(path)
    match = re.search(
        r'^\s*per_session_spending_limit_inj\s*=\s*"([^"]*)"\s*$',
        text,
        re.MULTILINE,
    )
    _require(match is not None, "config.toml has no spending-limit field")
    return match.group(1)


class InteractiveProcess:
    """A production child attached to a private real PTY."""

    def __init__(self, argv: list[str], env: dict[str, str], cwd: str) -> None:
        self.buffer = bytearray()
        self.eof = False
        self.status: int | None = None
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            try:
                os.chdir(cwd)
                os.execvpe(argv[0], argv, env)
            except BaseException:
                os._exit(127)
        os.set_blocking(self.fd, False)
        try:
            fcntl.ioctl(
                self.fd,
                termios.TIOCSWINSZ,
                struct.pack("HHHH", 40, 120, 0, 0),
            )
        except OSError:
            pass

    def _poll_exit(self) -> int | None:
        if self.status is not None:
            return self.status
        try:
            pid, status = os.waitpid(self.pid, os.WNOHANG)
        except ChildProcessError:
            self.status = 0
            return self.status
        if pid == self.pid:
            self.status = status
        return self.status

    def _read_once(self, timeout: float) -> bool:
        if self.fd < 0:
            return False
        try:
            ready, _, _ = select.select([self.fd], [], [], timeout)
        except InterruptedError:
            return False
        if not ready:
            return False
        try:
            chunk = os.read(self.fd, 65536)
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
        _require(
            len(self.buffer) <= MAX_CHILD_OUTPUT_BYTES,
            "child terminal output exceeded its bounded buffer",
        )
        return True

    def _drain(self) -> None:
        while self._read_once(0):
            pass

    def _normalized_output(self) -> str:
        return _normalize(self.buffer.decode("utf-8", "replace"))

    def expect_any(self, patterns: list[str], timeout: float, stage: str) -> int:
        needles = [_normalize(pattern) for pattern in patterns]
        deadline = time.monotonic() + timeout
        while True:
            text = self._normalized_output()
            for index, needle in enumerate(needles):
                if needle in text:
                    return index
            if self._poll_exit() is not None:
                self._drain()
                text = self._normalized_output()
                for index, needle in enumerate(needles):
                    if needle in text:
                        return index
                raise QualificationError(
                    f"{stage} ended with {_describe_status(self.status)} "
                    "before the expected prompt"
                )
            if self.eof:
                raise QualificationError(
                    f"{stage} closed its terminal before the expected prompt"
                )
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise QualificationError(
                    f"{stage} timed out waiting for an expected prompt"
                )
            self._read_once(min(0.2, remaining))

    def _write_all(self, data: bytes) -> None:
        view = memoryview(data)
        deadline = time.monotonic() + PROMPT_TIMEOUT_SECONDS
        while view:
            try:
                written = os.write(self.fd, view)
            except BlockingIOError:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise QualificationError("timed out writing to the child PTY")
                select.select([], [self.fd], [], min(0.2, remaining))
                continue
            except OSError as error:
                if error.errno == errno.EIO:
                    raise QualificationError("child PTY closed before input completed")
                raise
            if written <= 0:
                raise QualificationError("child PTY accepted no input bytes")
            view = view[written:]

    def send_line(self, value: str) -> None:
        self._write_all(value.encode("utf-8") + b"\n")

    def send_secret_line(self, value: bytearray) -> None:
        self._write_all(bytes(value) + b"\n")

    def kill(self, signum: int = signal.SIGKILL) -> None:
        if self.status is None and self.pid > 0:
            try:
                os.kill(self.pid, signum)
            except ProcessLookupError:
                pass

    def wait_for_exit(self, timeout: float) -> int:
        deadline = time.monotonic() + timeout
        while True:
            if self._poll_exit() is not None:
                quiet_deadline = time.monotonic() + 1.0
                while not self.eof and time.monotonic() < quiet_deadline:
                    if not self._read_once(0.05):
                        break
                self._close_master()
                return self.status
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self.kill()
                raise QualificationError(
                    "production child did not exit within the bounded timeout"
                )
            self._read_once(min(0.2, remaining))

    def _close_master(self) -> None:
        if self.fd >= 0:
            try:
                os.close(self.fd)
            except OSError:
                pass
            self.fd = -1

    def cleanup(self) -> None:
        try:
            if self.status is None and self.pid > 0:
                self.kill()
                deadline = time.monotonic() + 5.0
                while self.status is None and time.monotonic() < deadline:
                    if self._poll_exit() is None:
                        self._read_once(0.05)
        except OSError:
            pass
        finally:
            self._close_master()
            if self.buffer:
                self.buffer[:] = b"\x00" * len(self.buffer)
                self.buffer.clear()


class Qualification:
    def __init__(self, binary: str) -> None:
        self.binary = os.path.abspath(binary)
        self.repo_root = os.path.dirname(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        )
        self.processes: list[InteractiveProcess] = []
        tmp_parent = os.environ.get("TMPDIR", "")
        _require(
            bool(tmp_parent) and os.path.isdir(tmp_parent),
            "refusing to run without a usable private TMPDIR",
        )
        # Keep the private socket pathname short enough for sockaddr_un.
        self.tmp = os.path.realpath(
            tempfile.mkdtemp(prefix="astatine-pj.", dir=tmp_parent)
        )
        try:
            self._prepare_private_layout()
        except BaseException:
            shutil.rmtree(self.tmp, ignore_errors=True)
            raise

    def _prepare_private_layout(self) -> None:
        os.chmod(self.tmp, 0o700)

        self.config_home = os.path.join(self.tmp, "config")
        self.home = os.path.join(self.tmp, "home")
        self.copied_config_home = os.path.join(self.tmp, "copied-config")
        self.runtime = os.path.join(self.tmp, "runtime")
        for directory in (
            self.config_home,
            self.home,
            self.copied_config_home,
            self.runtime,
            os.path.join(self.home, ".local", "share"),
            os.path.join(self.home, ".cache"),
        ):
            os.makedirs(directory, mode=0o700)
            os.chmod(directory, 0o700)

        self.root = os.path.join(self.config_home, "astatine")
        self.copied_root = os.path.join(self.copied_config_home, "astatine")
        self.unavailable_socket = os.path.join(self.tmp, "u.sock")

        self.env = os.environ.copy()
        self.env["HOME"] = self.home
        self.env["XDG_CONFIG_HOME"] = self.config_home
        self.env["XDG_DATA_HOME"] = os.path.join(self.home, ".local", "share")
        self.env["XDG_CACHE_HOME"] = os.path.join(self.home, ".cache")
        self.env["XDG_RUNTIME_DIR"] = self.runtime
        self.env["TMPDIR"] = self.tmp

        _require(
            os.path.isfile(self.binary) and os.access(self.binary, os.X_OK),
            "the production executable is missing or not executable",
        )
        _assert_private_mode(self.tmp, 0o700, "temporary root", directory=True)
        _assert_private_mode(self.home, 0o700, "HOME", directory=True)
        _assert_private_mode(
            self.config_home, 0o700, "XDG_CONFIG_HOME", directory=True
        )

    def _spawn(self, args: list[str]) -> InteractiveProcess:
        process = InteractiveProcess(
            [self.binary, *args],
            self.env,
            self.repo_root,
        )
        self.processes.append(process)
        return process

    def _run(self, args: list[str], env: dict[str, str], stage: str) -> subprocess.CompletedProcess:
        try:
            return subprocess.run(
                [self.binary, *args],
                cwd=self.repo_root,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=RECOVER_TIMEOUT_SECONDS,
                check=False,
            )
        except subprocess.TimeoutExpired:
            raise QualificationError(
                f"{stage} timed out within the bounded timeout"
            ) from None

    @staticmethod
    def _require_success(result: subprocess.CompletedProcess, stage: str) -> None:
        _require(
            result.returncode == 0,
            f"{stage} exited with status {result.returncode}",
        )

    def run_initial_init(self) -> None:
        password = bytearray(secrets.token_urlsafe(18).encode("ascii"))
        _require(len(password) >= 12, "generated keystore password is too short")
        process = self._spawn(_init_args(INIT_SPENDING_LIMIT_01))
        try:
            process.expect_any(
                ["Choose 1, 2, or 3"],
                PROMPT_TIMEOUT_SECONDS,
                "production init wallet selection",
            )
            process.send_line("1")

            process.expect_any(
                ["Type BACKED UP"],
                PROMPT_TIMEOUT_SECONDS,
                "production init recovery-phrase confirmation",
            )
            process.send_line("BACKED UP")

            process.expect_any(
                ["Create keystore password"],
                PROMPT_TIMEOUT_SECONDS,
                "production init keystore password creation",
            )
            process.send_secret_line(password)

            process.expect_any(
                ["Confirm keystore password"],
                PROMPT_TIMEOUT_SECONDS,
                "production init keystore password confirmation",
            )
            process.send_secret_line(password)
            _require(
                bytes(password) not in process.buffer,
                "hidden keystore prompt echoed the generated password",
            )

            process.expect_any(
                [
                    "Use the selected wallet for future per-run spending sessions?"
                ],
                PROMPT_TIMEOUT_SECONDS,
                "production init per-run wallet approval",
            )
            process.send_line("y")

            process.expect_any(
                [
                    "Persist and approve this per-run policy for the selected "
                    "wallet and network?"
                ],
                PROMPT_TIMEOUT_SECONDS,
                "production init per-run policy approval",
            )
            process.send_line("y")

            status = process.wait_for_exit(PROCESS_TIMEOUT_SECONDS)
            _require(
                os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0,
                f"production init ended with {_describe_status(status)}",
            )
        finally:
            password[:] = b"\x00" * len(password)
            process.cleanup()

    def assert_production_layout_and_journal(self) -> bytes:
        _assert_private_mode(self.root, 0o700, "data root", directory=True)
        transaction_dir = os.path.join(self.root, "transactions")
        wallet_dir = os.path.join(self.root, "wallets")
        config_path = os.path.join(self.root, "config.toml")
        journal_path = os.path.join(transaction_dir, "journal.json")
        lock_path = os.path.join(transaction_dir, "miner.lock")

        _assert_private_mode(
            transaction_dir, 0o700, "transactions directory", directory=True
        )
        _assert_private_mode(wallet_dir, 0o700, "wallet directory", directory=True)
        _assert_private_mode(
            config_path, 0o600, "config.toml", directory=False
        )
        _assert_private_mode(
            journal_path, 0o600, "transactions/journal.json", directory=False
        )
        _assert_private_mode(
            lock_path, 0o600, "transactions/miner.lock", directory=False
        )

        keystores = sorted(
            entry.path
            for entry in os.scandir(wallet_dir)
            if entry.is_file(follow_symlinks=False) and entry.name.endswith(".json")
        )
        _require(
            len(keystores) == 1,
            f"expected one wallet keystore, found {len(keystores)}",
        )
        _assert_private_mode(
            keystores[0], 0o600, "wallet keystore", directory=False
        )

        journal_bytes = _read_bytes(journal_path)
        try:
            document = json.loads(journal_bytes)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise QualificationError(
                f"production journal is not valid JSON ({type(error).__name__})"
            ) from None
        _require(isinstance(document, dict), "production journal is not an object")
        _require(
            document.get("version") == 10,
            "production journal is not schema version 10",
        )
        _require(
            isinstance(document.get("per_run_policy_approval"), dict),
            "production journal has no per-run policy approval",
        )
        integrity = document.get("integrity")
        _require(isinstance(integrity, dict), "production journal has no integrity record")
        revision = integrity.get("revision")
        _require(
            isinstance(revision, int) and revision > 0,
            "production journal has an invalid authenticated revision",
        )
        tag = integrity.get("tag")
        _require(
            isinstance(tag, str)
            and len(tag) == 64
            and all(character in "0123456789abcdef" for character in tag),
            "production journal has no valid authentication tag",
        )
        entries = document.get("entries", [])
        _require(isinstance(entries, list), "production journal entries are invalid")
        unresolved = [
            entry
            for entry in entries
            if isinstance(entry, dict) and entry.get("status") in UNRESOLVED_STATUSES
        ]
        _require(not unresolved, "production journal contains an unresolved transaction")
        _require(
            document.get("pending_authorization") is None,
            "production journal contains a pending signing authorization",
        )
        _require(
            document.get("pending_session_transition") is None,
            "production journal contains a pending session transition",
        )
        _require(
            _config_spending_limit(config_path) == INIT_SPENDING_LIMIT_01,
            "production config did not persist the requested 0.1 INJ limit",
        )
        return journal_bytes

    def recover_once(self, stage: str, env: dict[str, str] | None = None) -> None:
        result = self._run(["recover"], env or self.env, stage)
        self._require_success(result, stage)
        _require(
            b"No unresolved transaction remains." in result.stdout,
            f"{stage} did not report a fully authenticated journal",
        )

    def copied_root_fail_closed(self) -> None:
        shutil.copytree(self.root, self.copied_root)
        os.chmod(self.copied_root, 0o700)
        _assert_private_mode(
            self.copied_root, 0o700, "copied data root", directory=True
        )
        copied_env = self.env.copy()
        copied_env["XDG_CONFIG_HOME"] = self.copied_config_home
        result = self._run(
            ["recover"],
            copied_env,
            "copied data-root recovery",
        )
        _require(
            result.returncode != 0,
            "copied data root was accepted without its own checkpoint",
        )
        _require(
            b"has no OS credential-store checkpoint" in result.stderr,
            "copied data root did not fail with the missing-checkpoint reason",
        )

    def interrupted_init_is_recoverable(self) -> None:
        config_path = os.path.join(self.root, "config.toml")
        journal_path = os.path.join(self.root, "transactions", "journal.json")
        journal_before = _read_bytes(journal_path)
        process = self._spawn(_init_args(INIT_SPENDING_LIMIT_02))
        try:
            first = process.expect_any(
                [
                    "Keep the selected wallet?",
                    "Use the selected wallet for future per-run spending sessions?",
                    "Persist and approve this per-run policy for the selected "
                    "wallet and network?",
                    "ASTATINE PER-RUN SPENDING POLICY",
                ],
                PROMPT_TIMEOUT_SECONDS,
                "interrupted production init",
            )
            if first == 0:
                process.send_line("y")
                process.expect_any(
                    [
                        "Use the selected wallet for future per-run spending sessions?",
                        "Persist and approve this per-run policy for the selected "
                        "wallet and network?",
                        "ASTATINE PER-RUN SPENDING POLICY",
                    ],
                    PROMPT_TIMEOUT_SECONDS,
                    "interrupted production init policy boundary",
                )
            # This is an interruption at a real, user-visible init boundary:
            # the child is blocked on per-run wallet or policy consent before
            # set_per_run_policy_approval and config save. It is not a crash
            # injected inside a journal write.
            process.kill(signal.SIGKILL)
            status = process.wait_for_exit(10.0)
        finally:
            process.cleanup()
        _require(
            os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGKILL,
            "interrupted production init was not killed by SIGKILL",
        )

        self.recover_once("post-interruption production recover")
        _require(
            _config_spending_limit(config_path) == INIT_SPENDING_LIMIT_01,
            "interrupted production init partially committed the 0.2 INJ limit",
        )
        # `recover` authenticates the journal before it can report that no
        # transaction remains; it also rejects a pending init transition. This
        # keeps the assertion on production behavior rather than journal edits.
        _require(
            _read_bytes(journal_path) == journal_before,
            "interrupted production init changed the authenticated journal",
        )

    def unavailable_provider_fails_closed(self) -> None:
        journal_path = os.path.join(self.root, "transactions", "journal.json")
        journal_before = _read_bytes(journal_path)
        unavailable_env = self.env.copy()
        unavailable_env["DBUS_SESSION_BUS_ADDRESS"] = (
            "unix:path=" + self.unavailable_socket
        )
        unavailable_env.pop("ASTATINE_REQUIRE_NATIVE_CREDENTIAL_STORE", None)
        for name in (
            "DBUS_STARTER_ADDRESS",
            "DBUS_STARTER_BUS_TYPE",
            "GNOME_KEYRING_CONTROL",
            "GNOME_KEYRING_PID",
        ):
            unavailable_env.pop(name, None)
        result = self._run(
            ["recover"],
            unavailable_env,
            "unavailable-provider production recover",
        )
        _require(
            result.returncode != 0,
            "unavailable provider was accepted as authenticated",
        )
        stderr = result.stderr.decode("utf-8", "replace").lower()
        _require(
            "credential store" in stderr
            or "secret service" in stderr
            or "has no os credential-store checkpoint" in stderr,
            "unavailable provider did not fail closed on the native checkpoint",
        )
        _require(
            b"No unresolved transaction remains." not in result.stdout,
            "unavailable provider reported a successful recovery",
        )
        _require(
            _read_bytes(journal_path) == journal_before,
            "unavailable-provider recovery modified the journal",
        )

    def run(self) -> None:
        self.run_initial_init()
        self.assert_production_layout_and_journal()
        self.recover_once("first production recover")
        self.recover_once("second production recover process")
        self.copied_root_fail_closed()
        self.interrupted_init_is_recoverable()
        self.unavailable_provider_fails_closed()

    def cleanup(self) -> None:
        for process in reversed(self.processes):
            process.cleanup()
        shutil.rmtree(self.tmp, ignore_errors=True)


def _is_private_owned_directory(path: str) -> bool:
    try:
        metadata = os.lstat(path)
    except OSError:
        return False
    return (
        stat.S_ISDIR(metadata.st_mode)
        and metadata.st_uid == os.getuid()
        and stat.S_IMODE(metadata.st_mode) == 0o700
    )


def _is_harness_bus_address(address: str, bus_dir: str) -> bool:
    """Accept only the wrapper's single unix:path socket inside its private bus dir."""
    transports = address.split(";")
    if len(transports) != 1:
        return False
    transport, separator, raw_parameters = transports[0].partition(":")
    if not separator or transport != "unix":
        return False

    parameters: dict[str, str] = {}
    for raw_parameter in raw_parameters.split(","):
        key, separator, value = raw_parameter.partition("=")
        if not separator or key in parameters or key not in {"path", "guid"}:
            return False
        if re.search(r"%(?![0-9a-fA-F]{2})", value):
            return False
        parameters[key] = value
    if "path" not in parameters or set(parameters) not in (
        {"path"},
        {"path", "guid"},
    ):
        return False
    if "guid" in parameters and not re.fullmatch(
        r"[0-9a-fA-F]{32}", parameters["guid"]
    ):
        return False

    try:
        socket_path = os.fsdecode(
            urllib.parse.unquote_to_bytes(parameters["path"])
        )
        if (
            not os.path.isabs(socket_path)
            or os.path.normpath(socket_path) != socket_path
            or os.path.dirname(socket_path) != bus_dir
        ):
            return False
        metadata = os.lstat(socket_path)
    except (OSError, ValueError):
        return False
    return (
        stat.S_ISSOCK(metadata.st_mode)
        and metadata.st_uid == os.getuid()
        and os.path.realpath(socket_path) == socket_path
    )


def _require_private_harness_bus() -> None:
    tmp_dir = os.environ.get("TMPDIR", "")
    _require(
        bool(tmp_dir)
        and os.path.isabs(tmp_dir)
        and os.path.normpath(tmp_dir) == tmp_dir,
        "refusing without the private-session harness TMPDIR",
    )
    work_root = os.path.dirname(tmp_dir)
    _require(
        os.path.basename(work_root).startswith("astatine-linux-qualification."),
        "refusing outside the private-session harness directory layout",
    )
    _require(
        os.path.realpath(work_root) == work_root,
        "refusing through a symlinked private-session harness directory",
    )

    expected_environment = {
        "HOME": os.path.join(work_root, "home"),
        "XDG_CONFIG_HOME": os.path.join(work_root, "home", ".config"),
        "XDG_DATA_HOME": os.path.join(work_root, "home", ".local", "share"),
        "XDG_CACHE_HOME": os.path.join(work_root, "home", ".cache"),
        "XDG_RUNTIME_DIR": os.path.join(work_root, "runtime"),
        "TMPDIR": os.path.join(work_root, "tmp"),
    }
    for name, expected in expected_environment.items():
        _require(
            os.environ.get(name) == expected,
            "refusing without the private-session harness directory layout",
        )

    private_directories = {
        "private-session root": work_root,
        "private HOME": expected_environment["HOME"],
        "private configuration directory": expected_environment["XDG_CONFIG_HOME"],
        "private local data directory": os.path.join(work_root, "home", ".local"),
        "private data directory": expected_environment["XDG_DATA_HOME"],
        "private cache directory": expected_environment["XDG_CACHE_HOME"],
        "private runtime directory": expected_environment["XDG_RUNTIME_DIR"],
        "private temporary directory": expected_environment["TMPDIR"],
        "private bus directory": os.path.join(work_root, "bus"),
    }
    for label, path in private_directories.items():
        _require(
            _is_private_owned_directory(path),
            f"refusing because the {label} is not an owned 0700 directory",
        )

    for name in (
        "DBUS_STARTER_ADDRESS",
        "DBUS_STARTER_BUS_TYPE",
        "GNOME_KEYRING_CONTROL",
        "GNOME_KEYRING_PID",
        "SSH_AUTH_SOCK",
    ):
        _require(
            name not in os.environ,
            "refusing with ambient session-service environment present",
        )
    _require(
        os.environ.get("ASTATINE_REQUIRE_NATIVE_CREDENTIAL_STORE") == "1",
        "refusing without the provider-mode private-session harness marker",
    )
    _require(
        _is_harness_bus_address(
            os.environ.get("DBUS_SESSION_BUS_ADDRESS", ""),
            os.path.join(work_root, "bus"),
        ),
        "refusing unless D-Bus is the harness-owned private unix socket",
    )


def _require_environment() -> None:
    _require(sys.platform == "linux", "refusing to run outside Linux")
    _require(
        os.environ.get("ASTATINE_DISPOSABLE_CREDENTIAL_STORE") == "1",
        "refusing without ASTATINE_DISPOSABLE_CREDENTIAL_STORE=1",
    )
    _require(
        os.environ.get("ASTATINE_QUALIFICATION_MODE") == "provider",
        "refusing without ASTATINE_QUALIFICATION_MODE=provider",
    )
    _require_private_harness_bus()


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(
            "usage: qualify-production-journal.py <production-executable>",
            file=sys.stderr,
        )
        return 2
    qualification: Qualification | None = None
    try:
        _require_environment()
        qualification = Qualification(argv[1])
        qualification.run()
        print("production-init=ok")
        print("production-recover=ok")
        print("production-recover-second-process=ok")
        print("data-root-scope=fail-closed")
        print("interrupted-init-prompt=recoverable")
        print("unavailable-provider=fail-closed")
        print("root-mode=700 config-mode=600 journal-mode=600 keystore-mode=600")
        print("checkpoint=native-present")
        return 0
    except QualificationError as error:
        print(f"qualification failed: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("qualification interrupted", file=sys.stderr)
        return 130
    except Exception as error:  # noqa: BLE001 - deliberately sanitize diagnostics
        print(
            f"qualification failed: unexpected {type(error).__name__}",
            file=sys.stderr,
        )
        return 1
    finally:
        if qualification is not None:
            qualification.cleanup()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
