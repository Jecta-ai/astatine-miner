#!/usr/bin/env python3
"""Private GNOME Keyring controller for the container lifecycle qualification.

The only secret-bearing operation is `unlock`. It requires an interactive
terminal, reads a test-only passphrase with terminal echo disabled, and sends it
only on the child daemon's stdin pipe. It never places the passphrase in argv,
the environment, a file, output, or a diagnostic.
"""

from __future__ import annotations

import getpass
import os
import re
import signal
import subprocess
import sys
import time
from collections.abc import Sequence


DBUS_ADDRESS = "unix:path=/run/astatine/bus"
DEFAULT_COLLECTION = re.compile(rb"objectpath '([^']*)'")
SERVICE_TIMEOUT_SECONDS = 30.0


class ServiceError(RuntimeError):
    """A safe, script-authored failure reason."""


def _require_private_environment() -> None:
    expected = {
        "HOME": "/state/home",
        "XDG_CONFIG_HOME": "/state/home/.config",
        "XDG_DATA_HOME": "/state/home/.local/share",
        "XDG_CACHE_HOME": "/state/home/.cache",
        "XDG_RUNTIME_DIR": "/run/astatine",
        "DBUS_SESSION_BUS_ADDRESS": DBUS_ADDRESS,
    }
    for name, value in expected.items():
        if os.environ.get(name) != value:
            raise ServiceError("refusing outside the private qualification container")
    for name in (
        "DBUS_STARTER_ADDRESS",
        "DBUS_STARTER_BUS_TYPE",
        "DBUS_SESSION_BUS_PID",
        "GNOME_KEYRING_CONTROL",
        "GNOME_KEYRING_PID",
        "SSH_AUTH_SOCK",
        "SSH_AGENT_PID",
    ):
        if name in os.environ:
            raise ServiceError("refusing with ambient session-service state")


def _gdbus(arguments: Sequence[str]) -> bytes:
    try:
        completed = subprocess.run(
            ["/usr/bin/gdbus", *arguments],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=8,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise ServiceError("private Secret Service query failed") from None
    if completed.returncode != 0:
        raise ServiceError("private Secret Service query failed")
    return completed.stdout


def _service_owned() -> bool:
    output = _gdbus(
        [
            "call",
            "--session",
            "--dest",
            "org.freedesktop.DBus",
            "--object-path",
            "/org/freedesktop/DBus",
            "--method",
            "org.freedesktop.DBus.NameHasOwner",
            "org.freedesktop.secrets",
        ]
    )
    return re.search(rb"\btrue\b", output) is not None


def _default_collection() -> str | None:
    output = _gdbus(
        [
            "call",
            "--session",
            "--dest",
            "org.freedesktop.secrets",
            "--object-path",
            "/org/freedesktop/secrets",
            "--method",
            "org.freedesktop.Secret.Service.ReadAlias",
            "default",
        ]
    )
    match = DEFAULT_COLLECTION.search(output)
    if match is None:
        raise ServiceError("private Secret Service returned an invalid default collection")
    path = match.group(1).decode("utf-8", "strict")
    return None if path == "/" else path


def _collection_locked(path: str) -> bool:
    output = _gdbus(
        [
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
        ]
    )
    if re.search(rb"\btrue\b", output):
        return True
    if re.search(rb"\bfalse\b", output):
        return False
    raise ServiceError("private Secret Service returned an invalid lock state")


def _spawn_daemon(*, keyring_input: bytearray | None) -> subprocess.Popen[bytes]:
    arguments = [
        "/usr/bin/gnome-keyring-daemon",
        "--components=secrets",
        "--foreground",
    ]
    if keyring_input is not None:
        arguments.append("--unlock")
    try:
        process = subprocess.Popen(
            arguments,
            stdin=subprocess.PIPE if keyring_input is not None else subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            start_new_session=True,
        )
    except OSError:
        raise ServiceError("could not start the private Secret Service") from None

    if keyring_input is not None:
        payload = bytearray(keyring_input)
        payload.append(0x0A)
        try:
            assert process.stdin is not None
            process.stdin.write(payload)
            process.stdin.flush()
            process.stdin.close()
        except (BrokenPipeError, OSError):
            _stop_child(process)
            raise ServiceError("the private Secret Service did not accept the unlock input") from None
        finally:
            payload[:] = b"\x00" * len(payload)
    return process


def _stop_child(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        process.send_signal(signal.SIGTERM)
        process.wait(timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        try:
            process.kill()
            process.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            pass


def _wait_for_collection(
    process: subprocess.Popen[bytes], *, expected_locked: bool
) -> None:
    deadline = time.monotonic() + SERVICE_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise ServiceError("private Secret Service exited during startup")
        try:
            if _service_owned():
                path = _default_collection()
                if path is not None and _collection_locked(path) is expected_locked:
                    return
        except ServiceError:
            pass
        time.sleep(0.1)
    raise ServiceError("private Secret Service did not reach the expected collection state")


def _start_locked() -> None:
    if _service_owned():
        raise ServiceError("refusing to replace an existing Secret Service")
    process = _spawn_daemon(keyring_input=None)
    try:
        _wait_for_collection(process, expected_locked=True)
    except BaseException:
        _stop_child(process)
        raise
    print("secret-service=locked")


def _unlock_manually() -> None:
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise ServiceError("manual unlock requires a real interactive terminal")
    if _service_owned():
        raise ServiceError("refusing to unlock while a Secret Service is already running")

    supplied = getpass.getpass(
        "Enter the test-only Secret Service passphrase (input hidden): "
    )
    if not supplied:
        raise ServiceError("an empty test-only passphrase is not accepted")
    keyring_input = bytearray()
    keyring_input.extend(supplied.encode("utf-8"))
    supplied = ""
    process: subprocess.Popen[bytes] | None = None
    try:
        process = _spawn_daemon(keyring_input=keyring_input)
        _wait_for_collection(process, expected_locked=False)
    except BaseException:
        if process is not None:
            _stop_child(process)
        raise
    finally:
        keyring_input[:] = b"\x00" * len(keyring_input)
    print("secret-service=unlocked")


def _status() -> None:
    if not _service_owned():
        print("secret-service=absent")
        return
    path = _default_collection()
    if path is None:
        print("secret-service=present default-collection=missing")
        return
    state = "locked" if _collection_locked(path) else "unlocked"
    print(f"secret-service={state}")


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[1] not in {"status", "start-locked", "unlock"}:
        print(
            "usage: container-secret-service.py {status|start-locked|unlock}",
            file=sys.stderr,
        )
        return 2
    try:
        _require_private_environment()
        if argv[1] == "status":
            _status()
        elif argv[1] == "start-locked":
            _start_locked()
        else:
            _unlock_manually()
        return 0
    except ServiceError as error:
        print(f"container-secret-service: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("container-secret-service: interrupted", file=sys.stderr)
        return 130
    except BaseException as error:  # sanitize the final diagnostic boundary
        print(
            f"container-secret-service: unexpected failure ({type(error).__name__})",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
