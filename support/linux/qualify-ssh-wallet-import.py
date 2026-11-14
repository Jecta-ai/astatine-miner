#!/usr/bin/env python3
"""Qualify production encrypted-wallet import over the existing loopback SSH fixture.

Usage:
    python3 support/linux/qualify-ssh-wallet-import.py target/debug/astatine

This reuses ssh-application-lifecycle.py for the disposable account, loopback
sshd, private D-Bus/keyring, and production-created synthetic source wallet. It
imports that encrypted keyfile into two fresh data roots through actual SSH PTYs;
the second import verifies that the first import's new password decrypts in a
fresh production process. No secret is written to a file, command argument,
command argument, environment variable, or diagnostic by the import driver;
wallet passwords are sent only through hidden terminal prompts. The reused
fixture retains its existing private-file handling for the disposable keyring
bootstrap password. No RPC is needed for wallet import.

This does not qualify a container restart followed by manual Secret Service
unlock. A headless SSH process cannot faithfully display the desktop unlock
dialog, and the reused fixture intentionally discards its keyring password.
"""

from __future__ import annotations

import importlib.util
import os
import re
import secrets
import shlex
import signal
import sys
from pathlib import Path
from types import ModuleType


def _load_lifecycle() -> ModuleType:
    path = Path(__file__).with_name("ssh-application-lifecycle.py")
    spec = importlib.util.spec_from_file_location(
        "astatine_ssh_application_lifecycle_phase_d", path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load the existing SSH lifecycle fixture")
    module = importlib.util.module_from_spec(spec)
    # dataclasses resolves the defining module through sys.modules at import time.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


LIFECYCLE = _load_lifecycle()
ADDRESS_FILE = re.compile(r"(0x[0-9a-f]{40})\.json\Z")
IMPORTED_ADDRESS = re.compile(
    rb"Encrypted Ethereum V3 wallet imported: (0x[0-9a-fA-F]{40})"
)


def _check_cancelled() -> None:
    LIFECYCLE._check_cancelled()


def _prepare_profile(harness: object, config_home: Path) -> None:
    _check_cancelled()
    result = harness.run_as_user(
        ["mkdir", "--", str(config_home)], timeout=15
    )
    if result.returncode != 0:
        raise LIFECYCLE.HarnessError("could not create the isolated wallet-import profile")
    result = harness.run_as_user(
        ["chmod", "700", "--", str(config_home)], timeout=15
    )
    if result.returncode != 0:
        raise LIFECYCLE.HarnessError("could not protect the wallet-import profile")


def _remote_app_command(
    harness: object,
    args: list[str],
    *,
    config_home: Path,
    timeout_seconds: int,
) -> str:
    if harness.app_path is None:
        raise LIFECYCLE.HarnessError("production executable is not prepared")
    lines = harness.remote_environment_lines()
    lines.append(f"export XDG_CONFIG_HOME={shlex.quote(str(config_home))}")
    command = [
        "timeout",
        "--signal=TERM",
        "--kill-after=5s",
        f"{timeout_seconds}s",
        str(harness.app_path),
        *args,
    ]
    lines.append("exec " + " ".join(shlex.quote(value) for value in command))
    return "\n".join(lines) + "\n"


def _single_keystore(harness: object, wallet_dir: Path) -> tuple[Path, str]:
    script = (
        "import pathlib, sys; "
        "root = pathlib.Path(sys.argv[1]); "
        "paths = sorted(p for p in root.glob('*.json') "
        "if p.is_file() and not p.is_symlink()); "
        "print('\\n'.join(str(p) for p in paths))"
    )
    result = harness.run_as_user(
        ["python3", "-c", script, str(wallet_dir)], timeout=15
    )
    if result.returncode != 0:
        raise LIFECYCLE.HarnessError("could not inspect the synthetic wallet directory")
    try:
        paths = result.stdout.decode("utf-8", "strict").splitlines()
    except UnicodeDecodeError as error:
        raise LIFECYCLE.HarnessError("wallet directory returned an invalid path") from error
    if len(paths) != 1:
        raise LIFECYCLE.HarnessError("expected exactly one synthetic wallet keyfile")
    path = Path(paths[0])
    if not path.is_absolute() or path.parent != wallet_dir:
        raise LIFECYCLE.HarnessError("synthetic wallet path escaped its private profile")
    match = ADDRESS_FILE.fullmatch(path.name)
    if match is None:
        raise LIFECYCLE.HarnessError("synthetic wallet keyfile has an unexpected name")
    return path, match.group(1)


def _assert_private_regular_file(harness: object, path: Path) -> None:
    script = (
        "import os, stat, sys; "
        "s = os.lstat(sys.argv[1]); "
        "sys.exit(0 if stat.S_ISREG(s.st_mode) and "
        "stat.S_IMODE(s.st_mode) == 0o600 else 1)"
    )
    result = harness.run_as_user(
        ["python3", "-c", script, str(path)], timeout=15
    )
    if result.returncode != 0:
        raise LIFECYCLE.HarnessError("imported keystore is not a private mode-0600 file")


def _import_keystore(
    harness: object,
    *,
    source: Path,
    source_password: bytearray,
    new_password: bytearray,
    config_home: Path,
    expected_address: str,
    stage: str,
) -> None:
    _check_cancelled()
    process = LIFECYCLE.PtyProcess()
    remote = _remote_app_command(
        harness,
        ["wallet", "import", "--keystore", str(source)],
        config_home=config_home,
        timeout_seconds=180,
    )
    process.start(
        [
            harness.tools["ssh"],
            *harness.ssh_options,
            "-tt",
            harness.ssh_target(),
            remote,
        ],
        harness.local_ssh_env(),
    )
    try:
        process.expect(
            b"Ethereum V3 keystore password (input hidden): ",
            LIFECYCLE.PROMPT_TIMEOUT,
        )
        process.send(bytes(source_password) + b"\n")
        process.expect(
            b"Create keystore password (input hidden; use at least 12 characters): ",
            LIFECYCLE.PROMPT_TIMEOUT,
        )
        process.send(bytes(new_password) + b"\n")
        process.expect(
            b"Confirm keystore password (input hidden): ",
            LIFECYCLE.PROMPT_TIMEOUT,
        )
        process.send(bytes(new_password) + b"\n")
        code, output = process.wait_exit(LIFECYCLE.EXIT_TIMEOUT)
    except BaseException:
        process.kill(signal.SIGKILL)
        process.wait_local_exit(5.0)
        process.close()
        raise
    process.close()

    for password in (source_password, new_password):
        if bytes(password) in output:
            raise LIFECYCLE.HarnessError(f"{stage} echoed a hidden password")
    if code != 0:
        raise LIFECYCLE.HarnessError(f"{stage} failed with exit status {code}")
    match = IMPORTED_ADDRESS.search(output)
    if match is None:
        raise LIFECYCLE.HarnessError(f"{stage} did not report a completed production import")
    address = match.group(1).decode("ascii").lower()
    if address != expected_address:
        raise LIFECYCLE.HarnessError(f"{stage} imported a different public wallet address")


def _verify_selected_address(
    harness: object, *, config_home: Path, expected_address: str
) -> None:
    _check_cancelled()
    completed = harness.ssh_no_pty(
        _remote_app_command(
            harness,
            ["wallet", "address"],
            config_home=config_home,
            timeout_seconds=30,
        ),
        timeout=45,
    )
    if completed.returncode != 0:
        raise LIFECYCLE.HarnessError("fresh production address process failed after import")
    expected = f"Wallet: {expected_address}".encode("ascii")
    if expected not in completed.stdout + completed.stderr:
        raise LIFECYCLE.HarnessError("fresh production process did not select the imported wallet")


def qualify_import(harness: object) -> None:
    if harness.state is None:
        raise LIFECYCLE.HarnessError("SSH lifecycle state is unavailable")
    if harness.wallet_password is None:
        raise LIFECYCLE.HarnessError("synthetic source wallet password is unavailable")

    source, address = _single_keystore(
        harness, harness.state / "config" / "astatine" / "wallets"
    )
    _assert_private_regular_file(harness, source)
    first_config = harness.state / "import-profile-one"
    second_config = harness.state / "import-profile-two"
    _prepare_profile(harness, first_config)
    _prepare_profile(harness, second_config)

    first_password = bytearray(secrets.token_urlsafe(24).encode("ascii"))
    second_password = bytearray(secrets.token_urlsafe(24).encode("ascii"))
    if (
        first_password == second_password
        or first_password == harness.wallet_password
        or second_password == harness.wallet_password
    ):
        first_password[:] = b"\x00" * len(first_password)
        second_password[:] = b"\x00" * len(second_password)
        raise LIFECYCLE.HarnessError("could not generate distinct synthetic wallet passwords")

    try:
        _import_keystore(
            harness,
            source=source,
            source_password=harness.wallet_password,
            new_password=first_password,
            config_home=first_config,
            expected_address=address,
            stage="first production SSH wallet import",
        )
        first_file, first_address = _single_keystore(
            harness, first_config / "astatine" / "wallets"
        )
        if first_address != address:
            raise LIFECYCLE.HarnessError("first imported keystore has a different address")
        _assert_private_regular_file(harness, first_file)
        _verify_selected_address(
            harness, config_home=first_config, expected_address=address
        )

        _import_keystore(
            harness,
            source=first_file,
            source_password=first_password,
            new_password=second_password,
            config_home=second_config,
            expected_address=address,
            stage="fresh-process password round-trip import",
        )
        second_file, second_address = _single_keystore(
            harness, second_config / "astatine" / "wallets"
        )
        if second_address != address:
            raise LIFECYCLE.HarnessError("round-trip imported keystore has a different address")
        _assert_private_regular_file(harness, second_file)
        _verify_selected_address(
            harness, config_home=second_config, expected_address=address
        )
    finally:
        first_password[:] = b"\x00" * len(first_password)
        second_password[:] = b"\x00" * len(second_password)


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(
            "usage: support/linux/qualify-ssh-wallet-import.py "
            "path/to/target/debug/astatine",
            file=sys.stderr,
        )
        return 2
    app_source = Path(argv[1]).expanduser()
    if not app_source.is_file() or not os.access(app_source, os.X_OK):
        print("ssh-wallet-import: production executable is missing or not executable", file=sys.stderr)
        return 2

    LIFECYCLE._SIGNAL_REQUESTED = None
    LIFECYCLE._CLEANUP_IN_PROGRESS = False
    for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(signum, LIFECYCLE._record_signal)

    harness = None
    result = 1
    try:
        _check_cancelled()
        LIFECYCLE._preflight()
        _check_cancelled()
        harness = LIFECYCLE.Harness(app_source.resolve())
        # Keep setup, SSH, provider, and source-wallet behavior in the existing
        # production lifecycle fixture instead of cloning its privileged code.
        harness.run_lifecycle()
        qualify_import(harness)
        _check_cancelled()
        print("ssh-wallet-import=ok", flush=True)
        print("ssh-wallet-import-first-password-round-trip=ok", flush=True)
        print("provider-restart-manual-unlock=not-tested", flush=True)
        harness.success = True
        result = 0
    except LIFECYCLE.HarnessCancelled as error:
        result = 128 + error.signum
    except LIFECYCLE.HarnessError as error:
        print(f"ssh-wallet-import: {LIFECYCLE._sanitize(str(error))}", file=sys.stderr)
        result = 1
    except KeyboardInterrupt:
        print("ssh-wallet-import: interrupted", file=sys.stderr)
        result = 130
    except BaseException as error:  # pragma: no cover - final safety boundary
        print(
            f"ssh-wallet-import: unexpected failure: {type(error).__name__}: "
            f"{LIFECYCLE._sanitize(str(error))}",
            file=sys.stderr,
        )
        result = 1
    finally:
        LIFECYCLE._protect_cleanup_from_signals()
        if harness is not None:
            try:
                harness.cleanup()
            except BaseException as error:  # pragma: no cover - cleanup boundary
                harness.cleanup_errors.append(
                    f"unexpected cleanup failure: {type(error).__name__}"
                )
            if harness.cleanup_errors:
                for error in harness.cleanup_errors:
                    print(
                        f"ssh-wallet-import: cleanup: {LIFECYCLE._sanitize(error)}",
                        file=sys.stderr,
                    )
                result = 1
        if LIFECYCLE._SIGNAL_REQUESTED is not None:
            try:
                name = signal.Signals(LIFECYCLE._SIGNAL_REQUESTED).name
            except ValueError:
                name = f"signal {LIFECYCLE._SIGNAL_REQUESTED}"
            print(f"ssh-wallet-import: interrupted by {name}", file=sys.stderr)
            result = 128 + LIFECYCLE._SIGNAL_REQUESTED
    return result


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
