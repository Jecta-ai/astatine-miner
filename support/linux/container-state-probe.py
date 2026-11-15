#!/usr/bin/env python3
"""Validate and fingerprint only disposable production state in the container.

This emits hashes and boolean invariants, never wallet, journal, or keyring
contents. The caller keeps the hashes in memory and does not print or persist
them.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import sys
import tomllib
from pathlib import Path


ROOT = Path("/state/home/.config/astatine")
KEYRING_DIR = Path("/state/home/.local/share/keyrings")
UNRESOLVED_STATUSES = {"prepared", "broadcast", "unknown", "included"}


class StateError(RuntimeError):
    """A script-authored validation failure safe to report."""


def _require(condition: object, message: str) -> None:
    if not condition:
        raise StateError(message)


def _private_path(path: Path, expected_mode: int, *, directory: bool) -> None:
    try:
        metadata = os.lstat(path)
    except OSError:
        raise StateError("required private state is missing") from None
    _require(not stat.S_ISLNK(metadata.st_mode), "private state contains a symlink")
    if directory:
        _require(stat.S_ISDIR(metadata.st_mode), "private state directory is invalid")
    else:
        _require(stat.S_ISREG(metadata.st_mode), "private state file is invalid")
    _require(stat.S_IMODE(metadata.st_mode) == expected_mode, "private state mode is invalid")
    _require(metadata.st_uid == os.getuid(), "private state has an unexpected owner")


def _digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(64 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _single_file(directory: Path, suffix: str) -> Path:
    try:
        files = sorted(
            entry
            for entry in directory.iterdir()
            if entry.name.endswith(suffix)
            and not entry.is_symlink()
            and entry.is_file()
        )
    except OSError:
        raise StateError("private state directory could not be inspected") from None
    _require(len(files) == 1, "private state has an unexpected file count")
    return files[0]


def _keyring_fingerprint() -> tuple[int, str]:
    _private_path(KEYRING_DIR, 0o700, directory=True)
    try:
        files = sorted(
            entry
            for entry in KEYRING_DIR.iterdir()
            if entry.name.endswith(".keyring")
        )
    except OSError:
        raise StateError("private Secret Service storage could not be inspected") from None
    _require(bool(files), "private Secret Service has no persisted keyring file")
    digest = hashlib.sha256()
    for path in files:
        _private_path(path, 0o600, directory=False)
        digest.update(path.name.encode("utf-8"))
        digest.update(b"\x00")
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(64 * 1024), b""):
                digest.update(chunk)
        digest.update(b"\x00")
    return len(files), digest.hexdigest()


def inspect() -> dict[str, object]:
    _private_path(ROOT, 0o700, directory=True)
    transactions = ROOT / "transactions"
    wallets = ROOT / "wallets"
    config_path = ROOT / "config.toml"
    journal_path = transactions / "journal.json"
    lock_path = transactions / "miner.lock"
    for path in (transactions, wallets):
        _private_path(path, 0o700, directory=True)
    for path in (config_path, journal_path, lock_path):
        _private_path(path, 0o600, directory=False)

    try:
        config = tomllib.loads(config_path.read_text(encoding="utf-8"))
        journal_bytes = journal_path.read_bytes()
        journal = json.loads(journal_bytes)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, tomllib.TOMLDecodeError):
        raise StateError("production configuration or journal is invalid") from None

    _require(isinstance(journal, dict), "production journal is not an object")
    _require(journal.get("version") == 10, "production journal version is unexpected")
    approval = journal.get("per_run_policy_approval")
    _require(isinstance(approval, dict), "production journal has no per-run policy approval")
    integrity = journal.get("integrity")
    _require(isinstance(integrity, dict), "production journal has no integrity record")
    tag = integrity.get("tag")
    _require(
        isinstance(tag, str)
        and re.fullmatch(r"[0-9a-f]{64}", tag) is not None,
        "production journal has no valid authentication tag",
    )
    entries = journal.get("entries", [])
    _require(isinstance(entries, list), "production journal entries are invalid")
    unresolved = [
        item
        for item in entries
        if isinstance(item, dict) and item.get("status") in UNRESOLVED_STATUSES
    ]
    _require(not unresolved, "production journal has an unresolved transaction")
    _require(journal.get("pending_authorization") is None, "journal has pending authorization")
    _require(journal.get("pending_session_transition") is None, "journal has a pending transition")
    _require(
        config.get("per_session_spending_limit_inj") == "0.1",
        "production spending limit changed from the qualification value",
    )

    keystore_dir = wallets
    keystore = _single_file(keystore_dir, ".json")
    _private_path(keystore, 0o600, directory=False)
    keyring_count, keyring_digest = _keyring_fingerprint()
    return {
        "root_mode": 0o700,
        "config_mode": 0o600,
        "journal_mode": 0o600,
        "keystore_mode": 0o600,
        "config_sha256": _digest(config_path),
        "journal_sha256": _digest(journal_path),
        "keystore_sha256": _digest(keystore),
        "keystore_count": 1,
        "keyring_count": keyring_count,
        "keyring_sha256": keyring_digest,
        "spending_limit": config["per_session_spending_limit_inj"],
        "policy_approval_present": True,
        "unresolved_count": len(unresolved),
        "pending_authorization": False,
        "pending_session_transition": False,
    }


def main() -> int:
    try:
        result = inspect()
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except StateError as error:
        print(f"container-state-probe: {error}", file=sys.stderr)
        return 1
    except BaseException as error:  # sanitize the final diagnostic boundary
        print(f"container-state-probe: unexpected failure ({type(error).__name__})", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
