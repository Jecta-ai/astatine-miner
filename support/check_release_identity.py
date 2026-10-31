#!/usr/bin/env python3
"""Keep exact repository identity pins aligned without accepting wildcards."""

from __future__ import annotations

import pathlib
import re


ROOT = pathlib.Path(__file__).resolve().parent.parent
REPOSITORY = (ROOT / "support/release-repository.txt").read_text(encoding="ascii").splitlines()
EXPECTED_REPOSITORY = "Jecta-ai/astatine-miner"
LEGACY_REPOSITORY = "emyrinj/astatine-miner"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def main() -> None:
    require(len(REPOSITORY) == 1, "release-repository.txt must contain exactly one line")
    repository = REPOSITORY[0]
    require(repository == EXPECTED_REPOSITORY, f"release repository identity must be {EXPECTED_REPOSITORY}")
    require(
        re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*", repository) is not None,
        "release identity must be an exact OWNER/REPOSITORY value",
    )
    require(
        'env!("ASTATINE_RELEASE_REPOSITORY")' in (ROOT / "src/update.rs").read_text(encoding="utf-8"),
        "Rust updater must compile the exact release identity from build.rs",
    )
    require(
        'support/release-repository.txt' in (ROOT / "build.rs").read_text(encoding="utf-8"),
        "build.rs must use the canonical release identity file",
    )
    for filename, expected in (
        ("support/install-unix.sh", f'REPOSITORY="{repository}"'),
        ("support/install-windows.ps1", f"$Repository = '{repository}'"),
        ("support/verify-public-install-windows.ps1", f"$Repository = '{repository}'"),
    ):
        contents = (ROOT / filename).read_text(encoding="utf-8")
        require(expected in contents, f"{filename} is not pinned to canonical release identity {repository}")
    active_identity_files = (
        "build.rs",
        ".github/workflows/ci.yml",
        "README.md",
        "support/OFFLINE_RELEASE_PROCESS.md",
        "support/install-unix.sh",
        "support/install-windows.ps1",
        "support/verify-public-install-windows.ps1",
        "support/offline_sign_release.py",
        "support/publish_signed_release.py",
        "support/release_public_key.py",
        "support/release-notes-v0.1.0-testnet.13.md",
        "support/release-notes-v0.1.0-testnet.9.md",
        "support/release-notes-v0.1.0-testnet.10.md",
        "support/release-notes-v0.1.0-testnet.11.md",
        "support/release-notes-v0.1.0-testnet.12.md",
    )
    for filename in active_identity_files:
        contents = (ROOT / filename).read_text(encoding="utf-8")
        require(LEGACY_REPOSITORY not in contents, f"{filename} retains the old repository identity")
    for filename in (
        "support/verify_release_provenance.py",
        "support/offline_sign_release.py",
        "support/publish_signed_release.py",
    ):
        contents = (ROOT / filename).read_text(encoding="utf-8")
        require("REPOSITORY" in contents and "release_artifacts" in contents, f"{filename} must use the canonical release identity")
    helper = (ROOT / "support/release_artifacts.py").read_text(encoding="utf-8")
    require('with_name("release-repository.txt")' in helper, "release validator must use the canonical exact repository identity")
    require(
        f'("legacy-repository", "{LEGACY_REPOSITORY}")' in helper,
        "release artifact tests must reject the old repository identity",
    )
    provenance = (ROOT / "support/verify_release_provenance.py").read_text(encoding="utf-8")
    require(
        f'(valid, "{LEGACY_REPOSITORY}"' in provenance,
        "provenance tests must reject attestations from the old repository",
    )
    updater = (ROOT / "src/update.rs").read_text(encoding="utf-8")
    require(
        f'repository={LEGACY_REPOSITORY}' in updater
        and 'assert!(parse_manifest(legacy_repository.as_bytes()).is_err())' in updater,
        "updater tests must reject manifests from the old repository",
    )
    release_notes = (ROOT / "support/release-notes-v0.1.0-testnet.13.md").read_text(encoding="utf-8")
    require("__RELEASE_REPOSITORY__" in release_notes, "Testnet.13 release notes must receive the canonical repository during publication")
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    require("$GITHUB_REPOSITORY" in workflow, "workflow provenance checks must bind the GitHub repository context")
    require("--repo " + LEGACY_REPOSITORY not in workflow, "workflow must not retain a stale hardcoded GitHub owner/repository")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    require(f"raw.githubusercontent.com/{repository}/" in readme, "README installer URLs differ from the canonical release identity")
    require("support/release-repository.txt" in readme, "README provenance command must use the canonical release identity")
    print(f"Release repository identity is exact and aligned: {repository}")


if __name__ == "__main__":
    main()
