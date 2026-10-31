#!/usr/bin/env python3
"""Network preflight for a tag's unsigned release artifacts; never opens a key."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import subprocess
import tempfile
from datetime import datetime, timezone

from release_artifacts import REPOSITORY, TARGETS, LICENSES, parse_tag, sha256, validate_release


WORKFLOW = ".github/workflows/ci.yml"
UNSIGNED_FILES = {
    *(binary for binary, _ in TARGETS.values()),
    *(package for _, package in TARGETS.values()),
    *LICENSES,
    "update-manifest.txt",
}


class PreflightError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PreflightError(message)


def gh_json(arguments: list[str]) -> dict:
    result = subprocess.run(
        ["gh", *arguments],
        check=False,
        capture_output=True,
        text=True,
    )
    require(result.returncode == 0, f"GitHub CLI request failed: {result.stderr.strip()}")
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise PreflightError(f"GitHub CLI returned malformed JSON: {error}") from error
    require(isinstance(value, dict), "GitHub CLI response must be a JSON object")
    return value


def gh_success(arguments: list[str]) -> None:
    result = subprocess.run(
        ["gh", *arguments],
        check=False,
        capture_output=True,
        text=True,
    )
    require(result.returncode == 0, f"GitHub attestation verification failed: {result.stderr.strip()}")


def validate_local_source_checkout(repo_root: pathlib.Path, expected_commit: str) -> None:
    require(re.fullmatch(r"[0-9a-f]{40}", expected_commit) is not None, "source commit must be a full lowercase Git SHA")
    head = subprocess.run(
        ["git", "-C", str(repo_root), "rev-parse", "HEAD"],
        check=False,
        capture_output=True,
        text=True,
    )
    require(head.returncode == 0, f"cannot inspect local source checkout: {head.stderr.strip()}")
    require(head.stdout.strip() == expected_commit, "local source checkout HEAD differs from the selected release commit")
    status = subprocess.run(
        ["git", "-C", str(repo_root), "status", "--porcelain=v1", "--untracked-files=all"],
        check=False,
        capture_output=True,
        text=True,
    )
    require(status.returncode == 0, f"cannot inspect local source checkout status: {status.stderr.strip()}")
    require(not status.stdout, "local source checkout has uncommitted or untracked files")


def validate_run_context(run: dict, repository: str, tag: str, expected_commit: str) -> None:
    run_repository = run.get("repository")
    if isinstance(run_repository, dict):
        run_repository = run_repository.get("full_name")
    require(run_repository == repository, "source workflow run belongs to a different repository")
    require(run.get("conclusion") == "success", "source workflow run did not succeed")
    require(run.get("event") == "push", "source run must be an automatic tag push, not a manual/PR run")
    require(run.get("head_sha") == expected_commit, "source workflow run commit differs from the requested commit")
    require(run.get("head_branch") == tag, "source workflow run was not triggered by the requested tag")
    workflow_path = run.get("path")
    require(isinstance(workflow_path, str), "source workflow run has no workflow file identity")
    workflow_file, separator, workflow_ref = workflow_path.partition("@")
    require(workflow_file == WORKFLOW, "source workflow run was not executed by the pinned CI workflow")
    require(
        not separator or workflow_ref == f"refs/tags/{tag}",
        "source workflow run path does not identify the requested tag ref",
    )
    require(repository == REPOSITORY, "requested repository differs from the exact pinned release identity")
    require(tag == f"v{parse_tag(tag)}", "release tag is not canonical")
    require(re.fullmatch(r"[0-9a-f]{40}", expected_commit) is not None, "source commit must be a full lowercase Git SHA")


def resolve_tag_commit(repository: str, tag: str) -> str:
    reference = gh_json(["api", f"repos/{repository}/git/ref/tags/{tag}"])
    target = reference.get("object", {})
    for _ in range(4):
        object_type = target.get("type")
        object_sha = target.get("sha")
        require(isinstance(object_sha, str), "tag reference has no object SHA")
        if object_type == "commit":
            return object_sha
        require(object_type == "tag", "tag reference does not resolve to a commit or annotated tag")
        tag_object = gh_json(["api", f"repos/{repository}/git/tags/{object_sha}"])
        target = tag_object.get("object", {})
    raise PreflightError("annotated tag nesting exceeds the supported resolution depth")


def attested_files(root: pathlib.Path) -> list[pathlib.Path]:
    return [root / filename for filename in sorted(UNSIGNED_FILES)]


def verify_preflight(
    root: pathlib.Path,
    tag: str,
    run_id: str,
    expected_commit: str,
    repository: str = REPOSITORY,
) -> dict:
    parse_tag(tag)
    validate_local_source_checkout(pathlib.Path(__file__).resolve().parent.parent, expected_commit)
    validate_release(root, tag, pathlib.Path(__file__).resolve().parent.parent, None, signed=False)
    require(re.fullmatch(r"[0-9]+", str(run_id)) is not None, "GitHub Actions run ID must be numeric")
    run = gh_json(["api", f"repos/{repository}/actions/runs/{run_id}"])
    validate_run_context(run, repository, tag, expected_commit)
    tag_commit = resolve_tag_commit(repository, tag)
    require(tag_commit == expected_commit, "remote tag does not identify the attested source commit")

    source_ref = f"refs/tags/{tag}"
    signer_workflow = f"{repository}/{WORKFLOW}"
    for asset in attested_files(root):
        gh_success(
            [
                "attestation",
                "verify",
                str(asset),
                "--repo",
                repository,
                "--source-ref",
                source_ref,
                "--source-digest",
                expected_commit,
                "--signer-workflow",
                signer_workflow,
                "--deny-self-hosted-runners",
            ]
        )

    return {
        "schema": "astatine-owner-preflight-v1",
        "repository": repository,
        "tag": tag,
        "source_commit": expected_commit,
        "run_id": str(run_id),
        "run_url": run.get("html_url", ""),
        "tag_commit": tag_commit,
        "workflow": WORKFLOW,
        "attested_assets": {
            path.name: {"sha256": sha256(path), "size": path.stat().st_size}
            for path in attested_files(root)
        },
        "verified_at_utc": datetime.now(timezone.utc).isoformat(),
    }


def write_report(path: pathlib.Path, report: dict) -> None:
    require(not path.exists(), "refusing to overwrite an existing provenance report")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: pathlib.Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", prefix=f".{path.name}.", suffix=".tmp", dir=path.parent, delete=False
        ) as temporary:
            temporary_path = pathlib.Path(temporary.name)
            json.dump(report, temporary, sort_keys=True, indent=2)
            temporary.write("\n")
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_path, path)
    finally:
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()


def self_test() -> None:
    valid = {
        "conclusion": "success",
        "event": "push",
        "head_sha": "a" * 40,
        "head_branch": "v0.1.0-testnet.13",
        "path": f"{WORKFLOW}@refs/tags/v0.1.0-testnet.13",
        "repository": {"full_name": REPOSITORY},
    }
    validate_run_context(valid, REPOSITORY, "v0.1.0-testnet.13", "a" * 40)
    for mutated, repository, tag, commit in (
        ({**valid, "head_sha": "b" * 40}, REPOSITORY, "v0.1.0-testnet.13", "a" * 40),
        ({**valid, "head_branch": "v0.1.0-testnet.14"}, REPOSITORY, "v0.1.0-testnet.13", "a" * 40),
        ({**valid, "conclusion": "failure"}, REPOSITORY, "v0.1.0-testnet.13", "a" * 40),
        ({**valid, "path": ".github/workflows/untrusted.yml@refs/tags/v0.1.0-testnet.13"}, REPOSITORY, "v0.1.0-testnet.13", "a" * 40),
        ({**valid, "path": f"{WORKFLOW}@refs/heads/main"}, REPOSITORY, "v0.1.0-testnet.13", "a" * 40),
        ({**valid, "repository": {"full_name": "attacker.invalid/astatine-miner"}}, REPOSITORY, "v0.1.0-testnet.13", "a" * 40),
        (valid, "attacker.invalid/astatine-miner", "v0.1.0-testnet.13", "a" * 40),
        (valid, REPOSITORY, "v0.1.0-testnet.13", "b" * 40),
    ):
        try:
            validate_run_context(mutated, repository, tag, commit)
        except PreflightError:
            continue
        raise AssertionError("synthetic preflight accepted incorrect repository/tag/commit provenance")

    with tempfile.TemporaryDirectory(prefix="astatine-provenance-checkout-test-") as temporary:
        checkout = pathlib.Path(temporary)
        subprocess.run(["git", "-C", str(checkout), "init", "-q", "-b", "main"], check=True, capture_output=True)
        (checkout / "source.txt").write_text("synthetic source\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(checkout), "add", "source.txt"], check=True, capture_output=True)
        subprocess.run(
            [
                "git",
                "-C",
                str(checkout),
                "-c",
                "user.name=synthetic test",
                "-c",
                "user.email=synthetic@example.invalid",
                "commit",
                "-q",
                "-m",
                "synthetic source",
            ],
            check=True,
            capture_output=True,
        )
        commit = subprocess.run(
            ["git", "-C", str(checkout), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        validate_local_source_checkout(checkout, commit)
        try:
            validate_local_source_checkout(checkout, "b" * 40)
        except PreflightError:
            pass
        else:
            raise AssertionError("synthetic preflight accepted a local checkout at a different commit")
        (checkout / "untracked.txt").write_text("dirty\n", encoding="utf-8")
        try:
            validate_local_source_checkout(checkout, commit)
        except PreflightError:
            pass
        else:
            raise AssertionError("synthetic preflight accepted a dirty local source checkout")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--artifact-dir", type=pathlib.Path)
    parser.add_argument("--tag")
    parser.add_argument("--run-id")
    parser.add_argument("--source-commit")
    parser.add_argument("--report", type=pathlib.Path)
    arguments = parser.parse_args()
    try:
        if arguments.self_test:
            self_test()
            print("Synthetic release provenance metadata tests passed")
            return
        for name in ("artifact_dir", "tag", "run_id", "source_commit", "report"):
            require(getattr(arguments, name) is not None, f"--{name.replace('_', '-')} is required")
        report = verify_preflight(
            arguments.artifact_dir,
            arguments.tag,
            arguments.run_id,
            arguments.source_commit,
        )
        write_report(arguments.report, report)
        report_digest = sha256(arguments.report)
        print(
            f"Verified {len(report['attested_assets'])} unsigned assets from "
            f"{report['repository']}@{report['source_commit']} ({report['tag']}); report: {arguments.report}"
        )
        print(f"Record this preflight report SHA-256 for offline signing/publication: {report_digest}")
    except (OSError, subprocess.SubprocessError, PreflightError, ValueError) as error:
        parser.exit(1, f"release provenance preflight failed: {error}\n")


if __name__ == "__main__":
    main()
