#!/usr/bin/env python3
"""Exercise production CLI state across genuine Docker container recreation.

Run interactively on Ubuntu 24.04 x86_64 with a local Docker engine:

    python3 support/linux/qualify-container-lifecycle.py

Run the separate GitHub-hosted CI-only synthetic subset:

    ASTATINE_CONTAINER_QUALIFICATION_MODE=ci-synthetic \\
      python3 support/linux/qualify-container-lifecycle.py --ci-synthetic

Run offline regression checks without Docker:

    python3 support/linux/qualify-container-lifecycle.py --self-test-cleanup
    python3 support/linux/qualify-container-lifecycle.py --self-test-ci

The fixture uses a random private Docker named volume, a fresh Ubuntu 24.04
amd64 image built from a whitelist-only context, and containers with no network,
ports, host mounts, or capabilities. Both modes create a synthetic wallet with
the production CLI and check unavailable and locked Secret Service fail-closed
behavior after genuine container recreation. The default interactive mode keeps
its human keyring-unlock and post-unlock recovery gates. The CI-only mode instead
stops after the fail-closed checks and makes no post-unlock recovery claim.

No passphrase, mnemonic, wallet password, encrypted keystore, journal, or
checkpoint is printed or written to host files, command arguments, or
environment variables. Only hashes of disposable state are exchanged inside
the harness process; they are never printed or persisted. Docker build and
runtime output is captured and reduced to script-authored markers. Cleanup is
restricted to the exact uniquely named resources created by this invocation.
"""

from __future__ import annotations

import importlib.util
import json
import os
import platform
import posixpath
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import urllib.parse
from pathlib import Path
from types import ModuleType
from typing import Any


DOCKER_LABEL = "org.astatine.qualification"
DOCKER_LABEL_VALUE = "container-d2"
TIMEOUT_BUILD_SECONDS = 2400
TIMEOUT_DOCKER_SECONDS = 90
TIMEOUT_RECOVER_SECONDS = 120
SERVICE_HELPER = "/usr/local/lib/astatine-container/container-secret-service.py"
STATE_HELPER = "/usr/local/lib/astatine-container/container-state-probe.py"
RUNTIME_IMAGE = "ubuntu-24.04-linux-amd64"
NOT_FOUND_MARKERS = {
    "container": ("no such object:", "no such container:"),
    "volume": ("no such volume",),
    "image": ("no such image:", "no such object:"),
}

_SIGNAL_REQUESTED: int | None = None
_CLEANUP_IN_PROGRESS = False
_ACTIVE_DOCKER_PROCESS: subprocess.Popen[bytes] | None = None
_ACTIVE_CHILD_PID: int | None = None


class QualificationError(RuntimeError):
    """A safe diagnostic authored by this qualification harness."""


class QualificationCancelled(RuntimeError):
    """A signal requested cancellation before resource cleanup."""

    def __init__(self, signum: int) -> None:
        self.signum = signum


def _require(condition: object, reason: str) -> None:
    if not condition:
        raise QualificationError(reason)


def _signal_active_child(signum: int) -> None:
    if _ACTIVE_DOCKER_PROCESS is not None:
        try:
            _ACTIVE_DOCKER_PROCESS.send_signal(signum)
        except (OSError, ProcessLookupError):
            pass
    elif _ACTIVE_CHILD_PID is not None:
        try:
            os.kill(_ACTIVE_CHILD_PID, signum)
        except (OSError, ProcessLookupError):
            pass


def _record_signal(signum: int, _frame: object) -> None:
    global _SIGNAL_REQUESTED
    if _SIGNAL_REQUESTED is None:
        _SIGNAL_REQUESTED = signum
        _signal_active_child(signum)


def _check_cancelled() -> None:
    if _SIGNAL_REQUESTED is not None and not _CLEANUP_IN_PROGRESS:
        raise QualificationCancelled(_SIGNAL_REQUESTED)


def _protect_cleanup_from_signals() -> None:
    global _CLEANUP_IN_PROGRESS
    _CLEANUP_IN_PROGRESS = True
    for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(signum, signal.SIG_IGN)


def _load_production_fixture() -> ModuleType:
    path = Path(__file__).with_name("qualify-production-journal.py")
    spec = importlib.util.spec_from_file_location(
        "astatine_container_production_journal_fixture", path
    )
    if spec is None or spec.loader is None:
        raise QualificationError("could not load the existing production PTY fixture")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


PRODUCTION_FIXTURE = _load_production_fixture()


def _safe_status(status: int) -> str:
    if os.WIFSIGNALED(status):
        return f"signal {os.WTERMSIG(status)}"
    if os.WIFEXITED(status):
        return f"exit {os.WEXITSTATUS(status)}"
    return "unknown child status"


def _host_ubuntu_release() -> tuple[str, str]:
    values: dict[str, str] = {}
    try:
        for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
            key, separator, value = line.partition("=")
            if separator:
                values[key] = value.strip().strip('"')
    except OSError:
        raise QualificationError("host OS identity could not be verified") from None
    return values.get("ID", ""), values.get("VERSION_ID", "")


def _docker(args: list[str], *, timeout: int = TIMEOUT_DOCKER_SECONDS) -> subprocess.CompletedProcess[bytes]:
    global _ACTIVE_DOCKER_PROCESS
    _check_cancelled()
    command = ["docker", *args]
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError:
        raise QualificationError("the Docker CLI could not be started") from None

    _ACTIVE_DOCKER_PROCESS = process
    if _SIGNAL_REQUESTED is not None and not _CLEANUP_IN_PROGRESS:
        _signal_active_child(_SIGNAL_REQUESTED)
    try:
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()
            _check_cancelled()
            raise QualificationError("a bounded Docker operation timed out") from None
        except BaseException:
            if process.poll() is None:
                process.kill()
                process.wait()
            raise
    finally:
        if _ACTIVE_DOCKER_PROCESS is process:
            _ACTIVE_DOCKER_PROCESS = None

    _check_cancelled()
    return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)


def _require_docker_ok(result: subprocess.CompletedProcess[bytes], stage: str) -> bytes:
    _require(result.returncode == 0, f"Docker {stage} failed with status {result.returncode}")
    return result.stdout


def _safe_build_diagnostics(output: bytes) -> str:
    """Reduce compiler output to allowlisted path/package diagnostics only."""
    missing_file = re.compile(
        r"error: couldn't read `([^`\r\n]{1,256})`: No such file or directory "
        r"\(os error [0-9]+\)"
    )
    failed_crate = re.compile(r"error: could not compile `([A-Za-z0-9_.-]{1,128})`")
    messages: list[str] = []
    for raw_line in output.decode("utf-8", "replace").splitlines():
        line = raw_line.strip()
        missing = missing_file.search(line)
        if missing is not None:
            path = missing.group(1)
            if not re.fullmatch(r"[A-Za-z0-9_./-]{1,256}", path):
                continue
            normalized = posixpath.normpath(path)
            if normalized.startswith("../") or normalized in {".", ".."} or normalized.startswith("/"):
                continue
            message = f"missing build input: {normalized}"
        else:
            crate = failed_crate.search(line)
            if crate is None:
                continue
            message = f"Rust crate failed to compile: {crate.group(1)}"
        if message not in messages:
            messages.append(message)
        if len(messages) == 5:
            break
    if messages:
        return "; ".join(messages)
    return "no safe compiler summary matched; raw build diagnostics withheld"


def _confirmed_not_found(
    result: subprocess.CompletedProcess[bytes], *, kind: str, name: str
) -> bool:
    if result.returncode == 0:
        return False
    diagnostic = result.stderr.decode("utf-8", "replace").lower()
    return name.lower() in diagnostic and any(
        marker in diagnostic for marker in NOT_FOUND_MARKERS[kind]
    )


def _inspect_resource(
    args: list[str], *, kind: str, name: str
) -> bytes | None:
    result = _docker(args)
    if _confirmed_not_found(result, kind=kind, name=name):
        return None
    return _require_docker_ok(result, f"{kind} inspection")


def _remove_and_verify_absent(
    remove_args: list[str],
    inspect_args: list[str],
    *,
    kind: str,
    name: str,
    stage: str,
) -> None:
    removal_error: QualificationError | None = None
    removal: subprocess.CompletedProcess[bytes] | None = None
    try:
        removal = _docker(remove_args)
    except QualificationError as error:
        removal_error = error

    try:
        remaining = _inspect_resource(inspect_args, kind=kind, name=name)
    except QualificationError:
        raise QualificationError(f"could not verify {kind} absence after cleanup") from None
    if remaining is None:
        return
    if removal_error is not None:
        raise QualificationError(f"Docker {stage} failed") from None
    assert removal is not None
    if removal.returncode != 0:
        raise QualificationError(
            f"Docker {stage} failed with status {removal.returncode}"
        )
    raise QualificationError(f"{kind} remained after cleanup")


def _preflight(*, mode: str = "manual") -> None:
    _check_cancelled()
    _require(sys.platform == "linux", "Ubuntu 24.04 x86_64 is required; this is not evidence")
    distribution, version = _host_ubuntu_release()
    _require(
        distribution == "ubuntu" and version == "24.04",
        "the host must be Ubuntu 24.04",
    )
    _require(
        platform.machine() in {"x86_64", "amd64"},
        "the host must be x86_64",
    )
    if mode == "manual":
        _require(
            sys.stdin.isatty() and sys.stdout.isatty(),
            "a real interactive terminal is required for the manual keyring unlock gate",
        )
    else:
        _require(mode == "ci-synthetic", "unsupported container qualification mode")
        _preflight_github_hosted_runner()
    _require(shutil.which("docker") is not None, "the Docker CLI is required")
    _require(
        "DOCKER_HOST" not in os.environ and "DOCKER_CONTEXT" not in os.environ,
        "refusing a custom or remote Docker endpoint",
    )

    context = _docker(["context", "show"])
    _require_docker_ok(context, "context inspection")
    _require(
        context.stdout.decode("utf-8", "replace").strip() == "default",
        "the default local Docker context is required",
    )
    _verify_local_docker_endpoint()
    info = _docker(["info", "--format", "{{.OSType}} {{.Architecture}}"])
    _require_docker_ok(info, "engine inspection")
    os_type, _, architecture = info.stdout.decode("ascii", "replace").strip().partition(" ")
    _require(os_type == "linux", "the Docker engine must be Linux")
    _require(
        architecture in {"x86_64", "amd64"},
        "the Docker engine must be x86_64; emulation is not accepted",
    )


def _preflight_github_hosted_runner() -> None:
    _require(
        os.environ.get("ASTATINE_CONTAINER_QUALIFICATION_MODE") == "ci-synthetic",
        "the CI synthetic mode requires its explicit workflow marker",
    )
    _require(
        os.environ.get("GITHUB_ACTIONS") == "true"
        and os.environ.get("CI") == "true"
        and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
        and os.environ.get("RUNNER_OS") == "Linux"
        and os.environ.get("RUNNER_ARCH") == "X64",
        "CI synthetic mode is restricted to a GitHub-hosted Linux x86_64 runner",
    )
    _require(
        os.environ.get("GITHUB_JOB") == "container-lifecycle-ci-synthetic",
        "CI synthetic mode is restricted to its dedicated bounded job",
    )
    workspace = os.environ.get("GITHUB_WORKSPACE", "")
    expected_workspace = str(Path(__file__).resolve().parents[2])
    _require(
        bool(workspace)
        and Path(workspace).resolve() == Path(expected_workspace),
        "CI synthetic mode must run from its checked-out repository workspace",
    )
    _require(
        os.environ.get("GITHUB_RUN_ID", "").isdigit()
        and os.environ.get("GITHUB_RUN_ATTEMPT", "").isdigit(),
        "CI synthetic mode requires a GitHub Actions run identity",
    )


def _verify_local_docker_endpoint() -> None:
    result = _docker(
        [
            "context",
            "inspect",
            "default",
            "--format",
            "{{.Endpoints.docker.Host}}",
        ]
    )
    output = _require_docker_ok(result, "endpoint inspection")
    try:
        endpoint = output.decode("ascii").strip()
    except UnicodeDecodeError:
        raise QualificationError("Docker endpoint could not be verified as local") from None
    _require(
        bool(endpoint) and "\n" not in endpoint and "\r" not in endpoint,
        "Docker endpoint could not be verified as local",
    )
    try:
        parsed = urllib.parse.urlsplit(endpoint)
    except ValueError:
        raise QualificationError("Docker endpoint could not be verified as local") from None
    _require(
        parsed.scheme == "unix"
        and parsed.netloc == ""
        and parsed.path.startswith("/")
        and parsed.path != "/"
        and not parsed.query
        and not parsed.fragment,
        "Docker endpoint must be a local Unix socket",
    )
    try:
        socket_path = urllib.parse.unquote(parsed.path, errors="strict")
        metadata = os.lstat(socket_path)
    except (OSError, UnicodeDecodeError, ValueError):
        raise QualificationError("Docker endpoint is not an available local Unix socket") from None
    _require(
        stat.S_ISSOCK(metadata.st_mode),
        "Docker endpoint is not an available local Unix socket",
    )


def _copy_regular_file(source: Path, destination: Path) -> None:
    try:
        metadata = os.lstat(source)
    except OSError:
        raise QualificationError("a required production build input is missing") from None
    _require(stat.S_ISREG(metadata.st_mode), "refusing a non-regular production build input")
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    shutil.copyfile(source, destination)
    os.chmod(destination, 0o600)


def _copy_tree_without_links(source: Path, destination: Path) -> None:
    try:
        metadata = os.lstat(source)
    except OSError:
        raise QualificationError("a required production source directory is missing") from None
    _require(stat.S_ISDIR(metadata.st_mode), "refusing a non-directory production source")
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    for entry in os.scandir(source):
        source_entry = Path(entry.path)
        destination_entry = destination / entry.name
        if entry.is_symlink():
            raise QualificationError("refusing a symlink in the production build context")
        if entry.is_dir(follow_symlinks=False):
            _copy_tree_without_links(source_entry, destination_entry)
        elif entry.is_file(follow_symlinks=False):
            _copy_regular_file(source_entry, destination_entry)
        else:
            raise QualificationError("refusing a special file in the production build context")


def _create_build_context(repository: Path, parent: Path) -> Path:
    context = parent / "context"
    context.mkdir(mode=0o700)
    for name in ("Cargo.toml", "Cargo.lock", "build.rs", "rust-toolchain.toml"):
        _copy_regular_file(repository / name, context / name)
    _copy_tree_without_links(repository / "src", context / "src")
    for name in ("mainnet.toml", "testnet.toml"):
        _copy_regular_file(
            repository / "deployments" / name,
            context / "deployments" / name,
        )
    _copy_regular_file(
        repository / "support" / "release-repository.txt",
        context / "support" / "release-repository.txt",
    )
    _copy_tree_without_links(
        repository / "support" / "paste-shim",
        context / "support" / "paste-shim",
    )
    linux_support = repository / "support" / "linux"
    for name in (
        "container-qualification.Dockerfile",
        "container-entrypoint.sh",
        "container-secret-service.py",
        "container-state-probe.py",
        "container-session.conf",
    ):
        _copy_regular_file(linux_support / name, context / "support" / "linux" / name)

    allowed_top_level = {
        "Cargo.toml",
        "Cargo.lock",
        "build.rs",
        "rust-toolchain.toml",
        "src",
        "deployments",
        "support",
    }
    _require(
        {entry.name for entry in context.iterdir()} == allowed_top_level,
        "the private build context contains an unexpected path",
    )
    return context


def _state_core(snapshot: dict[str, Any]) -> tuple[object, ...]:
    return tuple(
        snapshot.get(name)
        for name in (
            "root_mode",
            "config_mode",
            "journal_mode",
            "keystore_mode",
            "config_sha256",
            "journal_sha256",
            "keystore_sha256",
            "keystore_count",
            "entry_count",
            "spending_limit",
            "policy_approval_present",
            "unresolved_count",
            "pending_authorization",
            "pending_session_transition",
        )
    )


def _assert_state_valid(snapshot: dict[str, Any]) -> None:
    _require(snapshot.get("root_mode") == 0o700, "production data root is not mode 0700")
    _require(snapshot.get("config_mode") == 0o600, "production config is not mode 0600")
    _require(snapshot.get("journal_mode") == 0o600, "production journal is not mode 0600")
    _require(snapshot.get("keystore_mode") == 0o600, "production keystore is not mode 0600")
    _require(snapshot.get("keystore_count") == 1, "expected exactly one synthetic keystore")
    _require(snapshot.get("keyring_count", 0) >= 1, "private keyring storage is missing")
    _require(snapshot.get("entry_count") == 0, "the synthetic journal has transaction entries")
    _require(snapshot.get("spending_limit") == "0.1", "the spending cap changed")
    _require(snapshot.get("policy_approval_present") is True, "per-run policy approval is missing")
    _require(snapshot.get("unresolved_count") == 0, "the synthetic journal has an unresolved transaction")
    _require(snapshot.get("pending_authorization") is False, "pending spending authorization exists")
    _require(snapshot.get("pending_session_transition") is False, "pending session transition exists")
    for name in ("config_sha256", "journal_sha256", "keystore_sha256", "keyring_sha256"):
        value = snapshot.get(name)
        _require(
            isinstance(value, str)
            and len(value) == 64
            and all(character in "0123456789abcdef" for character in value),
            f"{name} fingerprint is invalid",
        )


CI_SYNTHETIC_STAGES = (
    "keyring-bootstrapped",
    "production-init-complete",
    "initial-recovery-complete",
    "container-recreated",
    "state-preserved",
    "unavailable-provider-failed-closed",
    "locked-provider-failed-closed",
    "complete",
)


class CiSyntheticStateMachine:
    """Enforce the bounded CI path, which intentionally has no unlock stage."""

    def __init__(self) -> None:
        self._next_stage = 0

    def advance(self, stage: str) -> None:
        if self._next_stage >= len(CI_SYNTHETIC_STAGES):
            raise QualificationError("CI synthetic lifecycle advanced past completion")
        expected = CI_SYNTHETIC_STAGES[self._next_stage]
        if stage != expected:
            raise QualificationError("CI synthetic lifecycle stage was out of order")
        self._next_stage += 1

    def finish(self) -> None:
        if self._next_stage != len(CI_SYNTHETIC_STAGES):
            raise QualificationError("CI synthetic lifecycle ended before completion")


class ContainerQualification:
    def __init__(self) -> None:
        self.repository = Path(__file__).resolve().parents[2]
        self.token = os.urandom(8).hex()
        self.container_name = f"astatine-container-d2-{self.token}"
        self.volume_name = f"astatine-container-d2-{self.token}-state"
        self.image_tag = f"astatine-container-d2:{self.token}"
        self.work: Path | None = None
        self.context: Path | None = None
        self.volume_requested = False
        self.container_requested = False
        self.image_requested = False
        self.success = False

    def _docker_ok(self, args: list[str], stage: str, *, timeout: int = TIMEOUT_DOCKER_SECONDS) -> bytes:
        return _require_docker_ok(_docker(args, timeout=timeout), stage)

    def _build(self) -> None:
        self.work = Path(tempfile.mkdtemp(prefix="astatine-container-build.", dir="/tmp"))
        os.chmod(self.work, 0o700)
        self.context = _create_build_context(self.repository, self.work)
        self.image_requested = True
        build = _docker(
            [
                "build",
                "--progress=plain",
                "--pull",
                "--platform=linux/amd64",
                "--label",
                f"{DOCKER_LABEL}.id={self.token}",
                "--file",
                "support/linux/container-qualification.Dockerfile",
                "--tag",
                self.image_tag,
                str(self.context),
            ],
            timeout=TIMEOUT_BUILD_SECONDS,
        )
        if build.returncode != 0:
            details = _safe_build_diagnostics(build.stdout + build.stderr)
            raise QualificationError(
                "Docker production image build failed with "
                f"status {build.returncode}; {details}"
            )
        labels = self._docker_ok(
            ["image", "inspect", "--format", "{{json .Config.Labels}}", self.image_tag],
            "built image inspection",
        )
        try:
            label_map = json.loads(labels)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise QualificationError("built image labels could not be verified") from None
        _require(
            isinstance(label_map, dict)
            and label_map.get(DOCKER_LABEL) == DOCKER_LABEL_VALUE
            and label_map.get(f"{DOCKER_LABEL}.id") == self.token,
            "built image is not owned by this qualification",
        )

    def _create_volume(self) -> None:
        self.volume_requested = True
        output = self._docker_ok(
            [
                "volume",
                "create",
                "--label",
                f"{DOCKER_LABEL}={DOCKER_LABEL_VALUE}",
                "--label",
                f"{DOCKER_LABEL}.id={self.token}",
                self.volume_name,
            ],
            "private volume creation",
        )
        _require(
            output.decode("utf-8", "replace").strip() == self.volume_name,
            "Docker created an unexpected private volume",
        )

    def _start_container(self) -> None:
        self.container_requested = True
        self._docker_ok(
            [
                "run",
                "--detach",
                "--platform=linux/amd64",
                "--name",
                self.container_name,
                "--label",
                f"{DOCKER_LABEL}={DOCKER_LABEL_VALUE}",
                "--label",
                f"{DOCKER_LABEL}.id={self.token}",
                "--network",
                "none",
                "--read-only",
                "--cap-drop=ALL",
                "--security-opt",
                "no-new-privileges:true",
                "--pids-limit",
                "128",
                "--stop-timeout",
                "10",
                "--mount",
                f"type=volume,src={self.volume_name},dst=/state",
                "--tmpfs",
                "/run/astatine:rw,noexec,nosuid,nodev,size=16m,uid=10001,gid=10001,mode=0700",
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777",
                self.image_tag,
            ],
            "private container start",
        )
        self._verify_container_runtime()
        status = self._service_status()
        _require(status == "secret-service=absent", "new container did not start without a Secret Service")

    def _verify_container_runtime(self) -> None:
        script = (
            "import platform, pathlib; "
            "d = {}; "
            "exec(\"for line in pathlib.Path('/etc/os-release').read_text().splitlines():\\n"
            " k, sep, v = line.partition('=')\\n"
            " if sep: d[k] = v.strip('\\\"')\"); "
            "print(d.get('ID','') + '|' + d.get('VERSION_ID','') + '|' + platform.machine())"
        )
        output = self._docker_ok(
            ["exec", self.container_name, "/usr/bin/python3", "-c", script],
            "container runtime inspection",
        )
        _require(
            output.decode("ascii", "replace").strip() == "ubuntu|24.04|x86_64",
            "container is not Ubuntu 24.04 x86_64",
        )
        inspected = self._docker_ok(
            ["inspect", self.container_name], "container isolation inspection"
        )
        try:
            records = json.loads(inspected)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise QualificationError("container isolation metadata is invalid") from None
        _require(
            isinstance(records, list) and len(records) == 1,
            "container isolation metadata is invalid",
        )
        record = records[0]
        labels = record.get("Config", {}).get("Labels") or {}
        host_config = record.get("HostConfig", {})
        mounts = record.get("Mounts") or []
        volume_mounts = [mount for mount in mounts if mount.get("Type") == "volume"]
        _require(
            record.get("Name") == f"/{self.container_name}"
            and labels.get(DOCKER_LABEL) == DOCKER_LABEL_VALUE
            and labels.get(f"{DOCKER_LABEL}.id") == self.token
            and host_config.get("NetworkMode") == "none"
            and host_config.get("ReadonlyRootfs") is True
            and host_config.get("Privileged") is False
            and "ALL" in host_config.get("CapDrop", [])
            and "no-new-privileges:true" in host_config.get("SecurityOpt", [])
            and not host_config.get("PortBindings")
            and len(volume_mounts) == 1
            and volume_mounts[0].get("Name") == self.volume_name
            and volume_mounts[0].get("Destination") == "/state"
            and all(mount.get("Type") != "bind" for mount in mounts),
            "container network, mount, or ownership isolation is invalid",
        )

    def _service_status(self) -> str:
        output = self._docker_ok(
            ["exec", self.container_name, "/usr/bin/python3", SERVICE_HELPER, "status"],
            "private Secret Service status inspection",
        )
        return output.decode("ascii", "replace").strip()

    def _run_manual_unlock(self, stage: str) -> None:
        global _ACTIVE_DOCKER_PROCESS
        _check_cancelled()
        print(stage, flush=True)
        command = [
            "docker",
            "exec",
            "--interactive",
            "--tty",
            self.container_name,
            "/usr/bin/python3",
            SERVICE_HELPER,
            "unlock",
        ]
        try:
            process = subprocess.Popen(command)
        except OSError:
            raise QualificationError("could not start the interactive manual-unlock gate") from None
        _ACTIVE_DOCKER_PROCESS = process
        if _SIGNAL_REQUESTED is not None and not _CLEANUP_IN_PROGRESS:
            _signal_active_child(_SIGNAL_REQUESTED)
        try:
            while process.poll() is None:
                _check_cancelled()
                try:
                    process.wait(timeout=0.2)
                except subprocess.TimeoutExpired:
                    pass
            _check_cancelled()
        except BaseException:
            if process.poll() is None:
                try:
                    process.terminate()
                    process.wait(timeout=5)
                except (OSError, subprocess.TimeoutExpired):
                    try:
                        process.kill()
                        process.wait(timeout=5)
                    except (OSError, subprocess.TimeoutExpired):
                        pass
            if _SIGNAL_REQUESTED is not None:
                raise QualificationCancelled(_SIGNAL_REQUESTED) from None
            raise
        finally:
            if _ACTIVE_DOCKER_PROCESS is process:
                _ACTIVE_DOCKER_PROCESS = None
        _require(process.returncode == 0, "the human Secret Service unlock gate did not complete")
        _require(
            self._service_status() == "secret-service=unlocked",
            "the operator-entered Secret Service did not become unlocked",
        )

    def _run_init(self) -> None:
        global _ACTIVE_CHILD_PID
        _check_cancelled()
        password_buffer = bytearray(os.urandom(32).hex().encode("ascii"))
        process = PRODUCTION_FIXTURE.InteractiveProcess(
            [
                "docker",
                "exec",
                "--interactive",
                "--tty",
                self.container_name,
                "/usr/local/bin/astatine",
                *PRODUCTION_FIXTURE._init_args("0.1"),
            ],
            os.environ.copy(),
            str(self.repository),
        )
        _ACTIVE_CHILD_PID = process.pid
        if _SIGNAL_REQUESTED is not None and not _CLEANUP_IN_PROGRESS:
            _signal_active_child(_SIGNAL_REQUESTED)
        try:
            _check_cancelled()
            process.expect_any(
                ["Choose 1, 2, or 3"],
                PRODUCTION_FIXTURE.PROMPT_TIMEOUT_SECONDS,
                "container production init wallet selection",
            )
            _check_cancelled()
            process.send_line("1")
            process.expect_any(
                ["Type BACKED UP"],
                PRODUCTION_FIXTURE.PROMPT_TIMEOUT_SECONDS,
                "container production init recovery-phrase confirmation",
            )
            _check_cancelled()
            process.send_line("BACKED UP")
            process.expect_any(
                ["Create keystore password"],
                PRODUCTION_FIXTURE.PROMPT_TIMEOUT_SECONDS,
                "container production init keystore password creation",
            )
            _check_cancelled()
            process.send_secret_line(password_buffer)
            process.expect_any(
                ["Confirm keystore password"],
                PRODUCTION_FIXTURE.PROMPT_TIMEOUT_SECONDS,
                "container production init keystore password confirmation",
            )
            _check_cancelled()
            process.send_secret_line(password_buffer)
            _require(
                bytes(password_buffer) not in process.buffer,
                "production init echoed the synthetic keystore password",
            )
            process.expect_any(
                ["Use the selected wallet for future per-run spending sessions?"],
                PRODUCTION_FIXTURE.PROMPT_TIMEOUT_SECONDS,
                "container production init per-run wallet approval",
            )
            _check_cancelled()
            process.send_line("y")
            process.expect_any(
                [
                    "Persist and approve this per-run policy for the selected "
                    "wallet and network?"
                ],
                PRODUCTION_FIXTURE.PROMPT_TIMEOUT_SECONDS,
                "container production init spending policy approval",
            )
            _check_cancelled()
            process.send_line("y")
            status = process.wait_for_exit(PRODUCTION_FIXTURE.PROCESS_TIMEOUT_SECONDS)
            _check_cancelled()
            _require(
                os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0,
                f"production init ended with {_safe_status(status)}",
            )
        except BaseException:
            if _SIGNAL_REQUESTED is not None:
                raise QualificationCancelled(_SIGNAL_REQUESTED) from None
            raise
        finally:
            _ACTIVE_CHILD_PID = None
            password_buffer[:] = bytes(len(password_buffer))
            process.cleanup()

    def _bootstrap_synthetic_keyring(self) -> None:
        output = self._docker_ok(
            [
                "exec",
                self.container_name,
                "/usr/bin/python3",
                SERVICE_HELPER,
                "bootstrap-synthetic",
            ],
            "synthetic Secret Service bootstrap",
        )
        _require(
            output.decode("ascii", "replace").strip()
            == "secret-service=unlocked synthetic-keyring=created",
            "synthetic Secret Service bootstrap did not create a fresh keyring",
        )
        _require(
            self._service_status() == "secret-service=unlocked",
            "synthetic Secret Service did not start unlocked",
        )

    def _run_ci_synthetic(self) -> None:
        state = CiSyntheticStateMachine()
        self._bootstrap_synthetic_keyring()
        state.advance("keyring-bootstrapped")

        self._run_init()
        state.advance("production-init-complete")
        baseline = self._snapshot()
        self._run_recover(expected_success=True, stage="initial production recover")
        after_initial_recover = self._snapshot()
        _require(
            _state_core(after_initial_recover) == _state_core(baseline),
            "initial read-only recovery changed production state",
        )
        state.advance("initial-recovery-complete")

        self._remove_container()
        self._start_container()
        state.advance("container-recreated")
        after_recreation = self._snapshot()
        _require(
            _state_core(after_recreation) == _state_core(baseline)
            and after_recreation.get("keyring_sha256") == baseline.get("keyring_sha256"),
            "wallet, journal, policy, or keyring did not persist on the designated volume",
        )
        state.advance("state-preserved")

        self._run_recover(
            expected_success=False, stage="unavailable-provider production recover"
        )
        after_unavailable = self._snapshot()
        _require(
            _state_core(after_unavailable) == _state_core(baseline),
            "unavailable-provider recovery changed production or spending state",
        )
        state.advance("unavailable-provider-failed-closed")

        self._docker_ok(
            ["exec", self.container_name, "/usr/bin/python3", SERVICE_HELPER, "start-locked"],
            "locked Secret Service startup",
        )
        _require(self._service_status() == "secret-service=locked", "the provider is not genuinely locked")
        self._run_recover(expected_success=False, stage="locked-provider production recover")
        after_locked = self._snapshot()
        _require(
            _state_core(after_locked) == _state_core(baseline),
            "locked-provider recovery changed production or spending state",
        )
        state.advance("locked-provider-failed-closed")
        state.advance("complete")
        state.finish()

        print(f"container-runtime={RUNTIME_IMAGE}")
        print("production-init=ok synthetic-wallet=created")
        print("production-recover-initial=ok")
        print("container-recreations=1 designated-volume=preserved")
        print("unavailable-provider=fail-closed")
        print("locked-provider=fail-closed")
        print("manual-unlock=not-run")
        print("post-unlock-recovery=not-tested")
        print("root-mode=700 config-mode=600 journal-mode=600 keystore-mode=600")
        print("spending-authorization=invariants-preserved journal-entries=0 unresolved-transactions=0")
        print("synthetic-liability=zero no-funds no-signing no-submission")
        print("container-network=none public-rpc=not-used")
        print("recovery-scope=initial-only post-unlock-not-tested")

    def _run_recover(self, *, expected_success: bool, stage: str) -> None:
        command = [
            "exec",
            self.container_name,
            "/usr/bin/timeout",
            "--signal=TERM",
            "--kill-after=5s",
            f"{TIMEOUT_RECOVER_SECONDS}s",
            "/usr/local/bin/astatine",
            "recover",
        ]
        result = _docker(command, timeout=TIMEOUT_RECOVER_SECONDS + 15)
        output = result.stdout + result.stderr
        success_marker = b"No unresolved transaction remains."
        if expected_success:
            _require(result.returncode == 0, f"{stage} failed with status {result.returncode}")
            _require(success_marker in output, f"{stage} did not authenticate the production journal")
            return

        _require(result.returncode != 0, f"{stage} unexpectedly accepted an unavailable checkpoint")
        _require(success_marker not in output, f"{stage} reported successful recovery")
        normalized = output.lower()
        _require(
            b"credential store" in normalized
            or b"secret service" in normalized
            or b"os credential-store checkpoint" in normalized,
            f"{stage} did not fail specifically on the native credential checkpoint",
        )

    def _snapshot(self) -> dict[str, Any]:
        output = self._docker_ok(
            ["exec", self.container_name, "/usr/bin/python3", STATE_HELPER],
            "production state inspection",
        )
        try:
            snapshot = json.loads(output)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise QualificationError("production state probe returned invalid metadata") from None
        _require(isinstance(snapshot, dict), "production state probe returned an invalid object")
        _assert_state_valid(snapshot)
        return snapshot

    def _remove_container(self) -> None:
        inspect_args = ["inspect", self.container_name]
        inspected = _inspect_resource(
            inspect_args, kind="container", name=self.container_name
        )
        if inspected is None:
            return
        try:
            records = json.loads(inspected)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise QualificationError("refusing to remove an unverified container") from None
        _require(isinstance(records, list) and len(records) == 1, "refusing to remove an unverified container")
        record = records[0]
        labels = record.get("Config", {}).get("Labels") or {}
        mounts = record.get("Mounts") or []
        _require(
            record.get("Name") == f"/{self.container_name}"
            and labels.get(DOCKER_LABEL) == DOCKER_LABEL_VALUE
            and labels.get(f"{DOCKER_LABEL}.id") == self.token
            and any(
                mount.get("Type") == "volume"
                and mount.get("Name") == self.volume_name
                and mount.get("Destination") == "/state"
                for mount in mounts
            ),
            "refusing to remove a container not owned by this qualification",
        )
        if record.get("State", {}).get("Running"):
            self._docker_ok(["stop", "--time", "10", self.container_name], "private container stop")
        _remove_and_verify_absent(
            ["rm", self.container_name],
            inspect_args,
            kind="container",
            name=self.container_name,
            stage="private container removal",
        )

    def _remove_volume(self) -> None:
        inspect_args = ["volume", "inspect", self.volume_name]
        inspected = _inspect_resource(
            inspect_args, kind="volume", name=self.volume_name
        )
        if inspected is None:
            return
        try:
            records = json.loads(inspected)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise QualificationError("refusing to remove an unverified volume") from None
        _require(isinstance(records, list) and len(records) == 1, "refusing to remove an unverified volume")
        record = records[0]
        labels = record.get("Labels") or {}
        _require(
            record.get("Name") == self.volume_name
            and labels.get(DOCKER_LABEL) == DOCKER_LABEL_VALUE
            and labels.get(f"{DOCKER_LABEL}.id") == self.token,
            "refusing to remove a volume not owned by this qualification",
        )
        _remove_and_verify_absent(
            ["volume", "rm", self.volume_name],
            inspect_args,
            kind="volume",
            name=self.volume_name,
            stage="private volume cleanup",
        )

    def _remove_image(self) -> None:
        if not self.image_requested:
            return
        inspect_args = [
            "image",
            "inspect",
            "--format",
            "{{json .Config.Labels}}",
            self.image_tag,
        ]
        inspected = _inspect_resource(
            inspect_args, kind="image", name=self.image_tag
        )
        if inspected is None:
            self.image_requested = False
            return
        try:
            labels = json.loads(inspected)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise QualificationError("refusing to remove an unverified image") from None
        _require(
            isinstance(labels, dict)
            and labels.get(DOCKER_LABEL) == DOCKER_LABEL_VALUE
            and labels.get(f"{DOCKER_LABEL}.id") == self.token,
            "refusing to remove an image not owned by this qualification",
        )
        _remove_and_verify_absent(
            ["image", "rm", self.image_tag],
            inspect_args,
            kind="image",
            name=self.image_tag,
            stage="private image cleanup",
        )
        self.image_requested = False

    def _cleanup(self) -> list[str]:
        errors: list[str] = []
        for label, action in (
            ("container", self._remove_container),
            ("volume", self._remove_volume),
            ("image", self._remove_image),
        ):
            try:
                action()
            except BaseException:
                errors.append(label)
        if self.work is not None:
            try:
                resolved = self.work.resolve(strict=True)
                _require(
                    resolved.parent == Path("/tmp")
                    and resolved.name.startswith("astatine-container-build.")
                    and os.lstat(resolved).st_uid == os.getuid()
                    and stat.S_IMODE(os.lstat(resolved).st_mode) == 0o700,
                    "refusing to remove an unverified private build context",
                )
                shutil.rmtree(resolved)
            except FileNotFoundError:
                pass
            except BaseException:
                errors.append("build-context")
        return errors

    def _report_cleanup(self) -> bool:
        errors = self._cleanup()
        if errors:
            for label in errors:
                print(
                    f"container-qualification: cleanup failed for owned {label}",
                    file=sys.stderr,
                )
            return False
        if self.success:
            print("container-fixture-cleanup=ok")
        return True

    def run(self, *, mode: str = "manual") -> None:
        _check_cancelled()
        self._build()
        self._create_volume()
        self._start_container()

        if mode == "ci-synthetic":
            self._run_ci_synthetic()
            self.success = True
            return

        self._run_manual_unlock(
            "OPERATOR GATE: Create a disposable test-only keyring passphrase at the hidden prompt. "
            "Remember it for the later manual unlock; do not use a production password."
        )
        self._run_init()
        baseline = self._snapshot()
        self._run_recover(expected_success=True, stage="initial production recover")
        after_initial_recover = self._snapshot()
        _require(
            _state_core(after_initial_recover) == _state_core(baseline),
            "initial read-only recovery changed production state",
        )

        self._remove_container()
        self._start_container()
        after_first_recreation = self._snapshot()
        _require(
            _state_core(after_first_recreation) == _state_core(baseline)
            and after_first_recreation.get("keyring_sha256") == baseline.get("keyring_sha256"),
            "named-volume production or Secret Service state did not persist across recreation",
        )
        self._run_recover(expected_success=False, stage="unavailable-provider production recover")
        after_unavailable = self._snapshot()
        _require(
            _state_core(after_unavailable) == _state_core(baseline),
            "unavailable-provider recovery changed production or spending state",
        )

        self._docker_ok(
            ["exec", self.container_name, "/usr/bin/python3", SERVICE_HELPER, "start-locked"],
            "locked Secret Service startup",
        )
        _require(self._service_status() == "secret-service=locked", "the provider is not genuinely locked")
        self._run_recover(expected_success=False, stage="locked-provider production recover")
        after_locked = self._snapshot()
        _require(
            _state_core(after_locked) == _state_core(baseline),
            "locked-provider recovery changed production or spending state",
        )

        self._remove_container()
        self._start_container()
        before_manual_unlock = self._snapshot()
        _require(
            _state_core(before_manual_unlock) == _state_core(baseline)
            and before_manual_unlock.get("keyring_sha256") == baseline.get("keyring_sha256"),
            "named-volume state did not survive the locked-container recreation",
        )
        self._run_manual_unlock(
            "OPERATOR GATE: The container has been recreated again. Manually enter the same "
            "test-only keyring passphrase at the hidden prompt; no value is prefilled or replayed."
        )
        after_manual_unlock = self._snapshot()
        _require(
            _state_core(after_manual_unlock) == _state_core(baseline),
            "manual Secret Service unlock changed production or spending state",
        )
        self._run_recover(expected_success=True, stage="fresh post-unlock production recover")
        after_recover = self._snapshot()
        _require(
            _state_core(after_recover) == _state_core(baseline),
            "fresh production recovery changed journal, config, keystore, or spending state",
        )

        print(f"container-runtime={RUNTIME_IMAGE}")
        print("production-init=ok synthetic-wallet=created")
        print("production-recover-initial=ok")
        print("container-recreations=2 named-volume=preserved")
        print("unavailable-provider=fail-closed")
        print("locked-provider=fail-closed")
        print("manual-unlock=human-entered")
        print("production-recover-fresh-process=ok")
        print("root-mode=700 config-mode=600 journal-mode=600 keystore-mode=600")
        print("spending-authorization=invariants-preserved")
        print("container-network=none public-rpc=not-used")
        self.success = True


def _run_ci_self_tests() -> None:
    import io
    import tempfile
    from contextlib import redirect_stderr, redirect_stdout
    from unittest.mock import patch

    def expect_rejected(
        action: object,
        message: str,
        exceptions: tuple[type[BaseException], ...] = (QualificationError,),
    ) -> None:
        try:
            action()  # type: ignore[operator]
        except exceptions:
            return
        raise AssertionError(message)

    safe_diagnostic = _safe_build_diagnostics(
        b"error: couldn't read `src/../deployments/testnet.toml`: "
        b"No such file or directory (os error 2)\n"
        b"error: couldn't read `src/../deployments/mainnet.toml`: "
        b"No such file or directory (os error 2)\n"
        b"error: could not compile `astatine-cli-rust` (bin \"astatine\")\n"
        b"build output password=offline-" + b"diagnostic-" + b"canary"
    )
    _require(
        "missing build input: deployments/testnet.toml" in safe_diagnostic
        and "missing build input: deployments/mainnet.toml" in safe_diagnostic
        and "Rust crate failed to compile: astatine-cli-rust" in safe_diagnostic
        and "[REDACTED]" not in safe_diagnostic,
        "Docker build diagnostics were not reduced to safe actionable summaries",
    )
    _require(
        "private-input" not in _safe_build_diagnostics(
            b"error: couldn't read `../../private-input`: "
            b"No such file or directory (os error 2)\n"
        ),
        "Docker build diagnostics exposed a path outside the build context",
    )

    with tempfile.TemporaryDirectory(prefix="astatine-container-context-selftest.") as temp:
        fixture_root = Path(temp) / "repository"
        fixture_parent = Path(temp) / "build"
        fixture_files = {
            "Cargo.toml": "[package]\n",
            "Cargo.lock": "version = 4\n",
            "build.rs": "fn main() {}\n",
            "rust-toolchain.toml": "[toolchain]\nchannel = 'stable'\n",
            "src/main.rs": "fn main() {}\n",
            "deployments/mainnet.toml": "mainnet fixture\n",
            "deployments/testnet.toml": "testnet fixture\n",
            "deployments/README.md": "not a build input\n",
            "support/release-repository.txt": "owner/repository\n",
            "support/paste-shim/Cargo.toml": "[package]\n",
            "support/paste-shim/src/lib.rs": "// fixture\n",
            "support/linux/container-qualification.Dockerfile": "FROM scratch\n",
            "support/linux/container-entrypoint.sh": "#!/bin/sh\n",
            "support/linux/container-secret-service.py": "# fixture\n",
            "support/linux/container-state-probe.py": "# fixture\n",
            "support/linux/container-session.conf": "<busconfig/>\n",
        }
        for relative, contents in fixture_files.items():
            source = fixture_root / relative
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_text(contents, encoding="utf-8")
        fixture_parent.mkdir()
        fixture_context = _create_build_context(fixture_root, fixture_parent)
        _require(
            (fixture_context / "deployments" / "mainnet.toml").read_text(encoding="utf-8")
            == "mainnet fixture\n"
            and (fixture_context / "deployments" / "testnet.toml").read_text(encoding="utf-8")
            == "testnet fixture\n"
            and not (fixture_context / "deployments" / "README.md").exists(),
            "whitelisted build context omitted deployment inputs or copied extra docs",
        )

    out_of_order = CiSyntheticStateMachine()
    expect_rejected(
        lambda: out_of_order.advance("production-init-complete"),
        "CI lifecycle accepted an out-of-order production init",
    )
    incomplete = CiSyntheticStateMachine()
    incomplete.advance("keyring-bootstrapped")
    expect_rejected(incomplete.finish, "CI lifecycle accepted an incomplete run")

    no_unlock = CiSyntheticStateMachine()
    for stage in CI_SYNTHETIC_STAGES[:5]:
        no_unlock.advance(stage)
    expect_rejected(
        lambda: no_unlock.advance("manual-unlock"),
        "CI lifecycle accepted a post-recreation manual unlock stage",
    )
    expect_rejected(
        lambda: no_unlock.advance("post-unlock-recovery"),
        "CI lifecycle accepted a post-unlock recovery stage",
    )

    complete = CiSyntheticStateMachine()
    for stage in CI_SYNTHETIC_STAGES:
        complete.advance(stage)
    complete.finish()
    expect_rejected(
        lambda: complete.advance("manual-unlock"),
        "CI lifecycle advanced after completion",
    )
    expect_rejected(
        lambda: complete.advance("post-unlock-recovery"),
        "CI lifecycle accepted post-completion work",
    )

    hosted_environment = {
        "ASTATINE_CONTAINER_QUALIFICATION_MODE": "ci-synthetic",
        "GITHUB_ACTIONS": "true",
        "CI": "true",
        "RUNNER_ENVIRONMENT": "github-hosted",
        "RUNNER_OS": "Linux",
        "RUNNER_ARCH": "X64",
        "GITHUB_JOB": "container-lifecycle-ci-synthetic",
        "GITHUB_WORKSPACE": str(Path(__file__).resolve().parents[2]),
        "GITHUB_RUN_ID": "123456789",
        "GITHUB_RUN_ATTEMPT": "1",
    }
    with patch.object(os, "environ", hosted_environment):
        _preflight_github_hosted_runner()
        hosted_environment["RUNNER_ENVIRONMENT"] = "self-hosted"
        expect_rejected(
            _preflight_github_hosted_runner,
            "CI synthetic mode accepted a self-hosted runner",
        )
        hosted_environment["RUNNER_ENVIRONMENT"] = "github-hosted"
        hosted_environment["ASTATINE_CONTAINER_QUALIFICATION_MODE"] = ""
        expect_rejected(
            _preflight_github_hosted_runner,
            "CI synthetic mode accepted a missing explicit workflow marker",
        )

    runtime_qualification = ContainerQualification.__new__(ContainerQualification)
    runtime_qualification.container_name = "astatine-container-d2-fixture"
    runtime_qualification.volume_name = "astatine-container-d2-selftest-state"
    runtime_qualification.token = runtime_qualification.container_name.rsplit("-", 1)[-1]
    runtime_record = {
        "Name": "/astatine-container-d2-fixture",
        "Config": {
            "Labels": {
                DOCKER_LABEL: DOCKER_LABEL_VALUE,
                f"{DOCKER_LABEL}.id": "fixture",
            }
        },
        "HostConfig": {
            "NetworkMode": "none",
            "ReadonlyRootfs": True,
            "Privileged": False,
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges:true"],
            "PortBindings": None,
        },
        "Mounts": [
            {
                "Type": "volume",
                "Name": "astatine-container-d2-selftest-state",
                "Destination": "/state",
            },
            {"Type": "tmpfs", "Destination": "/run/astatine"},
        ],
    }

    def verify_runtime_record(record: dict[str, Any]) -> None:
        answers = [
            b"ubuntu|24.04|x86_64\n",
            json.dumps([record]).encode(),
        ]
        runtime_qualification._docker_ok = lambda _args, _stage: answers.pop(0)  # type: ignore[method-assign]
        runtime_qualification._verify_container_runtime()

    verify_runtime_record(runtime_record)
    unsafe_runtime = json.loads(json.dumps(runtime_record))
    unsafe_runtime["HostConfig"]["NetworkMode"] = "bridge"
    expect_rejected(
        lambda: verify_runtime_record(unsafe_runtime),
        "container runtime isolation accepted a networked container",
    )

    helper_path = Path(__file__).with_name("container-secret-service.py")
    spec = importlib.util.spec_from_file_location(
        "astatine_container_secret_service_selftest", helper_path
    )
    if spec is None or spec.loader is None:
        raise AssertionError("could not load the Secret Service helper for self-test")
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)

    seed = bytes(range(32))
    secret = seed.hex().encode("ascii")
    captured: dict[str, Any] = {}

    class FakeStdin:
        def write(self, value: bytes | bytearray) -> int:
            captured.setdefault("stdin", bytearray()).extend(value)
            return len(value)

        def flush(self) -> None:
            captured["flushed"] = True

        def close(self) -> None:
            captured["closed"] = True

    class FakeDaemon:
        def __init__(self, argv: list[str], **kwargs: object) -> None:
            captured["argv"] = list(argv)
            captured["kwargs"] = kwargs
            self.stdin = FakeStdin() if kwargs.get("stdin") == subprocess.PIPE else None

        def poll(self) -> None:
            return None

        def send_signal(self, _signum: int) -> None:
            return

        def wait(self, timeout: int | None = None) -> int:
            del timeout
            return 0

        def kill(self) -> None:
            return

    with tempfile.TemporaryDirectory(prefix="astatine-container-secret-selftest.") as temp:
        keyring_dir = Path(temp) / "keyrings"
        helper.KEYRING_DIR = keyring_dir
        original_spawn = helper._spawn_daemon
        observed_secret_buffers: list[bytearray] = []

        def observe_spawn(*, keyring_input: bytearray | None) -> Any:
            if keyring_input is None:
                raise AssertionError("synthetic bootstrap omitted the daemon stdin secret")
            observed_secret_buffers.append(keyring_input)
            return original_spawn(keyring_input=keyring_input)

        def wait_for_unlocked_collection(
            _process: object, *, expected_locked: bool
        ) -> None:
            if expected_locked:
                raise AssertionError("synthetic bootstrap unexpectedly requested a locked ring")
            keyring_dir.mkdir(mode=0o700)
            os.chmod(keyring_dir, 0o700)
            keyring = keyring_dir / "login.keyring"
            keyring.write_bytes(b"encrypted synthetic test keyring")
            os.chmod(keyring, 0o600)

        stdout = io.StringIO()
        stderr = io.StringIO()
        isolated_environment: dict[str, str] = {}
        with (
            patch.object(helper.secrets, "token_bytes", return_value=seed) as random_bytes,
            patch.object(helper.os, "environ", isolated_environment),
            patch.object(helper.subprocess, "Popen", FakeDaemon),
            patch.object(helper, "_service_owned", return_value=False),
            patch.object(helper, "_wait_for_collection", wait_for_unlocked_collection),
            patch.object(helper, "_spawn_daemon", observe_spawn),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            helper._bootstrap_synthetic()

        _require(random_bytes.call_args.args == (32,), "bootstrap used an unexpected random source size")
        _require(
            captured.get("stdin") == secret + b"\n"
            and captured.get("flushed") is True
            and captured.get("closed") is True,
            "synthetic passphrase was not sent only through the daemon stdin pipe",
        )
        _require(
            "--unlock" in captured.get("argv", [])
            and secret not in repr(captured.get("argv", [])).encode()
            and "env" not in captured.get("kwargs", {})
            and all(secret.decode("ascii") not in value for value in isolated_environment.values()),
            "synthetic passphrase was exposed in daemon arguments or a supplied environment",
        )
        _require(
            captured.get("kwargs", {}).get("stdin") == subprocess.PIPE
            and captured.get("kwargs", {}).get("stdout") == subprocess.DEVNULL
            and captured.get("kwargs", {}).get("stderr") == subprocess.DEVNULL,
            "synthetic keyring daemon did not use a private stdin-only secret channel",
        )
        _require(
            len(observed_secret_buffers) == 1
            and not any(observed_secret_buffers[0]),
            "synthetic passphrase buffer was not erased after bootstrap",
        )
        output = stdout.getvalue().encode() + stderr.getvalue().encode()
        _require(secret not in output, "synthetic passphrase appeared in helper output")
        _require(
            all(secret not in path.read_bytes() for path in Path(temp).rglob("*") if path.is_file()),
            "synthetic passphrase appeared in a filesystem artifact",
        )
        _require(
            output.decode().strip() == "secret-service=unlocked synthetic-keyring=created",
            "synthetic bootstrap emitted an unexpected marker",
        )

        expect_rejected(
            helper._require_new_keyring_location,
            "synthetic bootstrap would accept an existing keyring directory",
            (helper.ServiceError,),
        )


def _run_cleanup_self_tests() -> None:
    import io
    from contextlib import redirect_stderr, redirect_stdout

    names = {
        "container": "astatine-container-d2-selftest",
        "volume": "astatine-container-d2-selftest-state",
        "image": "astatine-container-d2:selftest",
    }

    class MockDocker:
        def __init__(
            self,
            kind: str,
            *,
            present: bool = True,
            failure: bytes | None = None,
            fail_inspection: int | None = None,
            removal_status: int = 0,
            retain_after_removal: bool = False,
        ) -> None:
            self.kind = kind
            self.present = present
            self.failure = failure
            self.fail_inspection = fail_inspection
            self.removal_status = removal_status
            self.retain_after_removal = retain_after_removal
            self.inspect_count = 0
            self.remove_count = 0

        def __call__(self, args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
            if self.kind == "container":
                inspecting = args[:1] == ["inspect"]
                removing = args[:1] == ["rm"]
            elif self.kind == "volume":
                inspecting = args[:2] == ["volume", "inspect"]
                removing = args[:2] == ["volume", "rm"]
            else:
                inspecting = args[:2] == ["image", "inspect"]
                removing = args[:2] == ["image", "rm"]

            if inspecting:
                self.inspect_count += 1
                if self.fail_inspection == self.inspect_count:
                    return subprocess.CompletedProcess(args, 1, b"", self.failure or b"")
                if not self.present:
                    message = {
                        "container": f"Error: No such object: {names[self.kind]}",
                        "volume": (
                            "Error response from daemon: get "
                            f"{names[self.kind]}: no such volume"
                        ),
                        "image": f"Error: No such image: {names[self.kind]}",
                    }[self.kind]
                    return subprocess.CompletedProcess(args, 1, b"", message.encode())

                labels = {
                    DOCKER_LABEL: DOCKER_LABEL_VALUE,
                    f"{DOCKER_LABEL}.id": "selftest",
                }
                if self.kind == "container":
                    data: object = [
                        {
                            "Name": f"/{names[self.kind]}",
                            "Config": {"Labels": labels},
                            "Mounts": [
                                {
                                    "Type": "volume",
                                    "Name": names["volume"],
                                    "Destination": "/state",
                                }
                            ],
                            "State": {"Running": False},
                        }
                    ]
                elif self.kind == "volume":
                    data = [{"Name": names[self.kind], "Labels": labels}]
                else:
                    data = labels
                return subprocess.CompletedProcess(
                    args, 0, json.dumps(data).encode(), b""
                )

            if removing:
                self.remove_count += 1
                if self.removal_status == 0 and not self.retain_after_removal:
                    self.present = False
                return subprocess.CompletedProcess(
                    args, self.removal_status, b"", b"mock removal failure"
                )
            raise AssertionError("unexpected mocked Docker command")

    def make_qualification() -> ContainerQualification:
        qualification = ContainerQualification.__new__(ContainerQualification)
        qualification.token = names["container"].split("-")[-1]
        qualification.container_name = names["container"]
        qualification.volume_name = names["volume"]
        qualification.image_tag = names["image"]
        qualification.image_requested = True
        qualification.work = None
        qualification.success = False
        return qualification

    def remove(qualification: ContainerQualification, kind: str) -> None:
        getattr(qualification, f"_remove_{kind}")()

    original_docker = globals()["_docker"]
    try:
        for kind in ("container", "volume", "image"):
            for diagnostic in (
                b"Error response from daemon: connection refused",
                b"permission denied while connecting to Docker",
            ):
                mock = MockDocker(
                    kind, failure=diagnostic, fail_inspection=1
                )
                globals()["_docker"] = mock
                try:
                    remove(make_qualification(), kind)
                except QualificationError:
                    pass
                else:
                    raise AssertionError(f"{kind} inspection error was treated as missing")
                _require(mock.remove_count == 0, f"{kind} was removed after an inspection error")

            missing = MockDocker(kind, present=False)
            globals()["_docker"] = missing
            remove(make_qualification(), kind)
            _require(
                missing.remove_count == 0 and missing.inspect_count == 1,
                f"confirmed missing {kind} was not handled safely",
            )

            successful = MockDocker(kind)
            globals()["_docker"] = successful
            remove(make_qualification(), kind)
            _require(
                successful.remove_count == 1
                and successful.inspect_count == 2
                and not successful.present,
                f"{kind} removal was not verified absent",
            )

            post_inspection_error = MockDocker(
                kind,
                failure=b"permission denied during verification",
                fail_inspection=2,
            )
            globals()["_docker"] = post_inspection_error
            try:
                remove(make_qualification(), kind)
            except QualificationError:
                pass
            else:
                raise AssertionError(f"{kind} post-removal inspection error was ignored")

            still_present = MockDocker(kind, retain_after_removal=True)
            globals()["_docker"] = still_present
            try:
                remove(make_qualification(), kind)
            except QualificationError:
                pass
            else:
                raise AssertionError(f"remaining {kind} was reported removed")

        reporting = make_qualification()
        reporting._cleanup = lambda: ["container"]  # type: ignore[method-assign]
        reporting.success = True
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            reported_clean = reporting._report_cleanup()
        _require(not reported_clean, "cleanup errors were reported as successful")
        _require(
            "container-fixture-cleanup=ok" not in stdout.getvalue(),
            "cleanup success marker was emitted after an error",
        )

        class FailedCleanup:
            success = True

            def run(self) -> None:
                return

            def _report_cleanup(self) -> bool:
                print(
                    "container-qualification: cleanup failed for owned container",
                    file=sys.stderr,
                )
                return False

        saved_argv = sys.argv
        saved_globals = {
            name: globals()[name]
            for name in (
                "_preflight",
                "ContainerQualification",
                "_SIGNAL_REQUESTED",
                "_CLEANUP_IN_PROGRESS",
                "_ACTIVE_DOCKER_PROCESS",
                "_ACTIVE_CHILD_PID",
            )
        }
        saved_handlers = {
            signum: signal.getsignal(signum)
            for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
        }
        try:
            globals()["_preflight"] = lambda: None
            globals()["ContainerQualification"] = FailedCleanup
            sys.argv = ["qualify-container-lifecycle.py"]
            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                status = main()
            _require(status == 1, "cleanup failure did not make the fixture exit nonzero")
            _require(
                "container-fixture-cleanup=ok" not in stdout.getvalue(),
                "fixture printed cleanup success after a cleanup failure",
            )
        finally:
            sys.argv = saved_argv
            for name, value in saved_globals.items():
                globals()[name] = value
            for signum, handler in saved_handlers.items():
                signal.signal(signum, handler)
    finally:
        globals()["_docker"] = original_docker


def main() -> int:
    if sys.argv[1:] == ["--self-test-cleanup"]:
        try:
            _run_cleanup_self_tests()
        except BaseException as error:
            print(
                f"container-cleanup-self-test: failed ({type(error).__name__})",
                file=sys.stderr,
            )
            return 1
        print("container-cleanup-self-test=ok")
        return 0
    if sys.argv[1:] == ["--self-test-ci"]:
        try:
            _run_ci_self_tests()
        except BaseException as error:
            print(
                f"container-ci-self-test: failed ({type(error).__name__})",
                file=sys.stderr,
            )
            return 1
        print("container-ci-self-test=ok")
        return 0
    global _SIGNAL_REQUESTED, _CLEANUP_IN_PROGRESS
    global _ACTIVE_DOCKER_PROCESS, _ACTIVE_CHILD_PID
    if sys.argv[1:] == []:
        mode = "manual"
    elif sys.argv[1:] == ["--ci-synthetic"]:
        mode = "ci-synthetic"
    else:
        print(
            "usage: python3 support/linux/qualify-container-lifecycle.py "
            "[--ci-synthetic|--self-test-cleanup|--self-test-ci]",
            file=sys.stderr,
        )
        return 2
    os.umask(0o077)
    _SIGNAL_REQUESTED = None
    _CLEANUP_IN_PROGRESS = False
    _ACTIVE_DOCKER_PROCESS = None
    _ACTIVE_CHILD_PID = None
    for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(signum, _record_signal)

    qualification: ContainerQualification | None = None
    result = 1
    try:
        _check_cancelled()
        if mode == "manual":
            _preflight()
        else:
            _preflight(mode=mode)
        _check_cancelled()
        qualification = ContainerQualification()
        if mode == "manual":
            qualification.run()
        else:
            qualification.run(mode=mode)
        _check_cancelled()
        result = 0
    except QualificationCancelled as error:
        result = 128 + error.signum
    except QualificationError as error:
        print(f"container-qualification: {error}", file=sys.stderr)
        result = 1
    except KeyboardInterrupt:
        print("container-qualification: interrupted", file=sys.stderr)
        result = 130
    except BaseException as error:  # final boundary deliberately omits child output
        print(
            f"container-qualification: unexpected failure ({type(error).__name__})",
            file=sys.stderr,
        )
        result = 1
    finally:
        _protect_cleanup_from_signals()
        if qualification is not None and not qualification._report_cleanup():
            result = 1
        if _SIGNAL_REQUESTED is not None:
            try:
                name = signal.Signals(_SIGNAL_REQUESTED).name
            except ValueError:
                name = f"signal {_SIGNAL_REQUESTED}"
            print(f"container-qualification: interrupted by {name}", file=sys.stderr)
            result = 128 + _SIGNAL_REQUESTED
    return result


if __name__ == "__main__":
    raise SystemExit(main())
