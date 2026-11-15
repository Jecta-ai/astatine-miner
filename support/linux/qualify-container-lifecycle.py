#!/usr/bin/env python3
"""Exercise production CLI state across genuine Docker container recreation.

Run interactively on Ubuntu 24.04 x86_64 with a local Docker engine:

    python3 support/linux/qualify-container-lifecycle.py

Run the offline cleanup regression checks without Docker:

    python3 support/linux/qualify-container-lifecycle.py --self-test-cleanup

The fixture uses a random private Docker named volume, a fresh Ubuntu 24.04
amd64 image built from a whitelist-only context, and containers with no network,
ports, host mounts, or capabilities. It creates a synthetic wallet with the
production CLI, destroys and recreates the container while retaining the named
volume, checks unavailable and locked Secret Service fail-closed behavior, and
requires a real human to type the test-only keyring passphrase again at a hidden
terminal prompt before a fresh production `recover` process can succeed.

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


def _preflight() -> None:
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
    _require(
        sys.stdin.isatty() and sys.stdout.isatty(),
        "a real interactive terminal is required for the manual keyring unlock gate",
    )
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
        self._docker_ok(
            [
                "build",
                "--quiet",
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
            "production image build",
            timeout=TIMEOUT_BUILD_SECONDS,
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

    def run(self) -> None:
        _check_cancelled()
        self._build()
        self._create_volume()
        self._start_container()

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
        print("network=none public-rpc=not-used")
        self.success = True


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
    global _SIGNAL_REQUESTED, _CLEANUP_IN_PROGRESS
    global _ACTIVE_DOCKER_PROCESS, _ACTIVE_CHILD_PID
    if len(sys.argv) != 1:
        print(
            "usage: python3 support/linux/qualify-container-lifecycle.py "
            "[--self-test-cleanup]",
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
        _preflight()
        _check_cancelled()
        qualification = ContainerQualification()
        qualification.run()
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
