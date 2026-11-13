#!/usr/bin/env bash
# Run one command inside a disposable, private D-Bus session and keyring HOME.
#
# Modes:
#   provider  Start an unlocked disposable GNOME Keyring (Secret Service).
#   locked    Create it unlocked, stop the daemon, restart without the password,
#             and verify the default collection is genuinely locked.
#   missing   Start no provider on a private bus with no service activation.
#
# The script never prints or exports the disposable keyring password. It creates
# a private session bus, isolated HOME/XDG/TMPDIR, and a bounded command timeout.
set -euo pipefail
umask 077

usage() {
    printf 'usage: %s {provider|locked|missing} -- COMMAND [ARGS...]\n' "$0" >&2
    exit 2
}

if [[ $# -lt 3 ]]; then
    usage
fi
mode="$1"
shift
if [[ "${1:-}" != "--" ]]; then
    usage
fi
shift
if [[ $# -eq 0 ]]; then
    usage
fi

case "$mode" in
    provider|locked|missing) ;;
    *)
        usage
        ;;
esac

# The ambient Secret Service probes use this exact marker to prove they are
# running against a disposable fixture, not a personal keyring.
export ASTATINE_DISPOSABLE_CREDENTIAL_STORE=1

if [[ "$(uname -s)" != "Linux" ]]; then
    printf 'linux-qualification: Linux is required (got %s)\n' "$(uname -s)" >&2
    exit 1
fi

for tool in dbus-daemon gdbus python3 timeout; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        printf 'linux-qualification: required tool is missing: %s\n' "$tool" >&2
        exit 1
    fi
done
if [[ "$mode" != "missing" ]] && ! command -v gnome-keyring-daemon >/dev/null 2>&1; then
    printf 'linux-qualification: gnome-keyring-daemon is required for mode %s\n' "$mode" >&2
    exit 1
fi

original_home="${HOME:-}"
if [[ -z "$original_home" ]]; then
    printf 'linux-qualification: HOME must identify the real toolchain home\n' >&2
    exit 1
fi
if [[ -z "${CARGO_HOME:-}" ]]; then
    export CARGO_HOME="$original_home/.cargo"
fi
if [[ -z "${RUSTUP_HOME:-}" ]]; then
    export RUSTUP_HOME="$original_home/.rustup"
fi
if [[ -z "${PATH:-}" ]]; then
    export PATH="$original_home/.cargo/bin:/usr/local/bin:/usr/bin:/bin"
fi

base="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
work="$(mktemp -d "$base/astatine-linux-qualification.XXXXXX")"
bus_pid=""
keyring_pid=""
stop_pid() {
    local pid="$1"
    [[ -z "$pid" ]] && return 0
    kill "$pid" 2>/dev/null || true
    local attempt
    for attempt in $(seq 1 50); do
        local state
        state="$(awk '{print $3}' "/proc/$pid/stat" 2>/dev/null || true)"
        if [[ -z "$state" || "$state" == "Z" ]]; then
            return 0
        fi
        sleep 0.1
    done
    kill -KILL "$pid" 2>/dev/null || true
}
cleanup() {
    set +e
    if [[ -n "$keyring_pid" ]]; then
        stop_pid "$keyring_pid"
        wait "$keyring_pid" 2>/dev/null
    fi
    if [[ -z "$bus_pid" && -n "${pid_file:-}" && -s "$pid_file" ]]; then
        bus_pid="$(head -n 1 "$pid_file")"
    fi
    if [[ -z "$bus_pid" && -n "${bus_config:-}" ]] && command -v pgrep >/dev/null 2>&1; then
        bus_pid="$(pgrep -f "dbus-daemon --config-file=$bus_config" | head -n 1 || true)"
    fi
    if [[ -n "$bus_pid" ]]; then
        stop_pid "$bus_pid"
        wait "$bus_pid" 2>/dev/null
    fi
    rm -rf "$work"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

mkdir -p "$work/home" "$work/bus" "$work/tmp" "$work/runtime"
chmod 700 "$work/home" "$work/bus" "$work/tmp" "$work/runtime"
export HOME="$work/home"
export XDG_CONFIG_HOME="$work/home/.config"
export XDG_DATA_HOME="$work/home/.local/share"
export XDG_CACHE_HOME="$work/home/.cache"
export XDG_RUNTIME_DIR="$work/runtime"
export TMPDIR="$work/tmp"
mkdir -p "$XDG_CONFIG_HOME" "$XDG_DATA_HOME" "$XDG_CACHE_HOME"
chmod 700 "$XDG_CONFIG_HOME" "$XDG_DATA_HOME" "$XDG_CACHE_HOME"

unset DBUS_SESSION_BUS_ADDRESS DBUS_STARTER_ADDRESS DBUS_STARTER_BUS_TYPE
unset GNOME_KEYRING_CONTROL GNOME_KEYRING_PID SSH_AUTH_SOCK

bus_config="$work/session.conf"
cat >"$bus_config" <<EOF
<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>session</type>
  <listen>unix:dir=$work/bus</listen>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow send_destination="*" eavesdrop="true"/>
    <allow eavesdrop="true"/>
    <allow own="*"/>
  </policy>
</busconfig>
EOF

address_file="$work/bus-address"
pid_file="$work/bus-pid"
dbus-daemon --config-file="$bus_config" --fork \
    --print-address=3 --print-pid=4 3>"$address_file" 4>"$pid_file"
DBUS_SESSION_BUS_ADDRESS="$(head -n 1 "$address_file")"
bus_pid="$(head -n 1 "$pid_file")"
export DBUS_SESSION_BUS_ADDRESS
if [[ -z "$bus_pid" && -s "$pid_file" ]]; then
    bus_pid="$(head -n 1 "$pid_file")"
fi
if [[ -z "$bus_pid" ]] && command -v pgrep >/dev/null 2>&1; then
    bus_pid="$(pgrep -f "dbus-daemon --config-file=$bus_config" | head -n 1 || true)"
fi
if [[ -z "$DBUS_SESSION_BUS_ADDRESS" || -z "$bus_pid" ]]; then
    printf 'linux-qualification: private D-Bus session did not start\n' >&2
    exit 1
fi

secret_service_owned() {
    gdbus call --session \
        --dest org.freedesktop.DBus \
        --object-path /org/freedesktop/DBus \
        --method org.freedesktop.DBus.NameHasOwner \
        org.freedesktop.secrets 2>/dev/null | grep -q 'true'
}

wait_for_secret_service() {
    local attempt
    for attempt in $(seq 1 100); do
        if secret_service_owned; then
            return 0
        fi
        sleep 0.1
    done
    return 1
}

default_collection_path() {
    local output
    output="$(gdbus call --session \
        --dest org.freedesktop.secrets \
        --object-path /org/freedesktop/secrets \
        --method org.freedesktop.Secret.Service.ReadAlias default 2>/dev/null)"
    printf '%s\n' "$output" | sed -n "s/.*objectpath '\([^']*\)'.*/\1/p"
}

collection_is_locked() {
    local path="$1"
    gdbus call --session \
        --dest org.freedesktop.secrets \
        --object-path "$path" \
        --method org.freedesktop.DBus.Properties.Get \
        org.freedesktop.Secret.Collection Locked 2>/dev/null | grep -q 'true'
}

start_keyring_unlocked() {
    local password
    password="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
    printf '%s\n' "$password" | \
        gnome-keyring-daemon --components=secrets --foreground --unlock \
        >/dev/null 2>"$work/keyring.log" &
    keyring_pid="$!"
    unset password
    if ! wait_for_secret_service; then
        printf 'linux-qualification: org.freedesktop.secrets did not appear\n' >&2
        return 1
    fi
    if ! kill -0 "$keyring_pid" 2>/dev/null; then
        printf 'linux-qualification: the disposable keyring exited during startup\n' >&2
        return 1
    fi
}

start_keyring_locked() {
    gnome-keyring-daemon --components=secrets --foreground \
        >/dev/null 2>"$work/keyring.log" &
    keyring_pid="$!"
    if ! wait_for_secret_service; then
        printf 'linux-qualification: org.freedesktop.secrets did not appear in the locked phase\n' >&2
        return 1
    fi
    if ! kill -0 "$keyring_pid" 2>/dev/null; then
        printf 'linux-qualification: the locked keyring exited during startup\n' >&2
        return 1
    fi
}

stop_keyring() {
    if [[ -z "$keyring_pid" ]]; then
        return 0
    fi
    stop_pid "$keyring_pid"
    wait "$keyring_pid" 2>/dev/null || true
    keyring_pid=""
    local attempt
    for attempt in $(seq 1 100); do
        if ! secret_service_owned; then
            return 0
        fi
        sleep 0.1
    done
    printf 'linux-qualification: the previous keyring process still owns the bus\n' >&2
    return 1
}

case "$mode" in
    provider)
        start_keyring_unlocked
        default_path="$(default_collection_path)"
        if [[ -z "$default_path" ]]; then
            printf 'linux-qualification: unlocked provider has no default collection\n' >&2
            exit 1
        fi
        if collection_is_locked "$default_path"; then
            printf 'linux-qualification: provider default collection is unexpectedly locked\n' >&2
            exit 1
        fi
        export ASTATINE_REQUIRE_NATIVE_CREDENTIAL_STORE=1
        printf 'linux-qualification: provider=unlocked default_collection=%s\n' "$default_path"
        ;;
    locked)
        start_keyring_unlocked
        default_path="$(default_collection_path)"
        if [[ -z "$default_path" ]]; then
            printf 'linux-qualification: cannot lock a missing default collection\n' >&2
            exit 1
        fi
        # A freshly locked collection can be transparently unlocked again by
        # the same daemon because it still holds the login password in memory.
        # Restart without the password so the on-disk collection is genuinely
        # locked for the client under test.
        stop_keyring
        start_keyring_locked
        default_path="$(default_collection_path)"
        if [[ -z "$default_path" ]]; then
            printf 'linux-qualification: locked provider has no default collection\n' >&2
            exit 1
        fi
        if ! collection_is_locked "$default_path"; then
            printf 'linux-qualification: default collection did not enter the locked state\n' >&2
            exit 1
        fi
        unset ASTATINE_REQUIRE_NATIVE_CREDENTIAL_STORE
        printf 'linux-qualification: provider=locked default_collection=%s\n' "$default_path"
        ;;
    missing)
        if secret_service_owned; then
            printf 'linux-qualification: a Secret Service unexpectedly owns the private bus\n' >&2
            exit 1
        fi
        unset ASTATINE_REQUIRE_NATIVE_CREDENTIAL_STORE
        printf 'linux-qualification: provider=missing (private bus, no activation)\n'
        ;;
esac

timeout_seconds="${ASTATINE_QUALIFICATION_TIMEOUT_SECONDS:-300}"
if ! [[ "$timeout_seconds" =~ ^[1-9][0-9]*$ ]]; then
    printf 'linux-qualification: invalid ASTATINE_QUALIFICATION_TIMEOUT_SECONDS\n' >&2
    exit 1
fi

export ASTATINE_QUALIFICATION_MODE="$mode"
printf 'linux-qualification: running bounded command (timeout %ss)\n' "$timeout_seconds"
timeout --signal=TERM --kill-after=10s "$timeout_seconds" "$@"
