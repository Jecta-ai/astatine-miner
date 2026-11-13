#!/usr/bin/env bash
# Minimal SSH loopback PTY smoke test for the Linux qualification workflow.
#
# This does not test wallet prompts or any application secret. It proves that a
# disposable sshd bound only to 127.0.0.1 can authenticate with an ephemeral
# key and allocate a PTY whose /dev/tty is usable. All key material lives under
# RUNNER_TEMP and is removed by the trap.
set -euo pipefail
umask 077

if [[ "$(uname -s)" != "Linux" ]]; then
    printf 'ssh-loopback: Linux is required\n' >&2
    exit 1
fi
if [[ "${GITHUB_ACTIONS:-}" != "true" && "${ASTATINE_ALLOW_SSH_SMOKE:-}" != "1" ]]; then
    printf 'ssh-loopback: refusing to create a disposable system user outside a disposable CI runner; set ASTATINE_ALLOW_SSH_SMOKE=1 to override\n' >&2
    exit 1
fi
for tool in ssh ssh-keygen sudo python3 useradd userdel chpasswd passwd; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        printf 'ssh-loopback: required tool is missing: %s\n' "$tool" >&2
        exit 1
    fi
done
if ! sudo -n true 2>/dev/null; then
    printf 'ssh-loopback: passwordless sudo is required to start the disposable sshd\n' >&2
    exit 1
fi

caller="$(id -un)"
if [[ -z "$caller" || "$caller" == "root" ]]; then
    printf 'ssh-loopback: a non-root caller is required\n' >&2
    exit 1
fi

work="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/astatine-ssh.XXXXXX")"
sshd_pid=""
launcher_pid=""
smoke_user="astatine-ssh-$(python3 -c 'import secrets; print(secrets.token_hex(4))')"
created_user="false"
stop_sshd() {
    local pid="$1"
    [[ -z "$pid" ]] && return 0
    sudo kill "$pid" 2>/dev/null || true
    local attempt
    for attempt in $(seq 1 50); do
        local state
        state="$(awk '{print $3}' "/proc/$pid/stat" 2>/dev/null || true)"
        if [[ -z "$state" || "$state" == "Z" ]]; then
            return 0
        fi
        sleep 0.1
    done
    sudo kill -KILL "$pid" 2>/dev/null || true
}
cleanup() {
    set +e
    if [[ -n "$sshd_pid" ]]; then
        stop_sshd "$sshd_pid"
    fi
    if [[ -n "$launcher_pid" && "$launcher_pid" != "$sshd_pid" ]]; then
        stop_sshd "$launcher_pid"
        wait "$launcher_pid" 2>/dev/null
    fi
    if [[ "$created_user" == "true" ]] && id "$smoke_user" >/dev/null 2>&1; then
        sudo userdel -r "$smoke_user" >/dev/null 2>&1
    fi
    rm -rf "$work"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
chmod 700 "$work"

if id "$smoke_user" >/dev/null 2>&1; then
    printf 'ssh-loopback: random disposable user unexpectedly exists: %s\n' "$smoke_user" >&2
    exit 1
fi
if ! sudo useradd -m -s /bin/bash "$smoke_user"; then
    printf 'ssh-loopback: could not create the disposable user\n' >&2
    exit 1
fi
created_user="true"
if ! id "$smoke_user" >/dev/null 2>&1; then
    printf 'ssh-loopback: disposable user was not created\n' >&2
    exit 1
fi
smoke_password="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
printf '%s:%s\n' "$smoke_user" "$smoke_password" | sudo chpasswd
unset smoke_password
account_state="$(sudo passwd -S "$smoke_user" | awk '{print $2}')"
if [[ "$account_state" != "P" ]]; then
    printf 'ssh-loopback: disposable user must have a non-empty, non-locked password marker\n' >&2
    exit 1
fi
target_user="$smoke_user"

ssh-keygen -q -t ed25519 -N '' -f "$work/host_ed25519"
ssh-keygen -q -t ed25519 -N '' -f "$work/user_ed25519"
cp "$work/user_ed25519.pub" "$work/authorized_keys"
chmod 711 "$work"
chmod 644 "$work/authorized_keys"

port="$(python3 - <<'PY'
import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind(("127.0.0.1", 0))
print(sock.getsockname()[1])
sock.close()
PY
)"
printf '[127.0.0.1]:%s %s\n' "$port" "$(cat "$work/host_ed25519.pub")" >"$work/known_hosts"

sshd_config="$work/sshd_config"
cat >"$sshd_config" <<EOF
Port $port
ListenAddress 127.0.0.1
HostKey $work/host_ed25519
PidFile $work/sshd.pid
AuthorizedKeysFile $work/authorized_keys
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
PubkeyAuthentication yes
PermitEmptyPasswords no
UsePAM no
PermitRootLogin no
AllowUsers $target_user
StrictModes no
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
AllowStreamLocalForwarding no
PermitTunnel no
GatewayPorts no
LogLevel ERROR
EOF

SSHD="/usr/sbin/sshd"
if [[ ! -x "$SSHD" ]]; then
    printf 'ssh-loopback: trusted sshd is missing: %s\n' "$SSHD" >&2
    exit 1
fi
sudo mkdir -p /run/sshd
sudo "$SSHD" -t -f "$sshd_config"
sudo "$SSHD" -D -e -f "$sshd_config" >"$work/sshd.log" 2>&1 &
launcher_pid="$!"
for _ in $(seq 1 50); do
    if [[ -s "$work/sshd.pid" ]]; then
        sshd_pid="$(head -n 1 "$work/sshd.pid")"
        break
    fi
    sleep 0.1
done
if [[ -z "$sshd_pid" ]]; then
    printf 'ssh-loopback: disposable sshd did not write its pid file\n' >&2
    sed -n '1,40p' "$work/sshd.log" >&2 || true
    exit 1
fi

ssh_options=(
    -F /dev/null
    -p "$port"
    -i "$work/user_ed25519"
    -o IdentitiesOnly=yes
    -o BatchMode=yes
    -o StrictHostKeyChecking=yes
    -o UserKnownHostsFile="$work/known_hosts"
    -o ConnectTimeout=2
    -o LogLevel=ERROR
)

ready=false
for _ in $(seq 1 50); do
    if ssh "${ssh_options[@]}" -n "$target_user@127.0.0.1" true >/dev/null 2>&1; then
        ready=true
        break
    fi
    sleep 0.2
done
if [[ "$ready" != "true" ]]; then
    printf 'ssh-loopback: disposable sshd did not accept a loopback key login\n' >&2
    sed -n '1,40p' "$work/sshd.log" >&2 || true
    exit 1
fi
if command -v ss >/dev/null 2>&1; then
    listeners="$(ss -ltnH "sport = :$port" 2>/dev/null | awk '{print $4}' | sort -u)"
    if [[ -z "$listeners" || "$listeners" != "127.0.0.1:$port" ]]; then
        printf 'ssh-loopback: disposable sshd is not bound exclusively to 127.0.0.1:%s: %s\n' "$port" "$listeners" >&2
        exit 1
    fi
fi

remote_command='set -eu; [ -t 0 ]; [ -t 1 ]; [ -r /dev/tty ]; [ -w /dev/tty ]; case "$(tty)" in /dev/pts/*) ;; *) exit 1;; esac; printf "ssh-loopback-pty-ok\n"'
output="$(SSH_AUTH_SOCK= ssh -tt "${ssh_options[@]}" "$target_user@127.0.0.1" "$remote_command" </dev/null)"
if ! grep -q 'ssh-loopback-pty-ok' <<<"$output"; then
    printf 'ssh-loopback: expected PTY marker was not returned\n' >&2
    printf '%s\n' "$output" >&2
    exit 1
fi

printf 'ssh-loopback: PTY and /dev/tty verified over a loopback-only disposable sshd\n'
