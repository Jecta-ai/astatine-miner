#!/bin/sh
set -eu
umask 077

if [ "$(id -u)" -ne 10001 ]; then
    printf 'container-entrypoint: unexpected runtime uid\n' >&2
    exit 1
fi

for directory in \
    /state \
    /state/home \
    /state/home/.config \
    /state/home/.local/share \
    /state/home/.cache \
    /run/astatine
do
    if [ ! -d "$directory" ] || [ -L "$directory" ]; then
        printf 'container-entrypoint: private state directory is unavailable\n' >&2
        exit 1
    fi
    if [ "$(stat -c '%u' "$directory")" != "10001" ]; then
        printf 'container-entrypoint: private state directory has the wrong owner\n' >&2
        exit 1
    fi
    if [ "$(stat -c '%a' "$directory")" != "700" ]; then
        printf 'container-entrypoint: private state directory is not mode 0700\n' >&2
        exit 1
    fi
done

if [ -e /run/astatine/bus ] || [ -L /run/astatine/bus ]; then
    printf 'container-entrypoint: refusing an unexpected D-Bus socket path\n' >&2
    exit 1
fi

unset DBUS_STARTER_ADDRESS DBUS_STARTER_BUS_TYPE DBUS_SESSION_BUS_PID
unset GNOME_KEYRING_CONTROL GNOME_KEYRING_PID SSH_AUTH_SOCK SSH_AGENT_PID

dbus-daemon \
    --config-file=/etc/astatine/container-session.conf \
    --fork \
    --print-pid=1 \
    >/dev/null

exec /usr/bin/sleep infinity
