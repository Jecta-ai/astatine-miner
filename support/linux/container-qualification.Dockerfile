FROM rust:1.94.1-bookworm AS build

WORKDIR /build
COPY Cargo.toml Cargo.lock build.rs rust-toolchain.toml ./
COPY src ./src
COPY deployments ./deployments
COPY support/release-repository.txt ./support/release-repository.txt
COPY support/paste-shim ./support/paste-shim
RUN cargo build --locked --release --bin astatine \
    && install -D -m 0755 target/release/astatine /out/astatine

FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates dbus gnome-keyring libglib2.0-bin python3 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 astatine \
    && useradd --uid 10001 --gid 10001 --home-dir /state/home \
        --no-create-home --shell /usr/sbin/nologin astatine \
    && install -d -o 10001 -g 10001 -m 0700 \
        /state /state/home /state/home/.config \
        /state/home/.local/share /state/home/.cache /run/astatine \
    && install -d -o root -g root -m 0755 /etc/astatine

COPY --from=build --chown=root:root /out/astatine /usr/local/bin/astatine
COPY --chown=root:root support/linux/container-entrypoint.sh \
    /usr/local/sbin/container-entrypoint
COPY --chown=root:root support/linux/container-secret-service.py \
    /usr/local/lib/astatine-container/container-secret-service.py
COPY --chown=root:root support/linux/container-state-probe.py \
    /usr/local/lib/astatine-container/container-state-probe.py
COPY --chown=root:root support/linux/container-session.conf \
    /etc/astatine/container-session.conf
RUN chmod 0755 /usr/local/sbin/container-entrypoint \
    && chmod 0644 /usr/local/lib/astatine-container/*.py \
    && chmod 0644 /etc/astatine/container-session.conf

LABEL org.astatine.qualification="container-d2"
ENV HOME=/state/home \
    XDG_CONFIG_HOME=/state/home/.config \
    XDG_DATA_HOME=/state/home/.local/share \
    XDG_CACHE_HOME=/state/home/.cache \
    XDG_RUNTIME_DIR=/run/astatine \
    TMPDIR=/tmp \
    DBUS_SESSION_BUS_ADDRESS=unix:path=/run/astatine/bus \
    PATH=/usr/local/bin:/usr/bin:/bin

USER 10001:10001
ENTRYPOINT ["/usr/local/sbin/container-entrypoint"]
