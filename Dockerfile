# --- web UI ---
FROM docker.io/library/node:24-slim AS web
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-fund --no-audit
COPY web/ ./
RUN npm run build

# --- manufacturer names (IEEE MAC address registry, public data) ---
# A small stage of its own, so code changes don't download it again. The layer is
# cached until OUI_MONTH changes (scripts/release.sh passes the current month), so the
# list is at most about a month old. (The IEEE server answers 418 to the HTTP client
# behind ADD <url>, so busybox wget fetches it.)
FROM docker.io/library/alpine:3.22 AS oui
ARG OUI_MONTH=
RUN echo "registry of ${OUI_MONTH:-the first build}" \
    && wget -q -O /oui.csv https://standards-oui.ieee.org/oui/oui.csv \
    && head -1 /oui.csv | grep -q Assignment \
    && chmod 644 /oui.csv

# --- controller ---
FROM docker.io/library/rust:1.98-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
COPY --from=web /web/dist web/dist
# The registry and target directory persist between builds (BuildKit cache
# mounts), so a code change recompiles our crates, not every dependency. The
# target directory is not part of the image: the binary is copied out of it.
# The release profile strips the binary.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p controller && cp target/release/apctl /apctl

# --- capture sidecar for shadow mode: tcpdump writing pcap into a FIFO ---
FROM docker.io/library/alpine:3.22 AS capture
RUN apk add --no-cache tcpdump
# The FIFO must be readable by the non-root controller. Alpine's tcpdump keeps
# its user (no -Z), which matters: switching user needs CAP_SETUID, and the pod
# only grants NET_RAW and NET_ADMIN. -p: the "any" device has no promiscuous mode.
ENTRYPOINT ["/bin/sh", "-c", "[ -p \"$FIFO\" ] || mkfifo -m 644 \"$FIFO\"; exec tcpdump -p -i any -U -s 0 -w \"$FIFO\" \"$FILTER\""]

# --- runtime ---
FROM gcr.io/distroless/cc-debian12:nonroot AS runtime
COPY --from=build /apctl /usr/local/bin/apctl
COPY --from=oui /oui.csv /usr/share/apctl/oui.csv
USER nonroot
ENV APCTL_DATA_DIR=/data APCTL_LISTEN=0.0.0.0:8090
EXPOSE 8090
ENTRYPOINT ["/usr/local/bin/apctl"]
CMD ["serve"]
