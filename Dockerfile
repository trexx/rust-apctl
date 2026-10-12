# syntax=docker/dockerfile:1

# --- web UI ---
FROM docker.io/library/node:24-slim AS web
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-fund --no-audit
COPY web/ ./
RUN npm run build

# --- controller ---
FROM docker.io/library/rust:1.98-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
COPY --from=web /web/dist web/dist
RUN cargo build --release --locked -p controller && strip target/release/apctl

# --- capture sidecar for shadow mode: tcpdump writing pcap into a FIFO ---
FROM docker.io/library/alpine:3.22 AS capture
RUN apk add --no-cache tcpdump
# The FIFO must be readable by the non-root controller, and tcpdump must keep
# root (-Z root) to write it.
ENTRYPOINT ["/bin/sh", "-c", "[ -p \"$FIFO\" ] || mkfifo -m 644 \"$FIFO\"; exec tcpdump -Z root -i any -U -s 0 -w \"$FIFO\" \"$FILTER\""]

# --- runtime ---
FROM gcr.io/distroless/cc-debian12:nonroot AS runtime
COPY --from=build /src/target/release/apctl /usr/local/bin/apctl
USER nonroot
ENV APCTL_DATA_DIR=/data APCTL_LISTEN=0.0.0.0:8090
EXPOSE 8090
ENTRYPOINT ["/usr/local/bin/apctl", "serve"]
