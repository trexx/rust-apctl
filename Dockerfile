# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e

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
# Manufacturer names (IEEE MAC address registry, public data).
RUN curl -fsSL -o /oui.csv https://standards-oui.ieee.org/oui/oui.csv

# --- capture sidecar for shadow mode: tcpdump writing pcap into a FIFO ---
FROM docker.io/library/alpine:3.22 AS capture
RUN apk add --no-cache tcpdump
# The FIFO must be readable by the non-root controller. Alpine's tcpdump keeps
# its user (no -Z), which matters: switching user needs CAP_SETUID, and the pod
# only grants NET_RAW and NET_ADMIN. -p: the "any" device has no promiscuous mode.
ENTRYPOINT ["/bin/sh", "-c", "[ -p \"$FIFO\" ] || mkfifo -m 644 \"$FIFO\"; exec tcpdump -p -i any -U -s 0 -w \"$FIFO\" \"$FILTER\""]

# --- runtime ---
FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f AS runtime
COPY --from=build /src/target/release/apctl /usr/local/bin/apctl
COPY --from=build /oui.csv /usr/share/apctl/oui.csv
USER nonroot
ENV APCTL_DATA_DIR=/data APCTL_LISTEN=0.0.0.0:8090
EXPOSE 8090
ENTRYPOINT ["/usr/local/bin/apctl"]
CMD ["serve"]
