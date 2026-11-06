# --- web UI ---
FROM docker.io/library/node:26-slim@sha256:5adad64f9a1fca2d51972caa65983634c8a774eb300d72b20f7f2a0f60368072 AS web
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci --no-fund --no-audit
COPY web/ ./
RUN npm run build

# --- manufacturer names (IEEE MAC address registry, public data) ---
# An image of the one file, /oui.csv (oui/Dockerfile), published monthly by
# .github/workflows/oui.yml: building apctl never downloads the list, so the IEEE
# server being down fails only a monthly refresh. Renovate brings each new list as
# a digest bump, which the Image workflow builds.
FROM ghcr.io/trexx/rust-apctl-oui:latest@sha256:1663fd97dfb203554f15730773e184ba49e5a98b996ae6d6ac3dc6ec1388456a AS oui

# --- controller ---
# The dependencies build from the manifests alone, every crate's own source replaced by
# an empty one: that stage does not wait for the web UI, and a code change leaves it
# cached. The skeleton stage runs on every change but makes the same files.
FROM docker.io/library/rust:1.99-bookworm@sha256:7085845219c18e7c5b1f34ed9ce89b84f822f2e3d54a02774cedc996ac0f304f AS skeleton
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
RUN for c in crates/*; do \
        targets=$(cd "$c" && ls src/lib.rs src/main.rs 2>/dev/null || true); \
        find "$c" -mindepth 1 -maxdepth 1 ! -name Cargo.toml -exec rm -rf {} +; \
        mkdir "$c/src"; \
        for t in $targets; do \
            case $t in *main.rs) echo 'fn main() {}' ;; *) : ;; esac > "$c/$t"; \
        done; \
    done

# The registry and target directory persist between builds (BuildKit cache
# mounts), so a code change recompiles our crates, not every dependency. The
# target directory is not part of the image: the binary is copied out of it.
# CARGO_BUILD_JOBS limits cargo on a machine short of memory (--build-arg).
# cargo auditable embeds the list of crates in the binary, where the image scan
# (.github/workflows/trivy.yml) reads it: the scan covers exactly the crates that ship.
FROM docker.io/library/rust:1.99-bookworm@sha256:7085845219c18e7c5b1f34ed9ce89b84f822f2e3d54a02774cedc996ac0f304f AS deps
RUN cargo install --locked cargo-auditable@0.7.6
WORKDIR /src
COPY --from=skeleton /src ./
ARG CARGO_BUILD_JOBS=default
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/target \
    cargo auditable build --release --locked -p controller

# The sources are touched: COPY keeps their times, which can be older than the empty
# ones', and cargo would take our crates as built. The release profile strips the binary.
FROM deps AS build
COPY crates/ crates/
COPY --from=web /web/dist web/dist
ARG CARGO_BUILD_JOBS=default
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/target \
    find crates -name '*.rs' -exec touch {} + \
    && cargo auditable build --release --locked -p controller && cp target/release/apctl /apctl
# The data directory, empty: the runtime image has no shell to make it. Owned by the
# controller's user there, which Docker copies to a new named volume mounted on it.
RUN mkdir -p /rootfs/data

# --- capture sidecar for shadow mode: tcpdump writing pcap into a FIFO ---
FROM docker.io/library/alpine:3.24@sha256:3f4d6b32e26703c6082839234f43769d5046b3ac7c910033911d1e71d8cd630a AS capture
RUN apk add --no-cache tcpdump
# The FIFO must be readable by the non-root controller. Alpine's tcpdump keeps
# its user (no -Z), which matters: switching user needs CAP_SETUID, and the pod
# only grants NET_RAW and NET_ADMIN. -p: the "any" device has no promiscuous mode.
ENTRYPOINT ["/bin/sh", "-c", "[ -p \"$FIFO\" ] || mkfifo -m 644 \"$FIFO\"; exec tcpdump -p -i any -U -s 0 -w \"$FIFO\" \"$FILTER\""]

# --- runtime ---
FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f AS runtime
COPY --from=build /apctl /usr/local/bin/apctl
COPY --from=oui /oui.csv /usr/share/apctl/oui.csv
COPY --from=build --chown=65532:65532 /rootfs/ /
USER nonroot
ENV APCTL_DATA_DIR=/data APCTL_LISTEN=0.0.0.0:8090
EXPOSE 8090
ENTRYPOINT ["/usr/local/bin/apctl"]
CMD ["serve"]
