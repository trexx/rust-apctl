# --- web UI ---
FROM docker.io/library/node:26-slim@sha256:94816674c62774da0d099a947bf4613b9e1972a2733abd0d0cd80e795f8411d0 AS web
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci --no-fund --no-audit
COPY web/ ./
RUN npm run build

# --- manufacturer names (IEEE MAC address registry, public data) ---
# A small stage of its own, so code changes don't download it again. The layer is
# cached until OUI_MONTH changes (scripts/release.sh passes the current month), so the
# list is at most about a month old. CI images (trexx/actions' build workflow, which
# passes no build args) are built with a fresh builder and no layer cache, so they always
# download it. (The IEEE server answers 418 to the HTTP client behind ADD <url>, so
# busybox wget fetches it.) Each line is cut after the name: the controller reads no
# more (vendor.rs), and the addresses are much of the file.
FROM docker.io/library/alpine:3.24@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a AS oui
ARG OUI_MONTH=
RUN echo "registry of ${OUI_MONTH:-the first build}" \
    && wget -q -O /oui-full.csv https://standards-oui.ieee.org/oui/oui.csv \
    && head -1 /oui-full.csv | grep -q Assignment \
    && sed -E 's/^(MA-L,[0-9A-F]{6},("([^"]|"")*"|[^,]*)).*/\1/' /oui-full.csv > /oui.csv \
    && rm /oui-full.csv \
    && chmod 644 /oui.csv
# The data directory, empty: the runtime image has no shell to make it. Owned by the
# controller's user there, which Docker copies to a new named volume mounted on it.
RUN mkdir -p /rootfs/data

# --- controller ---
# The dependencies build from the manifests alone, every crate's own source replaced by
# an empty one: that stage does not wait for the web UI, and a code change leaves it
# cached. The skeleton stage runs on every change but makes the same files.
FROM docker.io/library/rust:1.99-bookworm@sha256:48b7f435b8fc6378ce43b44f15e3a47fd8919b2825f835c39bd4bd3da50af5b8 AS skeleton
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
FROM docker.io/library/rust:1.99-bookworm@sha256:48b7f435b8fc6378ce43b44f15e3a47fd8919b2825f835c39bd4bd3da50af5b8 AS deps
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

# --- capture sidecar for shadow mode: tcpdump writing pcap into a FIFO ---
FROM docker.io/library/alpine:3.24@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a AS capture
RUN apk add --no-cache tcpdump
# The FIFO must be readable by the non-root controller. Alpine's tcpdump keeps
# its user (no -Z), which matters: switching user needs CAP_SETUID, and the pod
# only grants NET_RAW and NET_ADMIN. -p: the "any" device has no promiscuous mode.
ENTRYPOINT ["/bin/sh", "-c", "[ -p \"$FIFO\" ] || mkfifo -m 644 \"$FIFO\"; exec tcpdump -p -i any -U -s 0 -w \"$FIFO\" \"$FILTER\""]

# --- runtime ---
FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f AS runtime
COPY --from=build /apctl /usr/local/bin/apctl
COPY --from=oui /oui.csv /usr/share/apctl/oui.csv
COPY --from=oui --chown=65532:65532 /rootfs/ /
USER nonroot
ENV APCTL_DATA_DIR=/data APCTL_LISTEN=0.0.0.0:8090
EXPOSE 8090
ENTRYPOINT ["/usr/local/bin/apctl"]
CMD ["serve"]
