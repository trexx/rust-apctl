# The manufacturer names (IEEE MAC address registry, public data), as an image of one
# file, /oui.csv, that the main Dockerfile's `oui` stage pins by digest. Fetched
# monthly by .github/workflows/oui.yml and published when it changed, so building apctl
# never downloads the list and an IEEE outage fails only this month's refresh, which
# keeps the last list.
# (The IEEE server answers 418 to the HTTP client behind ADD <url>, so busybox wget
# fetches it.) Each line is cut after the name: the controller reads no more
# (vendor.rs), and the addresses are much of the file. A list much shorter than the
# 40 000 names of 2026 is a cut-off download, not a published one.
FROM docker.io/library/alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf AS fetch
RUN for try in 1 2 3 4 5; do \
        wget -q -O /oui-full.csv https://standards-oui.ieee.org/oui/oui.csv && break; \
        rm -f /oui-full.csv; sleep 60; \
    done \
    && head -1 /oui-full.csv | grep -q Assignment \
    && sed -E 's/^(MA-L,[0-9A-F]{6},("([^"]|"")*"|[^,]*)).*/\1/' /oui-full.csv > /oui.csv \
    && [ "$(wc -l < /oui.csv)" -gt 30000 ] \
    && rm /oui-full.csv \
    && chmod 644 /oui.csv

FROM scratch
COPY --from=fetch /oui.csv /oui.csv
