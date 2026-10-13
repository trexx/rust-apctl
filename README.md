# AP controller (working title)

A lightweight, open-source controller for Ubiquiti access points. It is written in Rust,
stores everything in SQLite and adds the metrics, logs and event timelines the official
Network application lacks. It has no affiliation with Ubiquiti.

Status: **milestone 2: monitoring in shadow mode.** apctl runs next to an existing
controller and learns everything from a capture of its traffic: APs, clients, radio
metrics, events and AP syslog. It never talks to the APs. Configuring APs comes in
milestone 3.

## Crates

| Crate | What it is |
|---|---|
| `crates/inform` | Codec for the inform protocol: TNBU framing, AES-128-CBC/GCM, zlib/snappy. No I/O. |
| `crates/wire` | Capture reading (pcap, TCP/HTTP reassembly, UDP), request/reply pairing, decryption, config diffs. |
| `crates/informdump` | A CLI that decodes inform traffic from pcap files or live tcpdump output, diffs config pushes and imports keys from an existing controller. |
| `crates/controller` | `apctl`: the controller. SQLite storage, event engine, syslog, REST/WebSocket API and the embedded web UI. |
| `web/` | The web UI (React, TypeScript, Vite, uPlot). |

## apctl

```sh
# Build the UI (no local npm needed), then the controller.
podman run --rm -v $PWD/web:/app:Z -w /app docker.io/library/node:24-slim sh -c "npm ci && npm run build"
cargo build --release -p controller

# Shadow mode from any pcap stream, e.g. tcpdump on the node running the other controller.
apctl serve --data-dir data --keys import.json \
  --shadow-cmd "ssh node sudo tcpdump -i any -U -s0 -w - 'tcp port 8080 or udp port 5514'"
# then open http://127.0.0.1:8090
```

Data lives in three SQLite files under `--data-dir`:
- `config.db` holds devices, clients, events and the redacted last config per AP.
- `metrics.db` holds the time series: raw for 48 h, 5-minute averages for 30 days and hourly for a year.
- `logs.db` holds AP syslog for 14 days, with full-text search. Secrets that APs log are masked on arrival.

In Kubernetes, `deploy/k8s/shadow.yaml` runs apctl with a tcpdump sidecar on the host
network of the node that runs the other controller.

### Dry run and active mode

- With settings imported (Settings page, from `informdump import`), every config push the other
  controller makes is compared with what apctl would generate (`crates/apcfg`); see the Dry run
  page.
- `apctl serve --active` answers the APs' informs itself. It decrypts with each AP's key, replies
  `setparam` when the AP's `cfgversion` differs and `noop` otherwise, and adopts the running
  config at cutover when it is identical. It is off by default and cannot be combined with
  shadow mode.
- Rehearse against a local instance only (the command refuses other hosts):

  ```sh
  apctl serve --active --inform-listen 127.0.0.1:18180 --listen 127.0.0.1:18101 ...
  informdump simulate capture.pcap --keys import.json --url http://127.0.0.1:18180/inform
  ```

## informdump

```sh
cargo build --release -p informdump

# 1. Snapshot device authkeys, sites and WLANs from the existing controller (read-only).
kubectl -n unifi-controller port-forward pod/unifi-controller-0 27117:27117 &
informdump import --out ~/.local/share/apctl/import.json

# 2. Watch live traffic on the node running the controller. Shows new devices and config
#    pushes, with a diff of system_cfg and mgmt_cfg against the previous push.
sudo tcpdump -i any -U -w - 'tcp port 8080' | informdump watch --keys ~/.local/share/apctl/import.json

# 3. Or decode a saved capture, showing everything and saving the decoded payloads.
informdump pcap capture.pcap --keys import.json --all --save decoded/

# 4. Turn decoded payloads into shareable fixtures (fake MACs, SSIDs, names, IDs and secrets).
#    It refuses to write anything if an original value survives.
informdump sanitize --input decoded/ --output testdata/captures/<session> --domain example.org FILE...
```

`--json` prints one JSON object per message, and `--full` prints the complete payloads.
Printed output masks passwords, PSKs and keys unless you pass `--no-redact`. Files written
with `--save` are not masked.

## Documentation

- `docs/protocol-observations.md` lists what we have seen on the wire, with evidence in `testdata/`.
- `testdata/captures/*/` holds sanitised real captures, each with a labelled `manifest.json`.

## Rules for this repository

- **No secrets or captures in git.** Import snapshots, keys and pcaps hold device authkeys
  and WLAN passphrases. Fixtures in `testdata/` must be sanitised, with fake MACs, keys and
  SSIDs.
- **Interoperability, not copying.** The official application may be decompiled as a
  reference for interoperability. The decompiled output stays outside this repository, and
  what we learn from it is written up in our own words. Never copy its code or assets in
  here. Wire captures are the source of truth: a rule taken from the decompile is relied on
  only once a capture confirms it.
