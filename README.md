# AP controller (working title)

A lightweight, open-source controller for Ubiquiti access points. It is written in Rust,
stores everything in SQLite and adds the metrics, logs and event timelines the official
Network application lacks. It has no affiliation with Ubiquiti.

Status: **milestone 1, the protocol foundation.** See the plan in
`~/.claude/plans/i-would-like-to-vast-rain.md`.

## Crates

| Crate | What it is |
|---|---|
| `crates/inform` | Codec for the inform protocol: TNBU framing, AES-128-CBC/GCM, zlib/snappy. No I/O. |
| `crates/informdump` | A CLI that decodes inform traffic from pcap files or live tcpdump output, diffs config pushes and imports keys from an existing controller. |

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
