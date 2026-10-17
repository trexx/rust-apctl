# Capture session 2026-10-12: two U6-Mesh APs, firmware 8.8.11

The captures themselves are not in this repository. Tests that replay them read them from
`$APCTL_TESTDATA/2026-10-12-u6m-8.8.11/` and are skipped when it is not set.

Config pushes (`setparam` replies) and sample informs, captured while settings were
changed one at a time in the official controller (10.6.106). They were decoded with
`informdump` and sanitised with `informdump sanitize`:

- MACs are replaced with `02:00:00:00:xx:yy`.
- SSIDs become `ssid-N` and hostnames `name-N`.
- Secrets become `secret-N`. This covers PSKs, keys, the SSH account and password hashes.
- Mongo IDs, UUIDs and other long hex tokens are replaced with stable fakes, and the controller's domain with `example.net`.
- Private IPv4 addresses are kept.
- Serial numbers (also those of neighbouring APs), SSH host key fingerprints, QR IDs, mDNS
  service names with device IDs, client manufacturer names and binary UUIDs are faked too.

Replacements are consistent across files, so diffs between consecutive pushes are unchanged.

| AP | MAC in fixtures |
|---|---|
| B (Garage) | `02:00:00:00:00:01` |
| U (Upstairs) | `02:00:00:00:00:02` |

`manifest.json` labels every push with the change that caused it and the diff that was
observed. `crates/wire/src/cfgdiff.rs` (`capture_fixtures`) replays them as tests.

| Step | Change | AP B diff | AP U diff |
|---|---|---|---|
| 1 | create SSID `test`: WPA2, 2.4 and 5 GHz, all APs | baseline (593 lines) | baseline (554 lines) |
| 2 | WPA2 → WPA2/WPA3 | 10 added, 8 changed | same |
| 3 | hide SSID | `aaa.3/4.hide_ssid`, `wireless.3/4.hide_ssid` | sections 2/3 |
| 4 | 5 GHz only | 79 lines removed | 111 removed, 2 `macacl` changed |
| 5 | VLAN 2 network on the SSID | 20 added, 1 removed, 3 changed | same |
| 6 | fast roaming (802.11r) | `aaa.4.ft.status` | `aaa.3.ft.status` |
| 7 | client isolation | `wireless.4.l2_isolation` | `wireless.3.l2_isolation` |
| 8 | 5 GHz minimum rate 12 Mbps | + `minrate_data`, `beacon_rate`, `mgmt_rate` = 12000 | same on section 3 |
| 9 | multicast enhancement and group rekey of 3600 s | `mcast.enhance`, `wpa.group_rekey` | same |
| 10 | delete SSID | 97 removed, 2 changed | 131 removed, 2 changed |
| 12 | U: 5 GHz transmit power custom → medium | not applicable | `radio.2.txpower_mode` |
| 13 | U: channel 44 → 36 | not applicable | `radio.2.channel` |
| 14 | U: width 80 → 40 MHz | not applicable | `radio.2.ieee_mode` (`11naht80` → `11naht40`) |
| 15 | U: restore channel 44, 80 MHz, custom power | not applicable | 3 keys back |

`controller-state.json` holds the official controller's settings as `informdump import`
read them after the session: sites, WLANs, networks, AP groups, settings, `config_meta`, devices
and known clients. It was sanitised in the same run as the captures, so its fakes match
theirs; for example a WLAN's `x_passphrase` and the `wpa.psk` in the configs are the same
`secret-N`. It is the input for config-generator tests, whose expected output is the last
push to each AP: step 10 for AP B and step 15 for AP U.

Samples:
- `…_000001_…_inform.json` is a normal inform (85 top-level keys).
- `…_000593_…_inform.json` is a notification: an inform the AP sends at once to report an event
  (`inform_as_notif`, `notif_reason: "event"`, here a client's association in `notif_payload`).
  It has 63 keys and no `vap_table`.
- `…_000002_…_reply-noop.json` is a routine reply.
