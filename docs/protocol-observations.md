# Protocol observations from real captures

Everything here was seen on the wire between the official controller (10.6.106) and two
U6-Mesh APs on firmware 8.8.11. The captures behind it are described in [captures.md](captures.md).
Anything we only infer, rather than observe, is marked *inferred*.

## Transport

- APs POST to `http://<controller>:8080/inform` every 10–14 s. The controller sets the
  interval in each reply (`interval`), and with 2 APs it varies between 10 and 14.
- Requests use flags `encrypted|zlib|gcm` (`0x000b`): AES-128-GCM with the 40-byte header as
  associated data, and the payload zlib-compressed. Replies use `encrypted|gcm` (`0x0009`) and
  are never compressed.
- A normal inform is about 37 KB of JSON with 85 top-level keys. Routine replies are
  `{"_type":"noop","interval":N,"server_time_in_utc":"<ms>"}`.

## Config pushes

- A push is a `setparam` reply carrying `mgmt_cfg` (9 lines), `system_cfg` (350–600 lines),
  `cfgversion`, `blocked_sta` and `server_time_in_utc`.
- `cfgversion` is a fresh random 16-hex token on every change, and it differs per AP.
  *Inferred:* any unique token works.
- Only APs affected by a change get a push. WLAN changes go to every AP broadcasting
  that WLAN, and radio changes go only to that AP. Creating or deleting a network that no
  WLAN uses pushes nothing.
- Each AP numbers its sections independently. The same WLAN was `aaa.3`/`aaa.4` on one AP
  and `aaa.2`/`aaa.3` on the other.
- **`aaa.N` and `wireless.N` keep their numbers when another section is removed**, so gaps
  are left. `macacl.N` is renumbered to stay contiguous. `netconf.N` reuses freed slots.
  A replacement controller must keep each AP's existing numbering, or every VAP restarts
  at cutover.

## Setting encodings (one key per setting unless noted)

| Setting | Keys |
|---|---|
| WPA2 → WPA2/WPA3 transition | `pmf.status=enabled`, `pmf.mode=1`, `wpa.key.1.mgmt=SAE`, `wpa.psk` written twice, plus `wpa3.support=enabled`, `wpa3.transition=enabled`, `wpa3.ft.status=disabled`, `sae.anti_clogging=5`, `sae.sync=5` |
| Hide SSID | `aaa.N.hide_ssid` and `wireless.N.hide_ssid` |
| 802.11r | `aaa.N.ft.status` (in transition mode, `wpa3.ft.status` is separate) |
| Client isolation | `wireless.N.l2_isolation` |
| Minimum data rate (5 GHz) | `wireless.N.minrate_data`, `beacon_rate`, `mgmt_rate` in kbps. These are absent when the feature is off. 2.4 GHz always has them. |
| Multicast enhancement | `wireless.N.mcast.enhance` 0/1 |
| Group rekey | `aaa.N.wpa.group_rekey` in seconds, 0 for off |
| VLAN | `vlan.status=enabled`, `vlan.1` = `eth0` with the VLAN ID, a new bridge `br0.<id>` holding the VAP and `eth0.<id>`, `aaa.N.br.devname=br0.<id>`, `netconf` entries for both, and `ebtables.status=enabled` with two broute DROP rules for tagged frames |
| Transmit power | `radio.R.txpower_mode` (`custom`/`medium`/…). `radio.R.txpower` keeps the custom value in every mode. |
| Channel | `radio.R.channel` |
| Channel width | suffix of `radio.R.ieee_mode` (`11naht80`, `11naht40`) |

## AP behaviour after a radio change

After a push that restarts a radio (a channel or width change), the AP's informs keep
their interval and shape (85 keys, with `vap_table`) and report the new channel. In between,
for about 25 s, come notifications (`inform_as_notif: true`, sent at once rather than on the
interval): first one with `notif_reason: "setparam"` (62 keys) acknowledging the push, then
a burst of `notif_reason: "event"` ones (63 keys, every 0.3–6 s) carrying client association
events in `notif_payload` as the clients re-associate. Clients that roam make the other AP
send them too.

A notification has **no `vap_table`**: the controller must not read it as an inform whose
VAPs and clients are gone, or every radio change would look like all clients disconnecting.
