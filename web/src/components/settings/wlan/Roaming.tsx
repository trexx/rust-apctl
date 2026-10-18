import { Row, Toggle } from "../form";
import type { WlanSection } from "./form";
import { Unsupported } from "./Unsupported";

export function Roaming({ w, list }: WlanSection) {
  const { form: f, set, bind } = w;
  const bands = f.wlan_bands ?? [];
  const dual = bands.includes("2g") && bands.includes("5g");
  const aps = f.aps;
  const iot = f.enhanced_iot === true;
  return (
    <details>
      <summary>Roaming</summary>
      <Row label="Fast roaming" hint="802.11r">
        <Toggle
          {...bind("fast_roaming_enabled")}
          disabled={iot}
          label="Enabled"
        />
        {f.protection === "wpa2_wpa3" && (
          <Toggle
            {...bind("wpa3_fast_roaming")}
            disabled={iot}
            label="Also for WPA3 clients (not in the official UI)"
          />
        )}
        <Unsupported
          feature="wpa3_fast_roaming"
          on={f.protection === "wpa2_wpa3" && f.wpa3_fast_roaming === true}
          aps={aps}
          list={list}
        />
      </Row>
      <Row
        label="Neighbour reports"
        hint="802.11k: clients learn the nearby APs (not in the official UI)"
      >
        <Toggle {...bind("rrm_enabled")} label="Enabled" />
      </Row>
      <Row label="BSS transition" hint="802.11v: APs suggest a better AP">
        <Toggle {...bind("bss_transition")} disabled={iot} label="Enabled" />
      </Row>
      <Row
        label="Roaming assistant (5 GHz)"
        hint="nudge clients away below this signal"
      >
        <Toggle
          {...bind("roaming_assistant_na_enabled")}
          disabled={iot}
          label="Enabled"
        />
        {f.roaming_assistant_na_enabled === true && (
          <label className="small">
            <input
              type="range"
              aria-label="Roaming assistant threshold"
              min={-80}
              max={-60}
              value={f.roaming_assistant_na_rssi ?? -75}
              onChange={(e) =>
                set("roaming_assistant_na_rssi", Number(e.target.value))
              }
            />{" "}
            {f.roaming_assistant_na_rssi ?? -75} dBm
          </label>
        )}
        <Unsupported
          feature="roaming_assistant"
          on={f.roaming_assistant_na_enabled === true}
          aps={aps}
          list={list}
        />
      </Row>
      <Row
        label="Band steering"
        hint="keep dual-band clients the APs have seen on 5 GHz off 2.4 GHz"
      >
        <Toggle
          {...bind("no2ghz_oui")}
          disabled={iot || !dual}
          label="Enabled"
        />
        {!dual && <span className="muted small">needs both 2.4 and 5 GHz</span>}
      </Row>
    </details>
  );
}
