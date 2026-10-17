import { useState } from "react";
import { Row, Toggle } from "../form";
import type { WlanSection } from "./form";

export function Iot({
  w,
  setIot,
}: Pick<WlanSection, "w"> & { setIot: (on: boolean) => void }) {
  const { form: f, set, bind } = w;
  const iot = f.enhanced_iot === true;
  const has2g = (f.wlan_bands ?? []).includes("2g");
  // Open at first when something is on; afterwards the user's choice (a live
  // `open` would snap shut as the last toggle goes off).
  const [open] = useState(
    iot || f.iot_channel_lock === true || f.iot_dtim_lock === true,
  );
  return (
    <details open={open}>
      <summary>IoT</summary>
      <Row
        label="Force Wi-Fi 4"
        hint="for legacy devices: WPA2 or open on 2.4 GHz, without the newer features"
      >
        <Toggle value={f.enhanced_iot} onChange={setIot} label="Enabled" />
      </Row>
      <Row
        label="Lock 2.4 GHz to channel 6"
        hint="on every AP broadcasting this SSID"
      >
        <Toggle
          {...bind("iot_channel_lock")}
          disabled={!has2g}
          label="Enabled"
        />
      </Row>
      <Row label="DTIM interval lock" hint="2.4 GHz DTIM held at 3">
        <Toggle
          value={f.iot_dtim_lock}
          disabled={!has2g}
          onChange={(v) => {
            set("iot_dtim_lock", v);
            if (v) set("dtim_ng", 3);
          }}
          label="Enabled"
        />
      </Row>
      {!has2g && <div className="muted small">The locks need 2.4 GHz.</div>}
    </details>
  );
}
