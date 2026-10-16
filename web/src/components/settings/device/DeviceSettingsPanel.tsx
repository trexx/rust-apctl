import { useState } from "react";
import { useDeviceSettings, useMe } from "../../../api";
import type { RadioSettings } from "../../../api";
import { band } from "../../../format";
import { DeviceEditor } from "./DeviceEditor";

/** One radio's settings in a line. */
const radioSummary = (r: RadioSettings) =>
  `${band(r.radio)}: ${r.channel === "auto" ? "auto channel" : `channel ${r.channel}`}, ${r.ht} MHz, power ${r.tx_power_mode === "custom" ? `${r.tx_power} dBm` : r.tx_power_mode}${r.min_rssi_enabled ? `, min signal ${r.min_rssi} dBm` : ""}`;

function DevicePanel({ mac }: { mac: string }) {
  const s = useDeviceSettings(mac);
  const readOnly = useMe().data?.read_only ?? true;
  const [editing, setEditing] = useState(false);
  if (!s.data || readOnly) return null;
  const d = s.data;
  return (
    <div className="panel">
      <div className="panel-head">
        <b>Settings</b>
        <span className="muted small">
          {editing ? "" : d.radios.map(radioSummary).join(" · ")}
        </span>
        <span className="spacer" />
        {!editing && (
          <button className="btn small" onClick={() => setEditing(true)}>
            Edit
          </button>
        )}
      </div>
      {editing && <DeviceEditor d={d} onClose={() => setEditing(false)} />}
    </div>
  );
}

/**
 * The AP page's settings section. Keyed by MAC: going to another AP's page
 * (Back, a link) starts afresh, so one AP's edits are never diffed against,
 * and saved to, another.
 */
export function DeviceSettingsPanel({ mac }: { mac: string }) {
  return <DevicePanel key={mac} mac={mac} />;
}
