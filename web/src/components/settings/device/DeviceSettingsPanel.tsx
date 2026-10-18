import { useDeviceSettings } from "../../../api";
import type { RadioSettings } from "../../../api";
import { band } from "../../../format";
import { QueryNote } from "../../common";
import { EditPanel } from "../EditPanel";
import { DeviceEditor } from "./DeviceEditor";

/** One radio's settings in a line. */
const radioSummary = (r: RadioSettings) =>
  `${band(r.radio)}: ${r.channel === "auto" ? "auto channel" : `channel ${r.channel}`}, ${r.ht} MHz, power ${r.tx_power_mode === "custom" ? `${r.tx_power} dBm` : r.tx_power_mode}${r.min_rssi_enabled ? `, min signal ${r.min_rssi} dBm` : ""}`;

function DevicePanel({ mac }: { mac: string }) {
  const s = useDeviceSettings(mac);
  if (!s.data) return <QueryNote q={s} panel />;
  const d = s.data;
  return (
    <EditPanel
      title="Settings"
      summary={d.radios.map(radioSummary).join(" · ")}
      editor={(onClose) => <DeviceEditor d={d} onClose={onClose} />}
    />
  );
}

/**
 * The AP page's settings section, for those who can edit (the page shows it
 * only to them, so that nobody else loads it). Keyed by MAC: going to
 * another AP's page (Back, a link) starts afresh, so one AP's edits are
 * never diffed against, and saved to, another.
 */
export function DeviceSettingsPanel({ mac }: { mac: string }) {
  return <DevicePanel key={mac} mac={mac} />;
}
