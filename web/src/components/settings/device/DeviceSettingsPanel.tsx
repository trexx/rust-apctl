import { useDeviceSettings } from "../../../api";
import type { RadioSettings } from "../../../api";
import { band, dbm } from "../../../format";
import { QueryNote } from "../../common";
import { EditPanel } from "../EditPanel";
import { DeviceEditor } from "./DeviceEditor";

/** One radio's settings in a line. */
const radioSummary = (r: RadioSettings) =>
  `${band(r.radio)}: ${r.channel === "auto" ? "auto channel" : `channel ${r.channel}`}, ${r.ht} MHz, power ${r.tx_power_mode === "custom" ? `${r.tx_power} dBm` : r.tx_power_mode}${r.min_rssi_enabled ? `, min signal ${dbm(r.min_rssi)}` : ""}`;

/**
 * The AP page's settings section, for those who can edit (the page shows it
 * only to them, so that nobody else loads it).
 */
export function DeviceSettingsPanel({ mac }: { mac: string }) {
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
