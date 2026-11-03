import { useDeviceSettings, useSettingsState } from "../../../api";
import type { RadioSettings } from "../../../api";
import { band, dbm } from "../../../format";
import { QueryNote } from "../../common";
import { EditPanel, NotImported } from "../EditPanel";
import { DeviceEditor } from "./DeviceEditor";

/** One radio's settings in a line (the width it runs at, and the one set when that is wider). */
const radioSummary = (r: RadioSettings) =>
  `${band(r.radio)}: ${r.channel === "auto" ? "auto channel" : `channel ${r.channel}`}, ${r.width} MHz${r.ht > r.width ? ` (set to ${r.ht})` : ""}, power ${r.tx_power_mode === "custom" ? `${r.tx_power} dBm` : r.tx_power_mode}${r.min_rssi_enabled ? `, min signal ${dbm(r.min_rssi)}` : ""}`;

/**
 * The AP page's settings section, for those who can edit (the page shows it
 * only to them, so that nobody else loads it).
 */
export function DeviceSettingsPanel({ mac }: { mac: string }) {
  // The server answers 409 before an import: ask once the state says there is one.
  const state = useSettingsState();
  const imported = !!state.data?.summary;
  const s = useDeviceSettings(mac, imported);
  if (!state.data) return <QueryNote q={state} panel />;
  if (!imported) return <NotImported title="Settings" />;
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
