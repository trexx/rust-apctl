import { useCanEdit, useSettingsState, useWlanSettings } from "../../../api";
import { band } from "../../../format";
import { QueryNote } from "../../common";
import { ListPanel } from "../ListPanel";
import { BAND_RADIO, PROTECTION } from "./form";
import { WlanEditor } from "./WlanEditor";

/** The Networks page's settings section: every SSID, editable. */
export function WlanSettingsPanel() {
  const s = useWlanSettings();
  // An SSID is added to the imported settings: without them there is nowhere
  // to add it (and nothing is said until that is known).
  const state = useSettingsState().data;
  const imported = !!state?.summary;
  const readOnly = !useCanEdit();
  if (!s.data) return <QueryNote q={s} panel />;
  const list = s.data;
  if (list.wlans.length === 0 && !list.active) return null;
  const apName = (m: string) => list.aps.find((a) => a.mac === m)?.name ?? m;
  return (
    <ListPanel
      title="Settings"
      note={
        state && !imported
          ? "no settings imported: import them on the Settings page to add SSIDs"
          : list.active
            ? "changes are reviewed, then sent to the APs"
            : "shadow mode: you can try changes and see what they would send"
      }
      add={imported ? "Add SSID" : undefined}
      kind="wlan"
      items={list.wlans}
      active={list.active}
      readOnly={readOnly}
      gone="This SSID was deleted meanwhile."
      editor={(wlan, onClose) => (
        <>
          <div className="small">
            <b>{wlan ? `Editing ${wlan.name}` : "New SSID"}</b>
          </div>
          <WlanEditor wlan={wlan} list={list} onClose={onClose} />
        </>
      )}
      rows={(edit, remove) =>
        list.wlans.map((w) => (
          <tr key={w.id}>
            <td>
              <b>{w.name}</b>
              {w.enabled === false && <span className="tag">off</span>}
            </td>
            <td className="muted small">
              {PROTECTION.find((p) => p[0] === w.protection)?.[1] ??
                "other security"}{" "}
              ·{" "}
              {(w.wlan_bands ?? [])
                .map((b) => band(BAND_RADIO[b] ?? b))
                .join(" + ")}{" "}
              ·{" "}
              {w.aps === null
                ? "all APs"
                : w.aps.length === 0
                  ? "no APs"
                  : w.aps.map(apName).join(", ")}
            </td>
            <td className="nowrap">
              {!readOnly && w.editable && (
                <>
                  <button className="btn small" onClick={() => edit(w)}>
                    Edit
                  </button>{" "}
                  <button className="btn small" onClick={() => remove(w)}>
                    Delete
                  </button>
                </>
              )}
            </td>
          </tr>
        ))
      }
    />
  );
}
