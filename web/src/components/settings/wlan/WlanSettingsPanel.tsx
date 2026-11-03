import { Suspense } from "react";
import {
  useActive,
  useCanEdit,
  useSettingsState,
  useWlanSettings,
} from "../../../api";
import { band } from "../../../format";
import { lazyNamed } from "../../../lazy";
import { Loading, QueryNote } from "../../common";
import { ListPanel } from "../ListPanel";
import { BAND_RADIO } from "./form";

// The SSID editor is most of the settings code: it loads when an SSID is
// edited or added, so the list alone (all a read-only user sees) doesn't.
const WlanEditor = lazyNamed(() => import("./WlanEditor"), "WlanEditor");

/** The Networks page's settings section: every SSID, editable. */
export function WlanSettingsPanel() {
  const s = useWlanSettings();
  // An SSID is added to the imported settings: without them there is nowhere
  // to add it (and nothing is said until that is known).
  const state = useSettingsState().data;
  const imported = !!state?.summary;
  const readOnly = !useCanEdit();
  const active = useActive();
  if (!s.data) return <QueryNote q={s} panel />;
  const list = s.data;
  if (list.wlans.length === 0 && !active) return null;
  const apName = (m: string) => list.aps.find((a) => a.mac === m)?.name ?? m;
  return (
    <ListPanel
      title="Settings"
      note={
        state && !imported
          ? "no settings imported: import them on the Settings page to add SSIDs"
          : active
            ? "changes are reviewed, then sent to the APs"
            : active === false &&
              "shadow mode: you can try changes and see what they would send"
      }
      add={imported ? "Add SSID" : undefined}
      kind="wlan"
      items={list.wlans}
      readOnly={readOnly}
      gone="This SSID was deleted meanwhile."
      editor={(wlan, onClose) => (
        <>
          <div className="small">
            <b>{wlan ? `Editing ${wlan.name}` : "New SSID"}</b>
          </div>
          <Suspense fallback={<Loading />}>
            <WlanEditor wlan={wlan} list={list} onClose={onClose} />
          </Suspense>
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
              {w.security} ·{" "}
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
