import { useMe, useWlanSettings } from "../../../api";
import { band } from "../../../format";
import { ErrorNote, Loading } from "../../common";
import { ListPanel } from "../ListPanel";
import { BAND_RADIO, PROTECTION } from "./form";
import { WlanEditor } from "./WlanEditor";

/** The Networks page's settings section: every SSID, editable. */
export function WlanSettingsPanel() {
  const s = useWlanSettings();
  const readOnly = useMe().data?.read_only ?? true;
  if (s.error) return <ErrorNote error={s.error} />;
  if (!s.data) return <Loading />;
  const list = s.data;
  if (list.wlans.length === 0 && !list.active) return null;
  const apName = (m: string) => list.aps.find((a) => a.mac === m)?.name ?? m;
  return (
    <ListPanel
      title="Settings"
      note={
        list.active
          ? "changes are reviewed, then sent to the APs"
          : "shadow mode: you can try changes and see what they would send"
      }
      add="Add SSID"
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
              {((w.wlan_bands as string[] | null) ?? [])
                .map((b) => band(BAND_RADIO[b] ?? b))
                .join(" + ")}{" "}
              · {w.aps === null ? "all APs" : w.aps.map(apName).join(", ")}
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
