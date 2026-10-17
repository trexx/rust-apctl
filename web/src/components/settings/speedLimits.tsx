import { useState } from "react";
import { useCanEdit, useUserGroups } from "../../api";
import { speed } from "../../format";
import type { UserGroup } from "../../api";
import { Row, TextInput } from "./form";
import type { Fields } from "./form";
import { EditorShell } from "./Review";
import { ListPanel } from "./ListPanel";

/** A limit in kbps as the Mbps text of its field; empty for none. */
const mbpsField = (k: number | null | undefined) =>
  k && k > 0 ? String(k / 1000) : "";

/** The field's Mbps text as kbps; -1 (no limit) when empty. */
const kbps = (v: string) =>
  v.trim() === "" ? -1 : Math.round(Number(v) * 1000);

function SpeedLimitEditor({
  group,
  onClose,
  active,
}: {
  group: UserGroup | null;
  onClose: () => void;
  active: boolean;
}) {
  const [name, setName] = useState(group?.name ?? "");
  const [down, setDown] = useState(mbpsField(group?.qos_rate_max_down));
  const [up, setUp] = useState(mbpsField(group?.qos_rate_max_up));
  // The whole limit is sent, not a difference (the default group, which has
  // no name, isn't editable); an unchanged group sends nothing, so Review
  // says there is nothing to review.
  const patch: Fields = {
    name,
    qos_rate_max_down: kbps(down),
    qos_rate_max_up: kbps(up),
  };
  const unchanged =
    group !== null &&
    name === group.name &&
    kbps(down) === kbps(mbpsField(group.qos_rate_max_down)) &&
    kbps(up) === kbps(mbpsField(group.qos_rate_max_up));
  const rate = (label: string, value: string, set: (v: string) => void) => (
    <Row label={label} hint="Mbps per client; empty for no limit">
      <TextInput
        className="search num-input"
        type="number"
        min={0.002}
        max={100}
        step="any"
        value={value}
        onChange={set}
      />
    </Row>
  );
  return (
    <EditorShell
      target={{ kind: "usergroup", id: group?.id ?? null }}
      active={active}
      patch={unchanged ? {} : patch}
      invalid={!name.trim()}
      onClose={onClose}
    >
      <Row label="Name">
        <TextInput maxLength={128} value={name} onChange={setName} />
      </Row>
      {rate("Download", down, setDown)}
      {rate("Upload", up, setUp)}
    </EditorShell>
  );
}

/** Speed limits (user groups): used by SSIDs and by single clients. */
export function SpeedLimitsPanel() {
  const g = useUserGroups();
  const readOnly = !useCanEdit();
  if (!g.data) return null;
  const { active, groups } = g.data;
  return (
    <ListPanel
      title="Speed limits"
      note="per client, for an SSID or a single device"
      add="Add speed limit"
      kind="usergroup"
      items={groups}
      active={active}
      readOnly={readOnly}
      gone="This speed limit was deleted meanwhile."
      editor={(group, onClose) => (
        <SpeedLimitEditor group={group} active={active} onClose={onClose} />
      )}
      rows={(edit, remove) =>
        groups.map((x) => (
          <tr key={x.id}>
            <td>
              <b>{x.default ? "No limit (default)" : x.name}</b>
            </td>
            <td className="small">
              down {speed(x.qos_rate_max_down)} · up {speed(x.qos_rate_max_up)}
            </td>
            <td className="muted small">
              {x.used_by.length ? x.used_by.join(", ") : "unused"}
            </td>
            <td className="nowrap">
              {!readOnly && !x.default && (
                <>
                  <button className="btn small" onClick={() => edit(x)}>
                    Edit
                  </button>{" "}
                  <button
                    className="btn small"
                    disabled={x.used_by.length > 0}
                    title={x.used_by.length ? "still in use" : ""}
                    onClick={() => remove(x)}
                  >
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
