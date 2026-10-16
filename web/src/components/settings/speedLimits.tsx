import { useState } from "react";
import { speed, useMe, useUserGroups } from "../../api";
import type { UserGroup } from "../../api";
import { Row } from "./form";
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
  // The whole limit is sent, not a difference; the default group has no name to send.
  const patch: Fields = {
    ...(!group?.default && { name }),
    qos_rate_max_down: kbps(down),
    qos_rate_max_up: kbps(up),
  };
  const rate = (label: string, value: string, set: (v: string) => void) => (
    <Row label={label} hint="Mbps per client; empty for no limit">
      <input
        className="search num-input"
        type="number"
        min={0.002}
        max={100}
        step="any"
        value={value}
        onChange={(e) => set(e.target.value)}
      />
    </Row>
  );
  return (
    <EditorShell
      target={{ kind: "usergroup", id: group?.id ?? null }}
      active={active}
      patch={patch}
      invalid={!name.trim()}
      onClose={onClose}
    >
      {!group?.default && (
        <Row label="Name">
          <input
            className="search"
            maxLength={128}
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
        </Row>
      )}
      {rate("Download", down, setDown)}
      {rate("Upload", up, setUp)}
    </EditorShell>
  );
}

/** Speed limits (user groups): used by SSIDs and by single clients. */
export function SpeedLimitsPanel() {
  const g = useUserGroups();
  const readOnly = useMe().data?.read_only ?? true;
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
