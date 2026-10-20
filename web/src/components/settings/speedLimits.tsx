import { useState } from "react";
import { useCanEdit, useUserGroups } from "../../api";
import { speed } from "../../format";
import { QueryNote } from "../common";
import type { UserGroup } from "../../api";
import { Row, TextInput, useSettingsForm } from "./form";
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
  // Compared with what the editor opened with, not with the group as it is
  // refetched: someone else's edit meanwhile is neither a change here nor undone.
  const { original, form, set } = useSettingsForm(() => ({
    name: group?.name ?? "",
    down: mbpsField(group?.qos_rate_max_down),
    up: mbpsField(group?.qos_rate_max_up),
  }));
  // A number the browser can't read reaches onChange as "", which would mean
  // no limit; such a field holds the review back instead.
  const [unreadable, setUnreadable] = useState({ down: false, up: false });
  // Only what was changed is sent (a new group starts with no limits); an
  // unchanged group sends nothing, so Review says there is nothing to review.
  const patch: Fields = {};
  if (form.name !== original.name) patch.name = form.name;
  if (kbps(form.down) !== kbps(original.down))
    patch.qos_rate_max_down = kbps(form.down);
  if (kbps(form.up) !== kbps(original.up))
    patch.qos_rate_max_up = kbps(form.up);
  const rate = (k: "down" | "up", label: string) => (
    <Row label={label} hint="Mbps per client; empty for no limit">
      <TextInput
        className="search num-input"
        type="number"
        min={0.002}
        max={100}
        step="any"
        value={form[k]}
        onChange={(v) => set(k, v)}
        onInput={(e) => {
          const bad = e.currentTarget.validity.badInput;
          setUnreadable((u) => ({ ...u, [k]: bad }));
        }}
      />
    </Row>
  );
  return (
    <EditorShell
      target={{ kind: "usergroup", id: group?.id ?? null }}
      active={active}
      patch={patch}
      invalid={!form.name.trim() || unreadable.down || unreadable.up}
      onClose={onClose}
    >
      <Row label="Name">
        <TextInput
          maxLength={128}
          value={form.name}
          onChange={(v) => set("name", v)}
        />
      </Row>
      {rate("down", "Download")}
      {rate("up", "Upload")}
    </EditorShell>
  );
}

/** Speed limits (user groups): used by SSIDs and by single clients. */
export function SpeedLimitsPanel() {
  const g = useUserGroups();
  const readOnly = !useCanEdit();
  if (!g.data) return <QueryNote q={g} panel />;
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
