import { useUserGroups } from "../../../api";
import { speed } from "../../../format";
import { Row } from "../form";

/** The SSID's speed limit: a user group; the default group means none. */
export function SpeedLimitRow({
  value,
  onChange,
}: {
  value: string | null | undefined;
  onChange: (v: string) => void;
}) {
  const groups = useUserGroups().data?.groups ?? [];
  const def = groups.find((g) => g.default);
  const current = typeof value === "string" && value !== def?.id ? value : "";
  return (
    <Row label="Speed limit" hint="per client on this SSID">
      <select value={current} onChange={(e) => onChange(e.target.value)}>
        <option value="">No limit</option>
        {groups
          .filter((g) => !g.default)
          .map((g) => (
            <option key={g.id} value={g.id}>
              {g.name} (down {speed(g.qos_rate_max_down)}, up{" "}
              {speed(g.qos_rate_max_up)})
            </option>
          ))}
      </select>
      {groups.length <= 1 && (
        <span className="muted small">add limits under Speed limits below</span>
      )}
    </Row>
  );
}
