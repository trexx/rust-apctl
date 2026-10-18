import { useUserGroups } from "../../../api";
import { Row } from "../form";
import { speedLimitOptions } from "../speedLimitOptions";

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
      <select
        aria-label="Speed limit per client"
        value={current}
        onChange={(e) => onChange(e.target.value)}
      >
        <option value="">No limit</option>
        {speedLimitOptions(groups)}
      </select>
      {groups.length <= 1 && (
        <span className="muted small">add limits under Speed limits below</span>
      )}
    </Row>
  );
}
