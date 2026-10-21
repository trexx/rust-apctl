import { useUserGroups } from "../../../api";
import { Row, Select } from "../form";
import { speedLimitOptions } from "../speedLimitOptions";

/**
 * The SSID's speed limit: a user group; the default group means none.
 * `stored` is the SSID's own value when the editor opened.
 */
export function SpeedLimitRow({
  value,
  stored,
  onChange,
}: {
  value: string | null | undefined;
  stored: string | null | undefined;
  onChange: (v: string | null | undefined) => void;
}) {
  const groups = useUserGroups().data?.groups;
  // "No limit" is the default group, or "" (the server's way to name it) while
  // it isn't known: so going back to it after trying a limit is no change.
  const none = groups?.find((g) => g.default)?.id ?? "";
  return (
    <Row label="Speed limit" hint="per client on this SSID">
      <Select
        aria-label="Speed limit per client"
        value={value || none}
        // An SSID stored with no group has no limit already: going back to
        // "No limit" restores that, rather than naming the default group.
        onChange={(v) => onChange(v === none && !stored ? stored : v)}
        // A group the settings no longer have counts as none, as the APs are told.
        stray={() =>
          groups
            ? "A limit no longer in the settings (no limit)"
            : "(loading the limits)"
        }
        options={[[none, "No limit"], ...speedLimitOptions(groups ?? [])]}
      />
      {groups && groups.length <= 1 && (
        <span className="muted small">add limits under Speed limits below</span>
      )}
    </Row>
  );
}
