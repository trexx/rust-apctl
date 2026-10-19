import type { WlanSettingsList } from "../../../api";

/**
 * Names the APs broadcasting this SSID that lack `feature`: they get the
 * SSID without it. Shown while the feature is on.
 */
export function Unsupported({
  feature,
  on,
  aps,
  list,
}: {
  feature: string;
  on: boolean;
  aps: string[] | null;
  list: WlanSettingsList;
}) {
  if (!on) return null;
  const from = aps ?? list.aps.map((a) => a.mac);
  const name = (m: string) => list.aps.find((a) => a.mac === m)?.name ?? m;
  const missing = (list.unsupported[feature] ?? []).filter((m) =>
    from.includes(m),
  );
  const unknown = list.unknown.filter((m) => from.includes(m));
  if (missing.length === 0 && unknown.length === 0) return null;
  return (
    <div className="form-warn">
      {missing.length > 0 && (
        <>
          Not supported by {missing.map(name).join(", ")}:{" "}
          {missing.length === 1 ? "it broadcasts" : "they broadcast"} this SSID
          without it.{" "}
        </>
      )}
      {unknown.length > 0 && (
        <>
          {unknown.map(name).join(", ")}{" "}
          {unknown.length === 1 ? "hasn't" : "haven't"} reported yet, so support
          is unknown.
        </>
      )}
    </div>
  );
}
