import { Link } from "react-router";
import { useThreats } from "../api";
import type { ThreatFinding } from "../api";

export const KIND_LABEL: Record<ThreatFinding["kind"], string> = {
  spoofed_bssid: "Cloned AP address",
  impersonation: "Copy of your network",
  lookalike: "Look-alike name",
  bridged: "Network run by a client",
  new_nearby: "New strong network",
};

/** A warning on the overview while anything serious is unacknowledged. */
export function ThreatBanner() {
  const t = useThreats();
  const open = (t.data?.findings ?? []).filter(
    (f) => !f.acknowledged && f.severity !== "low",
  );
  const worst = open[0];
  if (!worst) return null;
  return (
    <div className={`banner banner-${worst.severity}`}>
      <b>
        {open.length === 1
          ? "A suspicious network"
          : `${open.length} suspicious networks`}
      </b>{" "}
      nearby: {KIND_LABEL[worst.kind].toLowerCase()}
      {worst.essid ? ` "${worst.essid}"` : ""}
      {open.length > 1 ? " and more" : ""}.{" "}
      <Link to="/radios?tab=rogue">Review</Link>
    </div>
  );
}
