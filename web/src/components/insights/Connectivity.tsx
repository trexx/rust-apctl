import { useState } from "react";
import { useConnectivity } from "../../api";
import { useTimeSpan } from "../Chart";
import { QueryState } from "../common";
import { BandPicker, spanText } from "./shared";

const STAGES = [
  ["association_pct", "Assoc"],
  ["authentication_pct", "Auth"],
  ["dhcp_pct", "DHCP"],
  ["dns_pct", "DNS"],
] as const;

const pctTone = (p: number | null) =>
  p === null || p === 0 ? "" : p >= 80 ? "good" : p >= 60 ? "warn" : "bad";

export function Connectivity() {
  const [band, setBand] = useState("all");
  const [span] = useTimeSpan(86400);
  const c = useConnectivity(span);
  return (
    <QueryState q={c} panel>
      {(data) => {
        const d = data.bands[band];
        return (
          <div className="panel">
            <div className="panel-head">
              <b>Wi-Fi connectivity</b>
              <span className="muted small">{spanText(span)}</span>
              <span className="spacer" />
              <BandPicker value={band} onChange={setBand} />
            </div>
            {!d || d.attempts === 0 ? (
              <div className="muted small">
                No connection attempts recorded in this range. They come from
                the APs' connection-tracking reports.
              </div>
            ) : (
              <>
                <div className="stages">
                  {STAGES.map(([k, label]) => (
                    <div
                      key={k}
                      className={`stage-bar stage-${pctTone(d[k])}`}
                      title={`${d[k] ?? 0}% of clients got past ${label}`}
                    >
                      {label}
                    </div>
                  ))}
                  <div className="stage-success">
                    Success{" "}
                    <b className={`tone-${pctTone(d.success_pct)}`}>
                      {d.success_pct ?? 0}%
                    </b>
                  </div>
                </div>
                <div className="small muted">
                  {d.clients} client{d.clients === 1 ? "" : "s"}, {d.attempts}{" "}
                  attempt
                  {d.attempts === 1 ? "" : "s"}
                  {d.failed_clients > 0 &&
                    ` · ${d.failed_clients} never connected (stopped at ${Object.entries(
                      d.failed_at,
                    )
                      .filter(([, n]) => n > 0)
                      .map(([k, n]) => `${k} ${n}`)
                      .join(", ")})`}
                  {d.latency_ms?.total != null &&
                    ` · average time to connect ${d.latency_ms.total} ms (associate ${d.latency_ms.association ?? "—"}, authenticate ${d.latency_ms.authentication ?? "—"}, DHCP ${d.latency_ms.dhcp ?? "—"}, DNS ${d.latency_ms.dns ?? "—"})`}
                </div>
              </>
            )}
          </div>
        );
      }}
    </QueryState>
  );
}
