import { useState } from "react";
import { useRetries } from "../../api";
import { band as bandName } from "../../format";
import { useTimeSpan } from "../Chart";
import { QueryState } from "../common";
import { BandPicker, spanText } from "./shared";

/** Lower edges of the retry buckets, worst first (as the official dashboard). */
const RETRY_EDGES = [25, 20, 15, 10, 5, 0];

export function RetryBuckets() {
  const [band, setBand] = useState("all");
  const [span] = useTimeSpan(86400);
  const r = useRetries(span);
  return (
    <QueryState q={r} panel>
      {(data) => {
        const radios = data.filter((x) => band === "all" || x.radio === band);
        return (
          <div className="panel">
            <div className="panel-head">
              <b>AP radio TX retries</b>
              <span className="muted small">{spanText(span)}</span>
              <span className="spacer" />
              <BandPicker value={band} onChange={setBand} />
            </div>
            <div className="buckets">
              {RETRY_EDGES.map((min, i) => {
                const upper = i === 0 ? Infinity : RETRY_EDGES[i - 1]!;
                const inBucket = radios.filter(
                  (x) => x.tx_retry_pct >= min && x.tx_retry_pct < upper,
                );
                const tone = i === 0 ? "bad" : i === 1 ? "warn" : "good";
                const tip = inBucket
                  .map(
                    (x) =>
                      `${x.name ?? x.mac} ${bandName(x.radio)}: ${x.tx_retry_pct.toFixed(1)}%`,
                  )
                  .join("\n");
                return (
                  <div key={min} className="bucket">
                    <div
                      className={`bucket-bar bucket-${tone} ${inBucket.length ? "" : "bucket-empty"}`}
                      title={tip || undefined}
                    >
                      {inBucket.length || ""}
                    </div>
                  </div>
                );
              })}
            </div>
            <div className="bucket-edges muted small">
              {["35%+", "25%", "20%", "15%", "10%", "5%", "0%"].map((l) => (
                <span key={l}>{l}</span>
              ))}
            </div>
            <div className="muted small">
              Retries as a share of all transmissions (retries ÷ attempts +
              retries + dropped), per AP radio.
            </div>
          </div>
        );
      }}
    </QueryState>
  );
}
