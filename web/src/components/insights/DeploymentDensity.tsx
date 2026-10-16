import { useState } from "react";
import { useDensity } from "../../api";
import { useTimeSpan } from "../Chart";
import { QueryState } from "../common";
import type { DensityPin, Verdict } from "./shared";
import { BandPicker, DensityStrip, VerdictHead, spanText } from "./shared";

/** Weaker clients averaging below this (dBm) suggest they are far from their AP. */
const FAR = -75;
const VERY_FAR = -80;

/** Deployment density: per AP, the average signal of its weaker half of clients. */
export function DeploymentDensity() {
  const [band, setBand] = useState("all");
  const [span] = useTimeSpan(86400);
  const d = useDensity(span);
  return (
    <QueryState q={d} panel>
      {(data) => {
        const pins = data.aps.flatMap((ap) => {
          const g = ap.bands.find((b) => b.band === band);
          return g && g.clients > 0 && g.signal_avg !== 0
            ? [{ ap, g, quiet: g.traffic_pct < 1 }]
            : [];
        });
        const counted = pins.filter((p) => !p.quiet);
        const verdict: Verdict | null =
          counted.length === 0
            ? null
            : counted.some((p) => p.g.weakest_signal < FAR)
              ? {
                  text: "AP deployment density may need improvement",
                  tone: "warn",
                }
              : { text: "AP density is good", tone: "good" };
        return (
          <div className="panel">
            <div className="panel-head">
              <VerdictHead verdict={verdict} fallback="Deployment density" />
              <span className="muted small">{spanText(span)}</span>
              <span className="spacer" />
              <BandPicker value={band} onChange={setBand} />
            </div>
            <div className="muted small">
              Signal of each AP's weaker half of clients, averaged. Below −75
              dBm suggests clients are far from their AP.
            </div>
            <DensityStrip
              pins={pins.map(({ ap, g, quiet }): DensityPin => ({
                key: ap.mac,
                signal: g.weakest_signal,
                tone: quiet
                  ? "quiet"
                  : g.weakest_signal < VERY_FAR
                    ? "bad"
                    : g.weakest_signal < FAR
                      ? "warn"
                      : undefined,
                title: `${ap.name ?? ap.mac}: weaker clients ${g.weakest_signal} dBm, all clients ${g.signal_avg} dBm, ${g.clients} clients on average, ${g.traffic_pct.toFixed(1)}% of traffic${g.tx_retry_pct !== null ? `, ${g.tx_retry_pct.toFixed(1)}% TX retries` : ""}${quiet ? " (too little traffic to count)" : ""}`,
              }))}
            />
            {pins.length === 0 && (
              <div className="muted small">No clients in this range.</div>
            )}
          </div>
        );
      }}
    </QueryState>
  );
}
