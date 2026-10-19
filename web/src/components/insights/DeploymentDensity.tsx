import { useDensity } from "../../api";
import type { DensityAp } from "../../api";
import { dbm, pct1 } from "../../format";
import { useTimeSpan } from "../Chart";
import type { DensityPin, Verdict } from "./shared";
import { BandInsight, DensityStrip, VerdictHead } from "./shared";

/** Weaker clients averaging below this (dBm) suggest they are far from their AP. */
const FAR = -75;
const VERY_FAR = -80;

/** The APs with clients on `band`; "quiet" ones carry too little traffic to count. */
const pinsOf = (aps: DensityAp[], band: string) =>
  aps.flatMap((ap) => {
    const g = ap.bands.find((b) => b.band === band);
    return g && g.clients > 0 && g.signal_avg !== 0
      ? [{ ap, g, quiet: g.traffic_pct < 1 }]
      : [];
  });

function verdictOf(pins: ReturnType<typeof pinsOf>): Verdict | null {
  const counted = pins.filter((p) => !p.quiet);
  return counted.length === 0
    ? null
    : counted.some((p) => p.g.weakest_signal < FAR)
      ? { text: "AP deployment density may need improvement", tone: "warn" }
      : { text: "AP density is good", tone: "good" };
}

/** Deployment density: per AP, the average signal of its weaker half of clients. */
export function DeploymentDensity() {
  const [span] = useTimeSpan(86400);
  const d = useDensity(span);
  return (
    <BandInsight
      q={d}
      span={span}
      title={(data, band) => (
        <VerdictHead
          verdict={verdictOf(pinsOf(data.aps, band))}
          fallback="Deployment density"
        />
      )}
    >
      {(data, band) => {
        const pins = pinsOf(data.aps, band);
        return (
          <>
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
                title: `${ap.name ?? ap.mac}: weaker clients ${dbm(g.weakest_signal)}, all clients ${dbm(g.signal_avg)}, ${g.clients} clients on average, ${pct1(g.traffic_pct)} of traffic${g.tx_retry_pct !== null ? `, ${pct1(g.tx_retry_pct)} TX retries` : ""}${quiet ? " (too little traffic to count)" : ""}`,
              }))}
            />
            {pins.length === 0 && (
              <div className="muted small">No clients in this range.</div>
            )}
          </>
        );
      }}
    </BandInsight>
  );
}
