import { useRetries } from "../../api";
import { band as bandName, pct1, retryTone } from "../../format";
import { useTimeSpan } from "../Chart";
import { BandInsight } from "./shared";

/** Lower edges of the retry buckets, worst first (as the official dashboard). */
const RETRY_EDGES = [25, 20, 15, 10, 5, 0];
/** The labels under the bars' edges: the worst bucket runs up to 100%. */
const EDGE_LABELS = ["100%", ...RETRY_EDGES.map((e) => `${e}%`)];

export function RetryBuckets() {
  const [span] = useTimeSpan(86400);
  const r = useRetries(span);
  return (
    <BandInsight q={r} span={span} title="AP radio TX retries">
      {(data, band) => {
        const radios = data.filter((x) => band === "all" || x.radio === band);
        return (
          <>
            <div className="buckets">
              {RETRY_EDGES.map((min, i) => {
                const upper = i === 0 ? Infinity : RETRY_EDGES[i - 1]!;
                const inBucket = radios.filter(
                  (x) => x.tx_retry_pct >= min && x.tx_retry_pct < upper,
                );
                const tone = retryTone(min) || "good";
                const tip = inBucket
                  .map(
                    (x) =>
                      `${x.name ?? x.mac} ${bandName(x.radio)}: ${pct1(x.tx_retry_pct)}`,
                  )
                  .join("\n");
                return (
                  <div key={min} className="bucket">
                    <div
                      className={`bucket-bar fill-${tone} ${inBucket.length ? "" : "bucket-empty"}`}
                      title={tip || undefined}
                    >
                      {inBucket.length || ""}
                    </div>
                  </div>
                );
              })}
            </div>
            <div className="bucket-edges muted small">
              {EDGE_LABELS.map((l) => (
                <span key={l}>{l}</span>
              ))}
            </div>
            <div className="muted small">
              Retries as a share of all transmissions (retries ÷ attempts +
              retries + dropped), per AP radio.
            </div>
          </>
        );
      }}
    </BandInsight>
  );
}
