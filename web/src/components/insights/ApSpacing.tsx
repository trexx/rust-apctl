import { useNeighbors } from "../../api";
import { band } from "../../format";
import { QueryState } from "../common";
import type { Verdict } from "./shared";
import { DensityStrip, VerdictHead } from "./shared";

/** APs hearing each other louder than this (dBm) overlap a lot. */
const TOO_CLOSE = -55;

/**
 * AP spacing (apctl's own, not an official metric): how loudly our APs hear
 * each other in their background scans. Very loud means they overlap a lot
 * (more co-channel contention, clients clinging to the wrong AP).
 */
export function ApSpacing() {
  const n = useNeighbors(7 * 86400, "all");
  return (
    <QueryState q={n} panel>
      {(data) => {
        const links = data.own_links.flatMap((l) =>
          l.signal === null ? [] : [{ ...l, signal: l.signal }],
        );
        const loudest = links.reduce((m, l) => Math.max(m, l.signal), -100);
        const verdict: Verdict | null =
          links.length === 0
            ? null
            : loudest > TOO_CLOSE
              ? { text: "APs may be too close", tone: "warn" }
              : { text: "APs are well spaced", tone: "good" };
        return (
          <div className="panel">
            <div className="panel-head">
              <VerdictHead verdict={verdict} fallback="AP spacing" />
              <span className="muted small">last 7 days</span>
            </div>
            <div className="muted small">
              How loudly your APs hear each other in their scans (not clients,
              so it differs from deployment density). Louder than −55 dBm means
              they overlap a lot.
            </div>
            <DensityStrip
              reverse
              pins={links.map((l) => ({
                key: `${l.from}-${l.to}-${l.radio}`,
                signal: l.signal,
                tone: l.signal > TOO_CLOSE ? "warn" : undefined,
                title: `${l.from_name} hears ${l.to_name} at ${l.signal} dBm (${band(l.radio)})`,
              }))}
            />
            {links.length === 0 && (
              <div className="muted small">
                No AP-to-AP measurements yet: they come from the APs' background
                scans.
              </div>
            )}
          </div>
        );
      }}
    </QueryState>
  );
}
