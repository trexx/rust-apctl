import type { TimeSpan } from "../../api";
import { band, duration, spanLabel } from "../../format";

export function BandPicker({
  value,
  onChange,
  all = true,
}: {
  value: string;
  onChange: (b: string) => void;
  all?: boolean;
}) {
  const bands = [
    ...(all ? [["all", "All radios"]] : []),
    ...["ng", "na"].map((b) => [b, band(b)]),
  ];
  return (
    <div className="segmented" role="group" aria-label="Band">
      {bands.map(([v, l]) => (
        <button
          key={v}
          className={value === v ? "active" : ""}
          onClick={() => onChange(v!)}
        >
          {l}
        </button>
      ))}
    </div>
  );
}

/** "last 24 hours", or the fixed window. */
export function spanText(span: TimeSpan): string {
  return "from" in span
    ? spanLabel(span.from, span.to)
    : `last ${duration(span.last).replace(/^1d 0h$/, "24h")}`;
}

/** A verdict over a panel's data, coloured by how it came out. */
export interface Verdict {
  text: string;
  tone: "good" | "warn";
}

export function VerdictHead({
  verdict,
  fallback,
}: {
  verdict: Verdict | null;
  fallback: string;
}) {
  return verdict ? (
    <b className={`tone-${verdict.tone}`}>{verdict.text}</b>
  ) : (
    <b>{fallback}</b>
  );
}

export interface DensityPin {
  key: string;
  /** dBm, placed on a −90 … −30 scale. */
  signal: number;
  tone?: "quiet" | "warn" | "bad";
  title: string;
}

const AXIS = [-90, -80, -70, -60, -50, -40, -30];

const pos = (s: number) =>
  `${((Math.min(-30, Math.max(-90, s)) + 90) / 60) * 100}%`;

/** Pins on a signal scale; pins in the same 3 dB step stack upwards. */
export function DensityStrip({
  pins,
  reverse = false,
}: {
  pins: DensityPin[];
  /** Colour the scale for "louder is worse" (AP spacing). */
  reverse?: boolean;
}) {
  const stack = new Map<number, number>();
  return (
    <div className="density">
      <div className={reverse ? "density-scale reverse" : "density-scale"} />
      {pins.map((p) => {
        const step = Math.round(p.signal / 3);
        const level = stack.get(step) ?? 0;
        stack.set(step, level + 1);
        return (
          <div
            key={p.key}
            className={`density-mark ${p.tone ?? ""}`}
            style={{ left: pos(p.signal), top: 8 - level * 14 }}
            title={p.title}
          />
        );
      })}
      <div className="density-axis muted small">
        {AXIS.map((v) => (
          <span key={v}>{v}</span>
        ))}
      </div>
    </div>
  );
}
