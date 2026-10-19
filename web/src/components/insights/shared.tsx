import { useState } from "react";
import type { ReactNode } from "react";
import type { TimeSpan } from "../../api";
import { band, spanText } from "../../format";
import { QueryState, Segmented } from "../common";

const RADIOS = (["ng", "na"] as const).map((b) => [b, band(b)] as const);
const BANDS = [["all", "All radios"] as const, ...RADIOS];

/** A radio band: 2.4 GHz ("ng") or 5 GHz ("na"). */
export type Radio = (typeof RADIOS)[number][0];
/** A band, or "all" for both. */
export type BandChoice = (typeof BANDS)[number][0];

/** Both bands or one of them. */
export function BandPicker({
  value,
  onChange,
}: {
  value: BandChoice;
  onChange: (b: BandChoice) => void;
}) {
  return (
    <Segmented
      label="Band"
      options={BANDS}
      value={value}
      onChange={onChange}
    />
  );
}

/** One of the two bands. */
export function RadioPicker({
  value,
  onChange,
}: {
  value: Radio;
  onChange: (b: Radio) => void;
}) {
  return (
    <Segmented
      label="Band"
      options={RADIOS}
      value={value}
      onChange={onChange}
    />
  );
}

/**
 * An insight panel with a band picker: the title (fixed, or worked out from
 * the data and band, as a verdict is), the range and the picker on top, then
 * `children` for the chosen band ("all" at first).
 */
export function BandInsight<T>({
  q,
  span,
  title,
  children,
}: {
  q: { data: T | undefined; error: unknown };
  span: TimeSpan;
  title: ReactNode | ((data: T, band: string) => ReactNode);
  children: (data: T, band: string) => ReactNode;
}) {
  const [picked, setPicked] = useState<BandChoice>("all");
  return (
    <QueryState q={q} panel>
      {(data) => (
        <div className="panel">
          <div className="panel-head">
            {typeof title === "function" ? (
              title(data, picked)
            ) : (
              <b>{title}</b>
            )}
            <span className="muted small">{spanText(span)}</span>
            <span className="spacer" />
            <BandPicker value={picked} onChange={setPicked} />
          </div>
          {children(data, picked)}
        </div>
      )}
    </QueryState>
  );
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
  reverse,
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
