import { Suspense, useRef, useState } from "react";
import type { ReactNode } from "react";
import { useSearchParams } from "react-router";
import "uplot/dist/uPlot.min.css";
import { isFixed, spanBounds } from "../api";
import type { TimeSpan } from "../api";
import { fromLocalInput, spanText, toLocalInput, useNow } from "../format";
import { lazyNamed } from "../lazy";
import { Segmented, useDismiss, useSetParams } from "./common";
import type { ChartProps } from "./Plot";
import { SpanScope } from "./span";

/**
 * The series colours: the page's `--c-*` variables, so dark mode gets the
 * dark palette. CSS takes them as they are; the chart reads their values.
 */
export const COLORS = {
  blue: "var(--c-blue)",
  orange: "var(--c-orange)",
  green: "var(--c-green)",
  purple: "var(--c-purple)",
  red: "var(--c-red)",
  teal: "var(--c-teal)",
};

// uPlot and the chart itself load with the first chart a page shows, so pages
// without charts never fetch them and the others show before they arrive.
const Plot = lazyNamed(() => import("./Plot"), "Plot");

/** A compact time-series chart with a live legend. */
export function Chart(props: ChartProps) {
  const height = props.height ?? 180;
  return (
    <Suspense
      fallback={
        <div className="chart">
          <div className="chart-title">{props.title}</div>
          <div className="chart-plot" style={{ height }} />
        </div>
      }
    >
      <Plot {...props} />
    </Suspense>
  );
}

const RANGES: { label: string; seconds: number }[] = [
  { label: "1h", seconds: 3600 },
  { label: "6h", seconds: 6 * 3600 },
  { label: "24h", seconds: 86400 },
  { label: "7d", seconds: 7 * 86400 },
  { label: "30d", seconds: 30 * 86400 },
];

const RANGE_OPTIONS = RANGES.map((r) => [r.seconds, r.label] as const);

const MAX_AGE = 400 * 86400;

/** The first day of the week in the browser's locale (1 = Monday … 7 = Sunday), Monday where it can't tell. */
function firstDayOfWeek(): number {
  try {
    const locale = new Intl.Locale(navigator.language) as Intl.Locale & {
      getWeekInfo?: () => { firstDay: number };
      weekInfo?: { firstDay: number };
    };
    return (locale.getWeekInfo?.() ?? locale.weekInfo)?.firstDay ?? 1;
  } catch {
    return 1;
  }
}

/** The page's time span, kept in the URL (`?range=` or `?from=&to=`) so reloads,
 *  links and the Back button keep it. */
export function useTimeSpan(
  defaultLast: number,
): [TimeSpan, (s: TimeSpan) => void] {
  const [params] = useSearchParams();
  const setUrl = useSetParams();
  const from = Number(params.get("from"));
  const to = Number(params.get("to"));
  const range = Number(params.get("range"));
  const span: TimeSpan =
    from > 0 && to > from
      ? { from, to }
      : range > 0
        ? { last: range }
        : { last: defaultLast };
  const set = (s: TimeSpan) =>
    setUrl(
      isFixed(s)
        ? { range: null, from: String(s.from), to: String(s.to) }
        : {
            range: s.last !== defaultLast ? String(s.last) : null,
            from: null,
            to: null,
          },
    );
  return [span, set];
}

function CustomRange({
  value,
  onApply,
  onClose,
}: {
  value: TimeSpan;
  onApply: (s: TimeSpan) => void;
  onClose: () => void;
}) {
  const [f0, t0] = spanBounds(value);
  const [from, setFrom] = useState(toLocalInput(f0));
  const [to, setTo] = useState(toLocalInput(t0));
  // "Now" as of opening the picker, so rendering stays pure.
  const [now] = useState(() => Math.floor(Date.now() / 1000));
  const f = fromLocalInput(from);
  const t = fromLocalInput(to);
  const error =
    f === null || t === null
      ? "Pick a start and an end"
      : t <= f
        ? "The end must be after the start"
        : f < now - MAX_AGE
          ? "Data is kept for about a year"
          : f >= now
            ? "The start is in the future"
            : null;
  const midnight = (daysAgo: number) => {
    const d = new Date();
    d.setHours(0, 0, 0, 0);
    d.setDate(d.getDate() - daysAgo);
    return Math.floor(d.getTime() / 1000);
  };
  // Midnight on the first day of this week (days numbered 1 = Monday … 7 = Sunday, as in firstDayOfWeek).
  const weekStart = () =>
    midnight(((new Date().getDay() || 7) - firstDayOfWeek() + 7) % 7);
  return (
    <div
      className="range-pop panel"
      role="dialog"
      aria-label="Custom time range"
    >
      <div className="range-quick">
        <button
          className="btn small"
          onClick={() => onApply({ from: midnight(0), to: now })}
        >
          Today
        </button>
        <button
          className="btn small"
          onClick={() => onApply({ from: midnight(1), to: midnight(0) })}
        >
          Yesterday
        </button>
        <button
          className="btn small"
          onClick={() => onApply({ from: weekStart(), to: now })}
        >
          This week so far
        </button>
      </div>
      <label>
        From
        <input
          type="datetime-local"
          className="search"
          value={from}
          max={toLocalInput(now)}
          onChange={(e) => setFrom(e.target.value)}
        />
      </label>
      <label>
        To
        <input
          type="datetime-local"
          className="search"
          value={to}
          max={toLocalInput(now)}
          onChange={(e) => setTo(e.target.value)}
        />
      </label>
      {error && <div className="small error">{error}</div>}
      <div className="range-actions">
        <span className="muted small">
          Tip: drag across a chart to zoom in.
        </span>
        <button className="btn small" onClick={onClose}>
          Cancel
        </button>
        <button
          className="btn small primary"
          disabled={!!error}
          onClick={() =>
            f !== null &&
            t !== null &&
            onApply({ from: f, to: Math.min(t, now) })
          }
        >
          Apply
        </button>
      </div>
    </div>
  );
}

/**
 * A page whose charts show the time `span`, which dragging across one of them
 * narrows; its head, `head` and then the range picker, sets it too.
 */
export function SpanPage({
  span,
  onSpan,
  head,
  children,
}: {
  span: TimeSpan;
  onSpan: (s: TimeSpan) => void;
  head: ReactNode;
  children: ReactNode;
}) {
  return (
    <SpanScope span={span} onSpan={onSpan}>
      <div className="page">
        <div className="page-head">
          {head}
          <span className="spacer" />
          <RangePicker value={span} onChange={onSpan} />
        </div>
        {children}
      </div>
    </SpanScope>
  );
}

export function RangePicker({
  value,
  onChange,
}: {
  value: TimeSpan;
  onChange: (s: TimeSpan) => void;
}) {
  const [open, setOpen] = useState(false);
  // The wrapper holds the toggle and the popup, so pressing the toggle
  // toggles rather than counting as a press outside.
  const box = useRef<HTMLDivElement>(null);
  useDismiss(box, () => setOpen(false), open);
  // Any other pick inside the wrapper (a preset, a step) closes the popup too.
  const pick = (s: TimeSpan) => {
    onChange(s);
    setOpen(false);
  };
  const fixed = isFixed(value);
  const preset = !fixed && RANGES.some((r) => r.seconds === value.last);
  const text = spanText(value);
  // A live window's start moves with the clock: read in render, React
  // Compiler would keep the first one, so the step reads it when pressed.
  const now = useNow();
  const start = fixed ? value.from : now - value.last;
  // Step a whole window back or forward; reaching the present goes live
  // again. At the oldest data kept the window stops, at its length: cutting
  // only its start left none at all, and an empty window shows live data.
  const step = (dir: -1 | 1) => {
    const [from, to] = spanBounds(value);
    const len = to - from;
    const at = Math.floor(Date.now() / 1000);
    const f = Math.max(from + dir * len, at - MAX_AGE);
    if (f + len >= at - 60) pick({ last: len });
    else pick({ from: f, to: f + len });
  };
  return (
    <div className="range-picker" ref={box}>
      <button
        className="btn small step"
        aria-label="Earlier"
        title="Earlier"
        disabled={start <= now - MAX_AGE}
        onClick={() => step(-1)}
      >
        ‹
      </button>
      <button
        className="btn small step"
        aria-label="Later"
        title="Later"
        disabled={!fixed}
        onClick={() => step(1)}
      >
        ›
      </button>
      <Segmented
        label="Time range"
        options={RANGE_OPTIONS}
        value={fixed ? null : value.last}
        onChange={(last) => pick({ last })}
      >
        <button
          className={preset ? "" : "active"}
          onClick={() => setOpen((o) => !o)}
          aria-pressed={!preset}
          aria-expanded={open}
          title="Pick dates and times"
        >
          {preset ? "Custom…" : text.charAt(0).toUpperCase() + text.slice(1)}
        </button>
      </Segmented>
      {open && (
        <CustomRange
          value={value}
          onClose={() => setOpen(false)}
          onApply={pick}
        />
      )}
    </div>
  );
}
