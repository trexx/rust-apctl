import {
  createContext,
  useContext,
  useEffect,
  useLayoutEffect,
  useRef,
  useState,
} from "react";
import { useSearchParams } from "react-router";
import uPlot from "uplot";
import "uplot/dist/uPlot.min.css";
import { isFixed, spanBounds } from "../api";
import type { TimeSpan } from "../api";
import { duration, fromLocalInput, spanLabel, toLocalInput } from "../format";
import { Segmented, useDismiss, useSetParams } from "./common";

/** The page's time span: charts show exactly this window, gaps included. */
export const SpanContext = createContext<TimeSpan | null>(null);

/** Breaks lines where samples are missing for much longer than usual (an AP
 *  offline, apctl not running) by inserting a point with no values. */
function withGaps(ts: number[], cols: (number | null)[][]): uPlot.AlignedData {
  if (ts.length < 3) return [ts, ...cols] as uPlot.AlignedData;
  const steps = ts
    .slice(1)
    .map((t, i) => t - ts[i]!)
    .sort((a, b) => a - b);
  const typical = steps[Math.floor(steps.length / 2)]!;
  const outTs: number[] = [ts[0]!];
  const out = cols.map((c) => [c[0] ?? null]);
  for (let i = 1; i < ts.length; i++) {
    const t = ts[i]!;
    const prev = ts[i - 1]!;
    if (t - prev > Math.max(3 * typical, 120)) {
      outTs.push(Math.round((t + prev) / 2));
      out.forEach((c) => c.push(null));
    }
    outTs.push(t);
    out.forEach((c, j) => c.push(cols[j]![i] ?? null));
  }
  return [outTs, ...out] as uPlot.AlignedData;
}

/** When provided, dragging across a chart selects that time window for the whole page. */
export const ZoomContext = createContext<
  ((from: number, to: number) => void) | null
>(null);

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

interface ChartSeries {
  label: string;
  /** Missing (a field the server didn't send) draws nothing. */
  values: (number | null)[] | undefined;
  color: string;
  /** Fill the area under the line (use for one series per chart at most). */
  fill?: boolean;
  /** Plot against the right-hand axis (formatted with `formatRight`). */
  right?: boolean;
  /** Dashed line, for secondary measures. */
  dashed?: boolean;
  /** Multiplies every value (8 for bytes to bits), so callers can pass the
   *  query's own arrays and the chart only redraws when those change. */
  scale?: number;
}

const NO_VALUES: (number | null)[] = [];

const scaled = (s: ChartSeries) =>
  s.scale === undefined || s.scale === 1
    ? (s.values ?? NO_VALUES)
    : (s.values ?? NO_VALUES).map((v) => (v === null ? null : v * s.scale!));

/** What was last drawn: the chart skips drawing the same arrays again. */
interface Drawn {
  ts: number[];
  values: ((number | null)[] | undefined)[];
  scales: (number | undefined)[];
  span: TimeSpan | null;
}

const sameData = (a: Drawn | null, b: Drawn) =>
  !!a &&
  a.ts === b.ts &&
  a.span === b.span &&
  a.values.length === b.values.length &&
  a.values.every((v, i) => v === b.values[i] && a.scales[i] === b.scales[i]);

/** Whether the page is in dark mode now, following changes. */
function useDarkMode(): boolean {
  const query = "(prefers-color-scheme: dark)";
  const [dark, setDark] = useState(() => window.matchMedia(query).matches);
  useEffect(() => {
    const m = window.matchMedia(query);
    const on = () => setDark(m.matches);
    m.addEventListener("change", on);
    return () => m.removeEventListener("change", on);
  }, []);
  return dark;
}

interface Props {
  title: string;
  ts: number[];
  series: ChartSeries[];
  format: (v: number) => string;
  formatRight?: (v: number) => string;
  rightMax?: number;
  height?: number;
  min?: number;
  max?: number;
}

/** Axis width that fits its longest tick label (11px font). */
const fitLabels = (_u: uPlot, values: string[] | null) =>
  values && values.length
    ? Math.max(36, Math.max(...values.map((v) => v.length)) * 6.6 + 16)
    : 48;

function cssVar(name: string): string {
  return getComputedStyle(document.documentElement)
    .getPropertyValue(name)
    .trim();
}

/** A colour the canvas can draw: a `var(--x)` is read from the page's CSS. */
function resolve(color: string): string {
  const v = /^var\((--[\w-]+)\)$/.exec(color)?.[1];
  return v ? cssVar(v) || "#888" : color;
}

/**
 * `color` at `alpha` opacity, in whatever notation it is written: the canvas
 * reads it back as "#rrggbb", or "rgba(r, g, b, a)" when it is translucent.
 */
function withAlpha(color: string, alpha: number): string {
  const ctx = document.createElement("canvas").getContext("2d");
  if (ctx) {
    ctx.fillStyle = color;
    const c = String(ctx.fillStyle);
    const hex = /^#([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})$/i.exec(c);
    if (hex) {
      const [r, g, b] = hex.slice(1).map((x) => parseInt(x, 16));
      return `rgba(${r}, ${g}, ${b}, ${alpha})`;
    }
    const rgb = /^rgba?\((.*)\)$/.exec(c)?.[1]?.split(",").map(Number);
    if (rgb && rgb.length >= 3 && rgb.every(Number.isFinite)) {
      const [r, g, b, a = 1] = rgb;
      return `rgba(${r}, ${g}, ${b}, ${alpha * a})`;
    }
  }
  return `color-mix(in srgb, ${color} ${alpha * 100}%, transparent)`;
}

/** A compact time-series chart with a live legend. */
export function Chart({
  title,
  ts,
  series,
  format,
  formatRight,
  rightMax,
  height = 180,
  min,
  max,
}: Props) {
  const box = useRef<HTMLDivElement>(null);
  const plot = useRef<uPlot | null>(null);
  const drawn = useRef<Drawn | null>(null);
  const zoom = useContext(ZoomContext);
  const span = useContext(SpanContext);
  const dark = useDarkMode();
  // Read by uPlot's callbacks, which are only set up when the chart is built.
  const spanRef = useRef(span);
  const zoomRef = useRef(zoom);
  const formatRef = useRef(format);
  const formatRightRef = useRef(formatRight);
  useLayoutEffect(() => {
    spanRef.current = span;
    zoomRef.current = zoom;
    formatRef.current = format;
    formatRightRef.current = formatRight;
  });

  // Rebuild when the shape (or the colour scheme, for the axes and series) changes; otherwise only push new data.
  const shape =
    series.map((s) => s.label + s.color + (s.right ? "r" : "")).join("|") +
    `|${min}|${max}|${height}|${rightMax}|${!!zoom}|${dark}`;
  const hasRight = series.some((s) => s.right);
  const current = (): Drawn => ({
    ts,
    values: series.map((s) => s.values),
    scales: series.map((s) => s.scale),
    span,
  });

  useEffect(() => {
    const el = box.current;
    if (!el) return;
    const text = cssVar("--text-muted") || "#888";
    const grid = cssVar("--grid") || "rgba(128,128,128,0.15)";
    const axis = (): uPlot.Axis => ({
      stroke: text,
      grid: { stroke: grid, width: 1 },
      ticks: { stroke: grid, width: 1 },
      font: "11px system-ui, sans-serif",
    });
    const opts: uPlot.Options = {
      width: el.clientWidth,
      height,
      padding: [8, 8, 0, 0],
      cursor: {
        points: { size: 6 },
        drag: { x: true, y: false, setScale: !zoom },
      },
      hooks: zoom
        ? {
            setSelect: [
              (u) => {
                const { left, width } = u.select;
                if (width > 4 && zoomRef.current) {
                  zoomRef.current(
                    Math.floor(u.posToVal(left, "x")),
                    Math.ceil(u.posToVal(left + width, "x")),
                  );
                }
                u.setSelect({ left: 0, top: 0, width: 0, height: 0 }, false);
              },
            ],
          }
        : {},
      legend: { show: true, live: true },
      scales: {
        x: {
          time: true,
          // The selected window, so charts line up and missing data shows as a gap.
          range: (_u, lo, hi) =>
            spanRef.current ? spanBounds(spanRef.current) : [lo, hi],
        },
        y: {
          range: (_u, lo, hi) => [
            min ?? Math.min(0, lo),
            max ?? (hi > 0 ? hi * 1.1 : 1),
          ],
        },
        r: { range: (_u, _lo, hi) => [0, rightMax ?? (hi > 0 ? hi * 1.1 : 1)] },
      },
      axes: [
        axis(),
        {
          ...axis(),
          size: fitLabels,
          values: (_u, vals) =>
            vals.map((v) => (v === null ? "" : formatRef.current(v))),
        },
        ...(hasRight
          ? [
              {
                ...axis(),
                scale: "r",
                side: 1 as const,
                grid: { show: false },
                size: fitLabels,
                values: (_u: uPlot, vals: number[]) =>
                  vals.map((v) =>
                    v === null
                      ? ""
                      : (formatRightRef.current ?? formatRef.current)(v),
                  ),
              },
            ]
          : []),
      ],
      series: [
        {},
        ...series.map((s) => ({
          label: s.label,
          stroke: resolve(s.color),
          width: 1.5,
          scale: s.right ? "r" : "y",
          dash: s.dashed ? [4, 3] : undefined,
          fill: s.fill ? withAlpha(resolve(s.color), 0.13) : undefined,
          spanGaps: false,
          points: { show: false },
          value: (_u: uPlot, v: number | null) =>
            v === null || v === undefined
              ? "—"
              : (s.right
                  ? (formatRightRef.current ?? formatRef.current)
                  : formatRef.current)(v),
        })),
      ],
    };
    drawn.current = current();
    plot.current = new uPlot(opts, withGaps(ts, series.map(scaled)), el);
    const ro = new ResizeObserver(() =>
      plot.current?.setSize({ width: el.clientWidth, height }),
    );
    ro.observe(el);
    return () => {
      ro.disconnect();
      plot.current?.destroy();
      plot.current = null;
      drawn.current = null;
    };
    // Everything else it reads is either part of `shape` or read through a ref.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [shape]);

  // Callers build `series` on every render: only draw when the data arrays
  // themselves (or the span) change, not on every parent render.
  useEffect(() => {
    const now = current();
    if (sameData(drawn.current, now)) return;
    drawn.current = now;
    plot.current?.setData(withGaps(ts, series.map(scaled)));
  });

  const empty = ts.length === 0;
  return (
    <div className="chart">
      <div className="chart-title">{title}</div>
      <div
        ref={box}
        className={empty ? "chart-plot chart-empty" : "chart-plot"}
      />
      {empty && (
        <div className="chart-empty-note">No data in this range yet</div>
      )}
    </div>
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
  const [from, to] = spanBounds(value);
  const len = to - from;
  // Step a whole window back or forward; reaching the present goes live again.
  const step = (dir: -1 | 1) => {
    const now = Math.floor(Date.now() / 1000);
    const t = to + dir * len;
    if (t >= now - 60) pick({ last: len });
    else pick({ from: Math.max(from + dir * len, now - MAX_AGE), to: t });
  };
  return (
    <div className="range-picker" ref={box}>
      <button
        className="btn small step"
        aria-label="Earlier"
        title="Earlier"
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
          aria-expanded={open}
          title="Pick dates and times"
        >
          {fixed
            ? spanLabel(from, to)
            : preset
              ? "Custom…"
              : `Last ${duration(len)}`}
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
