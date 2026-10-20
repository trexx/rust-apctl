import {
  useContext,
  useEffect,
  useEffectEvent,
  useRef,
  useSyncExternalStore,
} from "react";
import uPlot from "uplot";
import { spanBounds } from "../api";
import type { TimeSpan } from "../api";
import { SpanContext, ZoomContext } from "./span";

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

export interface ChartSeries {
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

/** Whether the page is in dark mode, kept once for all charts: one
 *  media-query listener while any chart is shown, not one per chart. */
const darkQuery = window.matchMedia("(prefers-color-scheme: dark)");
const darkListeners = new Set<() => void>();
const onDarkChange = () => darkListeners.forEach((l) => l());
const subscribeDark = (onChange: () => void) => {
  if (darkListeners.size === 0)
    darkQuery.addEventListener("change", onDarkChange);
  darkListeners.add(onChange);
  return () => {
    darkListeners.delete(onChange);
    if (darkListeners.size === 0)
      darkQuery.removeEventListener("change", onDarkChange);
  };
};
const readDark = () => darkQuery.matches;

/** Whether the page is in dark mode now, following changes. */
const useDarkMode = () => useSyncExternalStore(subscribeDark, readDark);

export interface ChartProps {
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

/** The chart that [`Chart`] shows once uPlot has loaded. */
export function Plot({
  title,
  ts,
  series,
  format,
  formatRight,
  rightMax,
  height: heightProp,
  min,
  max,
}: ChartProps) {
  // Not a default in the parameter: the React Compiler can't compile those.
  const height = heightProp ?? 180;
  const box = useRef<HTMLDivElement>(null);
  const plot = useRef<uPlot | null>(null);
  const drawn = useRef<Drawn | null>(null);
  const zoom = useContext(ZoomContext);
  const span = useContext(SpanContext);
  const dark = useDarkMode();
  // uPlot's callbacks are set up when the chart is built, and read these as they are now.
  const spanNow = useEffectEvent(() => span);
  const zoomTo = useEffectEvent((from: number, to: number) => zoom?.(from, to));
  const formatted = useEffectEvent((v: number, right: boolean) =>
    (right ? (formatRight ?? format) : format)(v),
  );

  // Rebuild when the shape (or the colour scheme, for the axes and series) changes; otherwise only push new data.
  const shape =
    series
      .map(
        (s) =>
          s.label +
          s.color +
          (s.right ? "r" : "") +
          (s.fill ? "f" : "") +
          (s.dashed ? "d" : ""),
      )
      .join("|") + `|${min}|${max}|${height}|${rightMax}|${!!zoom}|${dark}`;
  const hasRight = series.some((s) => s.right);
  const current = (): Drawn => ({
    ts,
    values: series.map((s) => s.values),
    scales: series.map((s) => s.scale),
    span,
  });

  // Builds the chart from what is shown now; everything it reads that the
  // chart's options hold is part of `shape`.
  const build = useEffectEvent((el: HTMLDivElement) => {
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
                if (width > 4)
                  zoomTo(
                    Math.floor(u.posToVal(left, "x")),
                    Math.ceil(u.posToVal(left + width, "x")),
                  );
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
          range: (_u, lo, hi) => {
            const span = spanNow();
            return span ? spanBounds(span) : [lo, hi];
          },
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
            vals.map((v) => (v === null ? "" : formatted(v, false))),
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
                  vals.map((v) => (v === null ? "" : formatted(v, true))),
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
            v === null || v === undefined ? "—" : formatted(v, !!s.right),
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
  });
  useEffect(() => {
    const el = box.current;
    return el ? build(el) : undefined;
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
