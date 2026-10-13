import { useEffect, useRef } from "react";
import uPlot from "uplot";
import "uplot/dist/uPlot.min.css";

export const COLORS = {
  blue: "#3b7ddd",
  orange: "#e8833a",
  green: "#2f9e6e",
  purple: "#8a63d2",
  red: "#d64545",
  teal: "#2aa3b8",
};

export interface ChartSeries {
  label: string;
  values: (number | null)[];
  color: string;
  /** Fill the area under the line (use for one series per chart at most). */
  fill?: boolean;
  /** Plot against the right-hand axis (formatted with `formatRight`). */
  right?: boolean;
  /** Dashed line, for secondary measures. */
  dashed?: boolean;
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

function cssVar(name: string): string {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

/** A compact time-series chart with a live legend. */
export function Chart({ title, ts, series, format, formatRight, rightMax, height = 180, min, max }: Props) {
  const box = useRef<HTMLDivElement>(null);
  const plot = useRef<uPlot | null>(null);

  // Rebuild when the shape changes; otherwise only push new data.
  const shape = series.map((s) => s.label + s.color + (s.right ? "r" : "")).join("|") + `|${min}|${max}|${height}|${rightMax}`;
  const hasRight = series.some((s) => s.right);

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
      cursor: { points: { size: 6 } },
      legend: { show: true, live: true },
      scales: {
        x: { time: true },
        y: { range: (_u, lo, hi) => [min ?? Math.min(0, lo), max ?? (hi > 0 ? hi * 1.1 : 1)] },
        r: { range: (_u, _lo, hi) => [0, rightMax ?? (hi > 0 ? hi * 1.1 : 1)] },
      },
      axes: [
        axis(),
        { ...axis(), size: 64, values: (_u, vals) => vals.map((v) => (v === null ? "" : format(v))) },
        ...(hasRight
          ? [{ ...axis(), scale: "r", side: 1 as const, grid: { show: false }, size: 52, values: (_u: uPlot, vals: number[]) => vals.map((v) => (v === null ? "" : (formatRight ?? format)(v))) }]
          : []),
      ],
      series: [
        {},
        ...series.map((s) => ({
          label: s.label,
          stroke: s.color,
          width: 1.5,
          scale: s.right ? "r" : "y",
          dash: s.dashed ? [4, 3] : undefined,
          fill: s.fill ? `${s.color}22` : undefined,
          spanGaps: false,
          points: { show: false },
          value: (_u: uPlot, v: number | null) => (v === null || v === undefined ? "—" : (s.right ? (formatRight ?? format) : format)(v)),
        })),
      ],
    };
    const data = [ts, ...series.map((s) => s.values)] as uPlot.AlignedData;
    plot.current = new uPlot(opts, data, el);
    const ro = new ResizeObserver(() => plot.current?.setSize({ width: el.clientWidth, height }));
    ro.observe(el);
    return () => {
      ro.disconnect();
      plot.current?.destroy();
      plot.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [shape]);

  useEffect(() => {
    plot.current?.setData([ts, ...series.map((s) => s.values)] as uPlot.AlignedData);
  }, [ts, series]);

  const empty = ts.length === 0;
  return (
    <div className="chart">
      <div className="chart-title">{title}</div>
      <div ref={box} className={empty ? "chart-plot chart-empty" : "chart-plot"} />
      {empty && <div className="chart-empty-note">No data in this range yet</div>}
    </div>
  );
}

export const RANGES: { label: string; seconds: number }[] = [
  { label: "1h", seconds: 3600 },
  { label: "6h", seconds: 6 * 3600 },
  { label: "24h", seconds: 86400 },
  { label: "7d", seconds: 7 * 86400 },
  { label: "30d", seconds: 30 * 86400 },
];

export function RangePicker({ value, onChange }: { value: number; onChange: (s: number) => void }) {
  return (
    <div className="segmented" role="group" aria-label="Time range">
      {RANGES.map((r) => (
        <button key={r.label} className={r.seconds === value ? "active" : ""} onClick={() => onChange(r.seconds)}>
          {r.label}
        </button>
      ))}
    </div>
  );
}
