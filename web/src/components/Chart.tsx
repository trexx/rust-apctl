import {
  createContext,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { useSearchParams } from "react-router-dom";
import uPlot from "uplot";
import "uplot/dist/uPlot.min.css";
import { isFixed, spanBounds } from "../api";
import type { TimeSpan } from "../api";
import { duration, fromLocalInput, spanLabel, toLocalInput } from "../format";

/** When provided, dragging across a chart selects that time window for the whole page. */
export const ZoomContext = createContext<
  ((from: number, to: number) => void) | null
>(null);

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

/** Axis width that fits its longest tick label (11px font). */
const fitLabels = (_u: uPlot, values: string[] | null) =>
  values && values.length ? Math.max(36, Math.max(...values.map((v) => v.length)) * 6.6 + 16) : 48;

function cssVar(name: string): string {
  return getComputedStyle(document.documentElement)
    .getPropertyValue(name)
    .trim();
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
  const zoom = useContext(ZoomContext);
  const zoomRef = useRef(zoom);
  zoomRef.current = zoom;

  // Rebuild when the shape changes; otherwise only push new data.
  const shape =
    series.map((s) => s.label + s.color + (s.right ? "r" : "")).join("|") +
    `|${min}|${max}|${height}|${rightMax}|${!!zoom}`;
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
        x: { time: true },
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
          values: (_u, vals) => vals.map((v) => (v === null ? "" : format(v))),
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
                    v === null ? "" : (formatRight ?? format)(v),
                  ),
              },
            ]
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
          value: (_u: uPlot, v: number | null) =>
            v === null || v === undefined
              ? "—"
              : (s.right ? (formatRight ?? format) : format)(v),
        })),
      ],
    };
    const data = [ts, ...series.map((s) => s.values)] as uPlot.AlignedData;
    plot.current = new uPlot(opts, data, el);
    const ro = new ResizeObserver(() =>
      plot.current?.setSize({ width: el.clientWidth, height }),
    );
    ro.observe(el);
    return () => {
      ro.disconnect();
      plot.current?.destroy();
      plot.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [shape]);

  useEffect(() => {
    plot.current?.setData([
      ts,
      ...series.map((s) => s.values),
    ] as uPlot.AlignedData);
  }, [ts, series]);

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

export const RANGES: { label: string; seconds: number }[] = [
  { label: "1h", seconds: 3600 },
  { label: "6h", seconds: 6 * 3600 },
  { label: "24h", seconds: 86400 },
  { label: "7d", seconds: 7 * 86400 },
  { label: "30d", seconds: 30 * 86400 },
];

const MAX_AGE = 400 * 86400;

/** The page's time span, kept in the URL (`?range=` or `?from=&to=`) so reloads,
 *  links and the Back button keep it. */
export function useTimeSpan(
  defaultLast: number,
): [TimeSpan, (s: TimeSpan) => void] {
  const [params, setParams] = useSearchParams();
  const from = Number(params.get("from"));
  const to = Number(params.get("to"));
  const range = Number(params.get("range"));
  const span = useMemo<TimeSpan>(
    () =>
      from > 0 && to > from
        ? { from, to }
        : range > 0
          ? { last: range }
          : { last: defaultLast },
    [from, to, range, defaultLast],
  );
  const set = (s: TimeSpan) =>
    setParams((prev) => {
      const next = new URLSearchParams(prev);
      for (const k of ["range", "from", "to"]) next.delete(k);
      if (isFixed(s)) {
        next.set("from", String(s.from));
        next.set("to", String(s.to));
      } else if (s.last !== defaultLast) {
        next.set("range", String(s.last));
      }
      return next;
    });
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
  const box = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const outside = (e: MouseEvent) =>
      box.current && !box.current.contains(e.target as Node) && onClose();
    const esc = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    document.addEventListener("mousedown", outside);
    document.addEventListener("keydown", esc);
    return () => {
      document.removeEventListener("mousedown", outside);
      document.removeEventListener("keydown", esc);
    };
  }, [onClose]);
  const now = Math.floor(Date.now() / 1000);
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
  return (
    <div
      className="range-pop panel"
      ref={box}
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
          onClick={() => onApply({ from: midnight(7), to: now })}
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
  const fixed = isFixed(value);
  const preset = !fixed && RANGES.some((r) => r.seconds === value.last);
  const [from, to] = spanBounds(value);
  const len = to - from;
  // Step a whole window back or forward; reaching the present goes live again.
  const step = (dir: -1 | 1) => {
    const now = Math.floor(Date.now() / 1000);
    const t = to + dir * len;
    if (t >= now - 60) onChange({ last: len });
    else onChange({ from: Math.max(from + dir * len, now - MAX_AGE), to: t });
  };
  return (
    <div className="range-picker">
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
      <div className="segmented" role="group" aria-label="Time range">
        {RANGES.map((r) => (
          <button
            key={r.label}
            className={!fixed && r.seconds === value.last ? "active" : ""}
            onClick={() => onChange({ last: r.seconds })}
          >
            {r.label}
          </button>
        ))}
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
      </div>
      {open && (
        <CustomRange
          value={value}
          onClose={() => setOpen(false)}
          onApply={(s) => {
            onChange(s);
            setOpen(false);
          }}
        />
      )}
    </div>
  );
}
