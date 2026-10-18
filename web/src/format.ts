import { useSyncExternalStore } from "react";
import type { TimeSpan } from "./api";

export const BANDS: Record<string, string> = { ng: "2.4 GHz", na: "5 GHz", "6e": "6 GHz" };

export const band = (radio: string | null | undefined) => (radio ? (BANDS[radio] ?? radio) : "—");

/** "5 GHz ch 36", or the band alone when the channel isn't known. */
export const bandChannel = (radio: string | null | undefined, channel: number | null | undefined) => `${band(radio)}${channel ? ` ch ${channel}` : ""}`;

/** An uplink's state: down, else its speed, else "—" (the AP doesn't say). */
export const uplinkText = (u: { up: boolean | null; speed: number | null; full_duplex: boolean | null }) =>
  u.up === false ? "down" : u.speed ? `${u.speed} Mbps${u.full_duplex ? " FD" : ""}` : "—";

export function duration(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined) return "—";
  const s = Math.max(0, Math.floor(seconds));
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m`;
  return `${s}s`;
}

/** How long before `now` (`useNow()`) `ts` was: "5m ago". */
export function ago(ts: number | null | undefined, now: number): string {
  if (!ts) return "—";
  const d = now - ts;
  if (d < 10) return "just now";
  return `${duration(d)} ago`;
}

/** A date formatter for the browser's locale. */
const formatter = (options: Intl.DateTimeFormatOptions) => new Intl.DateTimeFormat(undefined, options);
const timeFmt = formatter({ hour: "2-digit", minute: "2-digit", second: "2-digit" });
const dayFmt = formatter({ day: "numeric", month: "short" });
const minuteFmt = formatter({ hour: "2-digit", minute: "2-digit" });
const dateTimeFmt = formatter({ day: "numeric", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" });

/** "13 Oct 2026, 06:00" in the browser's locale. */
export const dateTime = (ts: number) => dateTimeFmt.format(new Date(ts * 1000));

/** "HH:MM" for minutes after midnight. */
export const hhmm = (minutes: number) =>
  `${String(Math.floor(minutes / 60) % 24).padStart(2, "0")}:${String(minutes % 60).padStart(2, "0")}`;

/** The local date of `now`, worked out once for all the times a list shows with the same `now`. */
let dayOfNow = { now: NaN, day: "" };
function dayOf(now: number): string {
  if (dayOfNow.now !== now) dayOfNow = { now, day: new Date(now * 1000).toDateString() };
  return dayOfNow.day;
}

/** Whether two times (Unix seconds) fall on the same local date. */
export const sameDay = (a: number, b: number) => a === b || new Date(a * 1000).toDateString() === new Date(b * 1000).toDateString();

/** The time of day, with the date unless it is the date of `now` (`useNow()`). */
export function clock(ts: number, now: number): string {
  const d = new Date(ts * 1000);
  const time = timeFmt.format(d);
  return d.toDateString() === dayOf(now) ? time : `${dayFmt.format(d)} ${time}`;
}

const unixNow = () => Math.floor(Date.now() / 1000);

/** A clock shared by the components that show times relative to now: one timer per interval, while they're shown. */
interface Ticker {
  subscribe: (onTick: () => void) => () => void;
  read: () => number;
}

const tickers = new Map<number, Ticker>();

function ticker(ms: number): Ticker {
  const known = tickers.get(ms);
  if (known) return known;
  const listeners = new Set<() => void>();
  let timer: number | undefined;
  let now = unixNow();
  const t: Ticker = {
    subscribe(onTick) {
      listeners.add(onTick);
      timer ??= window.setInterval(() => {
        now = unixNow();
        for (const l of listeners) l();
      }, ms);
      return () => {
        listeners.delete(onTick);
        if (listeners.size > 0) return;
        window.clearInterval(timer);
        timer = undefined;
      };
    },
    // While nothing is subscribed the timer is off: the first reading after a while is a fresh one.
    read() {
      if (timer === undefined && unixNow() !== now) now = unixNow();
      return now;
    },
  };
  tickers.set(ms, t);
  return t;
}

/**
 * The time (Unix seconds), renewed every `ms`: what `ago` and `clock` measure from. Read during render, the
 * time would be kept by React Compiler's memoisation; this re-renders the component as it passes instead.
 */
export function useNow(ms = 60_000): number {
  const t = ticker(ms);
  return useSyncExternalStore(t.subscribe, t.read);
}

/** A rate in bits per second. */
export function rate(bps: number): string {
  const units = ["bps", "kbps", "Mbps", "Gbps"];
  let v = bps;
  let i = 0;
  while (v >= 1000 && i < units.length - 1) {
    v /= 1000;
    i++;
  }
  return `${v >= 100 || i === 0 ? v.toFixed(0) : v.toFixed(1)} ${units[i]}`;
}

/** PHY rate reported in kbps. */
export function phy(kbps: number | null | undefined): string {
  if (!kbps) return "—";
  return kbps >= 1000 ? `${Math.round(kbps / 1000)} Mbps` : `${kbps} kbps`;
}

export function bytes(n: number | null | undefined): string {
  if (n === null || n === undefined) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v >= 100 || i === 0 ? v.toFixed(0) : v.toFixed(1)} ${units[i]}`;
}

export const pct = (v: number | null | undefined) => (v === null || v === undefined ? "—" : `${Math.round(v)}%`);

/** A percentage with one decimal: "12.5%". */
export const pct1 = (v: number | null | undefined) => (v === null || v === undefined ? "—" : `${v.toFixed(1)}%`);

/**
 * Client signal levels (dBm) commonly used for Wi-Fi: at least `good` is good
 * (at least `excellent` excellent), at least `fair` is fair, below it poor.
 */
export const SIGNAL = { excellent: -60, good: -65, fair: -75 } as const;

/** Signal quality bucket for colouring. */
export function signalClass(dbm: number | null | undefined): "good" | "fair" | "poor" | "none" {
  if (dbm === null || dbm === undefined) return "none";
  if (dbm >= SIGNAL.good) return "good";
  if (dbm >= SIGNAL.fair) return "fair";
  return "poor";
}

/**
 * TX retry shares (%) as the official dashboard colours its retry buckets: at
 * least `bad` is bad, at least `warn` needs attention, below it is fine.
 */
export const RETRY = { warn: 20, bad: 25 } as const;

/** A TX retry share's tone: "bad", "warn", or "" (fine or unknown). */
export const retryTone = (pct: number | null | undefined): "bad" | "warn" | "" =>
  pct === null || pct === undefined ? "" : pct >= RETRY.bad ? "bad" : pct >= RETRY.warn ? "warn" : "";

/** "−75 dBm", with a real minus sign. */
export const dbm = (v: number) => `${v < 0 ? "−" : ""}${Math.abs(v)} dBm`;

const compactFmt = new Intl.NumberFormat(undefined, { notation: "compact" });

/** A count for people: "950", "12K", "3.4M". */
export const compact = (n: number | null | undefined) => (n === null || n === undefined ? "—" : compactFmt.format(n));

/** A limit for people: "5 Mbps", or "none". */
export const speed = (kbps: number | null | undefined) => (kbps && kbps > 0 ? `${kbps >= 1000 ? `${+(kbps / 1000).toFixed(2)} Mbps` : `${kbps} kbps`}` : "none");

/** "13 Oct 06:00 – 09:00", or with both dates when the window spans days. */
export function spanLabel(from: number, to: number): string {
  const f = new Date(from * 1000);
  const t = new Date(to * 1000);
  const start = `${dayFmt.format(f)} ${minuteFmt.format(f)}`;
  return f.toDateString() === t.toDateString() ? `${start} – ${minuteFmt.format(t)}` : `${start} – ${dayFmt.format(t)} ${minuteFmt.format(t)}`;
}

/** "last 24h", "last 6h", "last 7d", "last 1h 30m", or the fixed window. */
export const spanText = (span: TimeSpan): string => ("from" in span ? spanLabel(span.from, span.to) : `last ${duration(span.last).replace(/^1d 0h$/, "24h").replace(/ 0[hm]$/, "")}`);

/** Value for an <input type="datetime-local"> in the browser's time zone. */
export function toLocalInput(ts: number): string {
  const d = new Date(ts * 1000);
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`;
}

export function fromLocalInput(v: string): number | null {
  const t = new Date(v).getTime();
  return Number.isFinite(t) ? Math.floor(t / 1000) : null;
}
