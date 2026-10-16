export const BANDS: Record<string, string> = { ng: "2.4 GHz", na: "5 GHz", "6e": "6 GHz" };

export const band = (radio: string | null | undefined) => (radio ? (BANDS[radio] ?? radio) : "—");

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

export function ago(ts: number | null | undefined, now = Date.now() / 1000): string {
  if (!ts) return "—";
  const d = now - ts;
  if (d < 10) return "just now";
  return `${duration(d)} ago`;
}

/** Date formatters for the browser's locale, falling back when the locale is invalid. */
function formatter(options: Intl.DateTimeFormatOptions): Intl.DateTimeFormat {
  try {
    return new Intl.DateTimeFormat(undefined, options);
  } catch {
    return new Intl.DateTimeFormat("en-GB", options);
  }
}
const timeFmt = formatter({ hour: "2-digit", minute: "2-digit", second: "2-digit" });
const dayFmt = formatter({ day: "numeric", month: "short" });
const minuteFmt = formatter({ hour: "2-digit", minute: "2-digit" });

/** Today's date as `clock` compares it: lists work it out once for all their rows. */
export const today = () => new Date().toDateString();

/** The time of day, with the date unless it is `day` (today). */
export function clock(ts: number, day = today()): string {
  const d = new Date(ts * 1000);
  const sameDay = d.toDateString() === day;
  const time = timeFmt.format(d);
  return sameDay ? time : `${dayFmt.format(d)} ${time}`;
}

/** Bits per second from bytes per second. */
export function bitrate(bytesPerSec: number | null | undefined): string {
  if (bytesPerSec === null || bytesPerSec === undefined) return "—";
  return rate(bytesPerSec * 8);
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

/** "−75 dBm", with a real minus sign. */
export const dbm = (v: number) => `${v < 0 ? "−" : ""}${Math.abs(v)} dBm`;

const compactFmt = (() => {
  try {
    return new Intl.NumberFormat(undefined, { notation: "compact" });
  } catch {
    return new Intl.NumberFormat("en-GB", { notation: "compact" });
  }
})();

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
