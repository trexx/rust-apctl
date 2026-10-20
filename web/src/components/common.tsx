import { memo, useEffect, useEffectEvent, useState } from "react";
import type { InputHTMLAttributes, ReactNode, RefObject } from "react";
import { Link, useSearchParams } from "react-router";
import { useQueryClient } from "@tanstack/react-query";
import type { QueryKey } from "@tanstack/react-query";
import { eventData, useDeviceNames } from "../api";
import type {
  AppEvent,
  EventKind,
  EventPayloads,
  LogLine,
  Names,
} from "../api";
import {
  band,
  clock,
  dbm,
  duration,
  loadTone,
  sameDay,
  signalTone,
  toneClass,
  useNow,
} from "../format";
import type { Tone } from "../format";

export function Stat({
  label,
  value,
  sub,
}: {
  label: string;
  value: ReactNode;
  sub?: ReactNode;
}) {
  return (
    <div className="stat">
      <div className="stat-label">{label}</div>
      <div className="stat-value">{value}</div>
      {sub !== undefined && <div className="stat-sub">{sub}</div>}
    </div>
  );
}

/** A status dot, beside text that says the same: good or bad (`ok`), or one of three tones. */
export function Dot(p: { ok: boolean } | { tone: Tone }) {
  const tone = "tone" in p ? p.tone : p.ok ? "good" : "bad";
  return <span className={`dot fill-${tone}`} aria-hidden />;
}

export function Signal({ dbm: v }: { dbm: number | null | undefined }) {
  return <span className={toneClass(signalTone(v))}>{dbm(v)}</span>;
}

/** A bar for a level (a percentage, or out of `max`), named `label` for screen readers. */
export function Meter({
  value,
  max: limit,
  label,
}: {
  value: number | null | undefined;
  max?: number;
  label: string;
}) {
  const known = value !== null && value !== undefined;
  const max = limit ?? 100;
  const v = known ? Math.min(100, (value / max) * 100) : 0;
  const text = known ? `${Math.round(value)}` : "unknown";
  return (
    <span
      className="meter"
      title={text}
      role="meter"
      aria-label={label}
      aria-valuemin={0}
      aria-valuemax={max}
      aria-valuenow={known ? value : undefined}
      aria-valuetext={known ? undefined : text}
    >
      <span
        className={`meter-fill fill-${loadTone(v)}`}
        style={{ width: `${v}%` }}
      />
    </span>
  );
}

/** A column's heading: its label, or `[label, title]` to explain it on hover. */
type Column = string | readonly [label: string, title: string];

/** A table's head row; a column given as `false` or `undefined` is left out. */
export function THead({
  columns,
}: {
  columns: readonly (Column | false | undefined)[];
}) {
  return (
    <thead>
      <tr>
        {columns.map((c, i) => {
          if (c === false || c === undefined) return null;
          const [label, title] = typeof c === "string" ? [c] : c;
          return (
            <th key={i} title={title}>
              {label}
            </th>
          );
        })}
      </tr>
    </thead>
  );
}

/** A checkbox with its label beside it. */
export function Toggle({
  value,
  onChange,
  label,
  disabled,
}: {
  value: boolean | null | undefined;
  onChange: (v: boolean) => void;
  label: string;
  disabled?: boolean;
}) {
  return (
    <label className="check">
      <input
        type="checkbox"
        checked={value === true}
        disabled={disabled}
        onChange={(e) => onChange(e.target.checked)}
      />
      {label}
    </label>
  );
}

/**
 * A text field (class "search" unless given) that names itself by its
 * `aria-label`; `onChange` gets the text. Settings rows use `TextInput`.
 */
export function TextField({
  value,
  onChange,
  className,
  ...props
}: Omit<InputHTMLAttributes<HTMLInputElement>, "value" | "onChange"> & {
  value: string | null | undefined;
  onChange: (v: string) => void;
}) {
  return (
    <input
      className={className ?? "search"}
      {...props}
      value={value ?? ""}
      onChange={(e) => onChange(e.target.value)}
    />
  );
}

export function Loading() {
  return <div className="muted pad">Loading…</div>;
}

export const errorText = (error: unknown) =>
  error instanceof Error ? error.message : String(error);

export function ErrorNote({ error }: { error: unknown }) {
  return <div className="error pad">{errorText(error)}</div>;
}

/**
 * What stands in for a query's data until it is there: its error, or else
 * "Loading…". A component shows it only while it has no data (`if (!q.data)
 * return <QueryNote q={q} />`), so a failed background refetch doesn't
 * replace what was fetched. With `panel`, it sits in a panel, so the layout
 * doesn't jump when the data (usually a panel itself) arrives.
 */
export function QueryNote({
  q,
  panel,
}: {
  q: { error: unknown };
  panel?: boolean;
}) {
  const note = q.error ? <ErrorNote error={q.error} /> : <Loading />;
  return panel ? <div className="panel">{note}</div> : note;
}

/** A query's data, rendered by `children`, or else its `QueryNote`. */
export function QueryState<T>({
  q,
  panel,
  children,
}: {
  q: { data: T | undefined; error: unknown };
  panel?: boolean;
  children: (data: T) => ReactNode;
}) {
  if (q.data !== undefined) return <>{children(q.data)}</>;
  return <QueryNote q={q} panel={panel} />;
}

/** An action's outcome, shown under its buttons. */
type RunResult = { ok: boolean; text: string } | null;

/**
 * Runs one action at a time: `busy` while it runs, then its outcome. The
 * action's own message (a string it returns) wins over `done`. `refresh` keys
 * are invalidated afterwards, before `busy` clears, so the next action starts
 * from fresh data; with `delay` (for changes the server applies a moment
 * later) they are invalidated after that many milliseconds instead.
 */
export function useRunner(refresh: QueryKey[] = [], delay = 0) {
  const qc = useQueryClient();
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<RunResult>(null);
  const run = async (fn: () => Promise<unknown>, done?: string) => {
    setBusy(true);
    setMsg(null);
    const outcome = await Promise.resolve()
      .then(fn)
      .then(
        (r): RunResult => {
          const text = typeof r === "string" && r ? r : done;
          return text ? { ok: true, text } : null;
        },
        (e: unknown): RunResult => ({ ok: false, text: errorText(e) }),
      );
    if (outcome) setMsg(outcome);
    const invalidate = () =>
      Promise.all(
        refresh.map((key) => qc.invalidateQueries({ queryKey: key })),
      );
    if (delay) window.setTimeout(() => void invalidate(), delay);
    else await invalidate().catch(() => undefined);
    setBusy(false);
  };
  return { busy, msg, setMsg, run };
}

/** An action's outcome line, or `why` actions are unavailable. */
export function Outcome({
  msg,
  why,
  inline,
}: {
  msg: RunResult;
  why?: string | null;
  inline?: boolean;
}) {
  const Tag = inline ? "span" : "div";
  if (msg)
    return (
      <Tag className={`small ${msg.ok ? "tone-good" : "error"}`}>
        {msg.text}
      </Tag>
    );
  return why ? <Tag className="small muted">{why}</Tag> : null;
}

/** The page's tab, kept in the URL (`?tab=`); the first tab has no parameter. */
export function useUrlTab<K extends string>(
  tabs: readonly (readonly [K, string])[],
): [K, (k: K) => void] {
  const [params, setParams] = useSearchParams();
  const first = tabs[0]![0];
  const tab = tabs.find(([k]) => k === params.get("tab"))?.[0] ?? first;
  return [tab, (k: K) => setParams(k === first ? {} : { tab: k })];
}

/**
 * Sets URL search parameters, keeping the others; an empty value removes one.
 * With `replace`, the change doesn't add a history entry.
 */
export function useSetParams() {
  const [, setParams] = useSearchParams();
  return (
    changes: Record<string, string | null | undefined>,
    options?: { replace?: boolean },
  ) =>
    setParams(
      (prev) => {
        const next = new URLSearchParams(prev);
        for (const [k, v] of Object.entries(changes)) {
          if (v) next.set(k, v);
          else next.delete(k);
        }
        return next;
      },
      { replace: options?.replace },
    );
}

/**
 * A row of buttons picking one of `options` (none when `value` matches none);
 * `children`, more buttons, follow them. With `tabs`, it switches the page's
 * views (in the URL): the current one is marked as the current page rather
 * than as a pressed button.
 */
export function Segmented<K extends string | number | boolean>({
  options,
  value,
  onChange,
  label,
  tabs,
  children,
}: {
  options: readonly (readonly [K, ReactNode])[];
  value: K | null;
  onChange: (k: K) => void;
  label?: string;
  tabs?: boolean;
  children?: ReactNode;
}) {
  return (
    <div className="segmented" role="group" aria-label={label}>
      {options.map(([k, text]) => (
        <button
          key={String(k)}
          aria-current={tabs && value === k ? "page" : undefined}
          aria-pressed={tabs ? undefined : value === k}
          className={value === k ? "active" : ""}
          onClick={() => onChange(k)}
        >
          {text}
        </button>
      ))}
      {children}
    </div>
  );
}

/** Calls `onClose` on a mouse press outside `ref`'s element or on Escape, while `active`. */
export function useDismiss(
  ref: RefObject<HTMLElement | null>,
  onClose: () => void,
  active = true,
) {
  const close = useEffectEvent(onClose);
  useEffect(() => {
    if (!active) return;
    const outside = (e: MouseEvent) =>
      ref.current && !ref.current.contains(e.target as Node) && close();
    const esc = (e: KeyboardEvent) => e.key === "Escape" && close();
    document.addEventListener("mousedown", outside);
    document.addEventListener("keydown", esc);
    return () => {
      document.removeEventListener("mousedown", outside);
      document.removeEventListener("keydown", esc);
    };
  }, [ref, active]);
}

/** Picks one AP, or "" for all of them. */
export function ApSelect({
  value,
  onChange,
}: {
  value: string;
  onChange: (mac: string) => void;
}) {
  const names = useDeviceNames();
  return (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value)}
      aria-label="Access point"
    >
      <option value="">All APs</option>
      {Object.entries(names).map(([mac, name]) => (
        <option key={mac} value={mac}>
          {name}
        </option>
      ))}
    </select>
  );
}

function DeviceLink({ mac, names }: { mac: string | null; names: Names }) {
  if (!mac) return <span className="muted">—</span>;
  return <Link to={`/devices/${mac}`}>{names[mac] ?? mac}</Link>;
}

type EventTone = "bad" | "warn" | "info" | "neutral";

interface EventSpec<K extends EventKind> {
  label: string;
  tone: EventTone | ((d: Partial<EventPayloads[K]>) => EventTone);
  /** The detail line (`ts` is the event's); a method so the table below can hold every kind. */
  describe?(d: Partial<EventPayloads[K]>, names: Names, ts: number): string;
}

const parts = (...xs: (string | null | undefined | false)[]) =>
  xs.filter(Boolean).join(" · ");

/** A radio's channel, width and power as a radio_changed event records them, "ch 36/80 MHz/20 dBm", leaving out what it lacks. */
const radioLevels = (l: EventPayloads["radio_changed"]["from"]) =>
  [
    `ch ${l?.channel ?? "?"}`,
    l?.bw && `${l.bw} MHz`,
    l?.tx_power != null && dbm(l.tx_power),
  ]
    .filter(Boolean)
    .join("/");

/** A kernel fault line, as the syslog crash capture recognises one (not a panic's closing line). */
const FAULT =
  /(?<!end )Kernel panic|Oops[:[]|Internal error:|sending SIGSEGV to |unhandled level 2 translation fault/;

/** A crash's summary line: its first fault, else its first line (a crash store's tail may start anywhere). */
const crashLine = (lines: string[] = []) =>
  lines.find((l) => FAULT.test(l)) ?? lines[0];

/** Every event kind: its label, colour and detail line. */
const EVENTS: { [K in EventKind]: EventSpec<K> } = {
  ap_seen: {
    label: "AP discovered",
    tone: "neutral",
    describe: (d) => parts(d.model, d.version, d.ip),
  },
  ap_online: {
    label: "AP back online",
    tone: "neutral",
    describe: (d) => (d.offline_for ? `after ${duration(d.offline_for)}` : ""),
  },
  ap_offline: {
    label: "AP offline",
    tone: "bad",
    // With its date only if that isn't the event's.
    describe: (d, _names, ts) =>
      d.last_seen !== undefined ? `last seen ${clock(d.last_seen, ts)}` : "",
  },
  ap_restarted: {
    label: "AP restarted",
    tone: "bad",
    describe: (d) => `uptime ${duration(d.uptime)}`,
  },
  ap_firmware_changed: {
    label: "Firmware changed",
    tone: "neutral",
    describe: (d) => `${d.from ?? "?"} → ${d.to ?? "?"}`,
  },
  // Older events (before 0.3.2) guessed a restart; it was a config being applied.
  ap_radios_restarting: { label: "Applying configuration", tone: "neutral" },
  ap_config_applied: {
    label: "Configuration applied",
    tone: "neutral",
    describe: (d) => {
      const secs = `in ${d.seconds}s`;
      if ((d.reconnected ?? 0) > 0)
        return `${secs}, ${d.reconnected} of ${d.clients_before} clients had to reconnect`;
      return (d.clients_before ?? 0) > 0 ? `${secs}, no clients dropped` : secs;
    },
  },
  config_applied: {
    label: "Config applied",
    tone: "neutral",
    describe: (d) =>
      d.seconds_after_push !== null && d.seconds_after_push !== undefined
        ? `${d.seconds_after_push}s after the push`
        : "",
  },
  client_connect_failed: {
    label: "Connection failed",
    tone: "warn",
    describe: (d) =>
      parts(
        d.essid,
        d.reason && `reason: ${d.reason}`,
        !!d.rssi && dbm(d.rssi),
      ),
  },
  dfs_radar: {
    label: "Radar detected (DFS)",
    tone: "warn",
    describe: (d) => (d.channel ? `channel ${d.channel}` : ""),
  },
  rogue_ap: {
    label: "Rogue AP (reported by AP)",
    tone: "bad",
    describe: (d) =>
      parts(
        d.essid,
        d.bssid,
        !!d.channel && `channel ${d.channel}`,
        typeof d.signal === "number" &&
          d.signal !== 0 &&
          (d.signal < 0 ? dbm(d.signal) : `signal ${d.signal}`),
      ),
  },
  network_threat: {
    label: "Suspicious network",
    tone: (d) =>
      d.severity === "low" ? "info" : d.severity === "medium" ? "warn" : "bad",
    describe: (d) => d.detail ?? "",
  },
  client_kicked: {
    label: "Client kicked",
    tone: "warn",
    describe: (d) =>
      parts(
        d.reason && `reason: ${d.reason}`,
        d.signal != null && `signal ${dbm(d.signal)}`,
        d.vap,
      ),
  },
  ap_upgrade_sent: {
    label: "Update sent",
    tone: "neutral",
    describe: (d) => `to ${d.target ?? "?"}`,
  },
  ap_upgrade_started: {
    label: "Update started",
    tone: "neutral",
    describe: (d) => (d.by ? `started by ${d.by}` : ""),
  },
  ap_upgrade_progress: {
    label: "Updating",
    tone: "neutral",
    describe: (d) =>
      d.step === "preparing"
        ? "preparing to download the firmware"
        : d.step === "downloading"
          ? "downloading the firmware"
          : d.step === "writing"
            ? "checked; writing it to flash"
            : String(d.step ?? ""),
  },
  ap_upgrade_failed: {
    label: "Update failed",
    tone: "bad",
    describe: (d) => String(d.detail ?? d.reason ?? ""),
  },
  ap_upgraded: {
    label: "Firmware updated",
    tone: "neutral",
    describe: (d) =>
      `${d.from ?? "?"} → ${d.to ?? "?"}${d.custom ? " (custom firmware)" : ""}`,
  },
  client_wrong_password: {
    label: "Wrong password?",
    tone: "warn",
    describe: (d) =>
      `failed the Wi-Fi handshake: the password it used is probably wrong${d.vap ? ` · ${d.vap}` : ""}`,
  },
  client_steered: {
    label: "Client steering",
    tone: "info",
    describe: (d) =>
      parts(
        `asked to move (802.11v)${d.signal != null ? ` at ${dbm(d.signal)}` : ""}`,
        d.result,
        (d.candidates ?? []).length > 0 &&
          `offered ${(d.candidates ?? []).map((c) => `${c.bssid}${c.channel ? ` ch ${c.channel}` : ""}`).join(", ")}`,
      ),
  },
  client_experience: {
    label: "Poor experience",
    tone: "warn",
    describe: (d) =>
      parts(
        (d.anomalies ?? []).map((a) => a.replace(/_/g, " ")).join(", "),
        d.satisfaction != null && `experience ${d.satisfaction}`,
        d.signal != null && `signal ${dbm(d.signal)}`,
      ),
  },
  ap_crash: {
    label: "AP crash",
    tone: "bad",
    describe: (d) =>
      parts(d.process ? `${d.process}: ${d.kind}` : d.kind, crashLine(d.lines)),
  },
  ap_process_restarted: {
    label: "Process restarted",
    tone: "warn",
    describe: (d) => {
      // As the alert says it: a code sent as text is still a code, and a
      // missing one is left out.
      const c: unknown = d.exit_status;
      const code =
        typeof c === "number"
          ? String(c)
          : typeof c === "string" && /^[+-]?\d+$/.test(c.trim())
            ? c.trim()
            : null;
      return `${d.proc ?? "a process"} exited${code !== null ? ` with code ${code}` : ""} and was restarted by ${d.caller ?? "the system"}`;
    },
  },
  ap_isolated: {
    label: "AP isolated",
    tone: "bad",
    describe: (d, names) =>
      `its beacon says it lost its uplink${d.heard_by ? ` (heard by ${names[d.heard_by] ?? d.heard_by})` : ""}`,
  },
  ap_scan_done: { label: "Scan finished", tone: "neutral" },
  ap_event: { label: "AP event", tone: "neutral" },
  radio_changed: {
    label: "Radio settings changed",
    tone: "neutral",
    describe: (d) =>
      `${band(d.radio)}: ${radioLevels(d.from)} → ${radioLevels(d.to)}`,
  },
  config_pushed: {
    label: "Config pushed",
    tone: "neutral",
    describe: (d) => {
      const s = d.system_cfg;
      if (!s) return "";
      return s.baseline
        ? `baseline captured (${s.lines} lines)`
        : `${s.added} added, ${s.removed} removed, ${s.changed} changed`;
    },
  },
  client_connected: {
    label: "Client connected",
    tone: "info",
    describe: (d) =>
      parts(
        d.essid,
        `${band(d.radio)} channel ${d.channel ?? "?"}`,
        d.signal !== undefined && d.signal !== null && dbm(d.signal),
        d.new && "first time seen",
      ),
  },
  client_disconnected: {
    label: "Client disconnected",
    tone: "warn",
    describe: (d) =>
      `${d.reason === "ap_offline" ? "AP went offline" : d.reason === "ap_forgotten" ? "its AP was forgotten" : "no longer seen"}${d.connected_for ? ` after ${duration(d.connected_for)}` : ""}${d.last_signal ? `, last ${dbm(d.last_signal)}` : ""}`,
  },
  client_roamed: {
    label: "Client roamed",
    tone: "info",
    describe: (d, names) =>
      `from ${names[d.from?.ap ?? ""] ?? "?"} (${band(d.from?.radio)}, ${dbm(d.from?.signal)}) to ${names[d.to?.ap ?? ""] ?? "?"} (${band(d.to?.radio)}, ${dbm(d.to?.signal)})`,
  },
  client_renamed: {
    label: "Client renamed",
    tone: "info",
    describe: (d) =>
      d.to
        ? `${d.from ? `"${d.from}" → ` : ""}"${d.to}"`
        : `alias "${d.from}" removed`,
  },
  dryrun_compared: {
    label: "Dry run",
    tone: "neutral",
    describe: (d) => {
      if (d.error) return `generator error: ${d.error}`;
      return d.matches
        ? "apctl would have pushed the identical config"
        : `differs: ${d.system_cfg?.added ?? 0} extra, ${d.system_cfg?.removed ?? 0} missing, ${d.system_cfg?.changed ?? 0} different lines`;
    },
  },
  settings_imported: {
    label: "Settings imported",
    tone: "neutral",
    describe: (d) =>
      `${(d.wlans ?? []).length} SSIDs, ${(d.networks ?? []).length} networks`,
  },
  settings_changed: {
    label: "Settings changed",
    tone: "neutral",
    describe: (d) => String(d.what ?? ""),
  },
  channel_plan: {
    label: "Channel AI",
    tone: "neutral",
    describe: (d, names) => {
      const moves = d.changes ?? [];
      const what = [d.band && band(d.band), d.trigger && `(${d.trigger})`];
      return `${what.filter(Boolean).join(" ") || "Plan"}: ${
        moves.length === 0
          ? "nothing to move"
          : moves
              .map(
                (m) =>
                  `${m.name ?? names[m.mac] ?? m.mac} ${m.from ?? "?"} → ${m.to ?? "?"}`,
              )
              .join(", ")
      }${moves.length > 0 && !d.applied ? " (not applied)" : ""}`;
    },
  },
  ap_pending: { label: "AP waiting for adoption", tone: "neutral" },
  ap_adopting: { label: "Adopting AP", tone: "neutral" },
  ap_adopted: { label: "AP adopted", tone: "neutral" },
  ap_forgotten: { label: "AP forgotten", tone: "neutral" },
  ap_host_key_mismatch: { label: "SSH host key changed", tone: "neutral" },
  ap_restart_requested: { label: "Restart requested", tone: "neutral" },
  ap_provision_requested: {
    label: "Config re-send requested",
    tone: "neutral",
  },
  client_reconnect_requested: { label: "Reconnect requested", tone: "info" },
  client_blocked: { label: "Client blocked", tone: "warn" },
  client_unblocked: { label: "Client unblocked", tone: "info" },
};

/** An event's label and detail line, as the event lists show them. */
export function eventText(
  e: AppEvent,
  names: Names,
): { label: string; detail: string } {
  const spec = eventSpec(e.kind);
  return {
    label: spec.label,
    detail: spec.describe?.(eventData(e), names, e.ts) ?? "",
  };
}

/** The kind's entry, or a plain one for kinds this UI doesn't know yet. */
function eventSpec(kind: string): EventSpec<EventKind> {
  return (
    (EVENTS as Record<string, EventSpec<EventKind>>)[kind] ?? {
      label: kind,
      tone: kind.startsWith("client") ? "info" : "neutral",
    }
  );
}

/**
 * A memoised row's comparator. Rows never change, so one re-renders only for
 * other props or another day, not for every minute the list's clock ticks.
 * The row's data is compared by identity, not by id: ids start again after a
 * restore, and React Query keeps an unchanged row's object.
 */
export const sameRow = <P extends { now: number }>(a: P, b: P) =>
  sameDay(a.now, b.now) &&
  Object.keys(a).length === Object.keys(b).length &&
  (Object.keys(a) as (keyof P)[]).every(
    (k) => k === "now" || Object.is(a[k], b[k]),
  );

/** React keys for table rows, from what identifies each row; numbered when two rows share one. */
export function stableKeys<T>(rows: T[], id: (row: T) => string): string[] {
  const seen = new Map<string, number>();
  return rows.map((row) => {
    const k = id(row);
    const n = seen.get(k) ?? 0;
    seen.set(k, n + 1);
    return n ? `${k}#${n}` : k;
  });
}

interface EventRowProps {
  e: AppEvent;
  names: Names;
  clientNames?: Names;
  showDevice: boolean;
  /** `useNow()`: only its date matters. */
  now: number;
}

/** One event. Events never change, so it re-renders only for another event, other names or another day. */
const EventRow = memo(
  function EventRow({
    e,
    names,
    clientNames,
    showDevice,
    now,
  }: EventRowProps) {
    const spec = eventSpec(e.kind);
    const d = eventData(e);
    const tone = typeof spec.tone === "function" ? spec.tone(d) : spec.tone;
    const detail = spec.describe?.(d, names, e.ts);
    const threat = eventData<"network_threat">(e);
    const diff = eventData<"config_pushed">(e).system_cfg?.diff;
    const crash =
      e.kind === "ap_crash" ? (eventData<"ap_crash">(e).lines ?? []) : [];
    return (
      <li className={`event event-${tone}`}>
        <span className="event-time">{clock(e.ts, now)}</span>
        <span className="event-kind">{spec.label}</span>
        <span className="event-what">
          <span className="event-subject">
            {e.kind === "network_threat" && (
              <>
                {threat.essid ? `"${threat.essid}"` : "Hidden network"}
                <span className="muted"> heard by </span>
              </>
            )}
            {e.client_mac && (
              <Link
                to={`/clients/${e.client_mac}`}
                className={clientNames?.[e.client_mac] ? "" : "mono"}
              >
                {clientNames?.[e.client_mac] ?? e.client_mac}
              </Link>
            )}
            {showDevice &&
              e.device_mac &&
              e.kind !== "client_roamed" && (
                <>
                  {e.client_mac && <span className="muted"> on </span>}
                  <DeviceLink mac={e.device_mac} names={names} />
                </>
              )}
          </span>
          {detail ? <span className="event-detail">{detail}</span> : null}
          {e.kind === "config_pushed" && typeof diff === "string" && diff && (
            <details>
              <summary>diff</summary>
              <pre className="diff">{diff}</pre>
            </details>
          )}
          {crash.length > 1 && (
            <details>
              <summary>crash log ({crash.length} lines)</summary>
              <pre className="diff">{crash.join("\n")}</pre>
            </details>
          )}
        </span>
      </li>
    );
  },
  sameRow,
);

export function EventList({
  events,
  names,
  clientNames,
  showDevice,
}: {
  events: AppEvent[];
  names: Names;
  clientNames?: Names;
  showDevice?: boolean;
}) {
  const now = useNow();
  if (events.length === 0)
    return <div className="muted pad">No events yet</div>;
  return (
    <ul className="events">
      {events.map((e) => (
        <EventRow
          key={e.id}
          e={e}
          names={names}
          clientNames={clientNames}
          showDevice={showDevice !== false}
          now={now}
        />
      ))}
    </ul>
  );
}

const SEVERITY = [
  "emerg",
  "alert",
  "crit",
  "error",
  "warn",
  "notice",
  "info",
  "debug",
];

interface LogRowProps {
  l: LogLine;
  names: Names;
  showDevice: boolean;
  /** `useNow()`: only its date matters. */
  now: number;
}

/** One log line. Lines never change, so it re-renders only for another line, other names or another day. */
const LogRow = memo(
  function LogRow({ l, names, showDevice, now }: LogRowProps) {
    return (
      <div className={`log-line sev-${l.severity ?? 6}`}>
        <span className="log-time">{clock(l.ts, now)}</span>
        {showDevice && (
          <span className="log-device">
            <DeviceLink mac={l.device_mac} names={names} />
          </span>
        )}
        <span className="log-sev">
          {l.severity !== null ? SEVERITY[l.severity] : ""}
        </span>
        <span className="log-prog">{l.program ?? ""}</span>
        <span className="log-msg">{l.msg}</span>
      </div>
    );
  },
  sameRow,
);

export function LogList({
  logs,
  names,
  showDevice,
}: {
  logs: LogLine[];
  names: Names;
  showDevice?: boolean;
}) {
  const now = useNow();
  if (logs.length === 0) return <div className="muted pad">No log lines</div>;
  return (
    <div className={showDevice !== false ? "logs" : "logs logs-no-device"}>
      {logs.map((l) => (
        <LogRow
          key={l.id}
          l={l}
          names={names}
          showDevice={showDevice !== false}
          now={now}
        />
      ))}
    </div>
  );
}
