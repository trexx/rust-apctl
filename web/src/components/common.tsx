import { useState } from "react";
import type { ReactNode } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import type { QueryKey } from "@tanstack/react-query";
import { eventData, useDevices } from "../api";
import type {
  AppEvent,
  EventKind,
  EventPayloads,
  LogLine,
  Names,
} from "../api";
import { band, clock, duration, signalClass } from "../format";

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

export function Dot({ ok, warn }: { ok: boolean; warn?: boolean }) {
  return (
    <span
      className={`dot ${warn ? "dot-warn" : ok ? "dot-ok" : "dot-bad"}`}
      aria-hidden
    />
  );
}

export function Signal({ dbm }: { dbm: number | null | undefined }) {
  return (
    <span className={`signal signal-${signalClass(dbm)}`}>
      {dbm === null || dbm === undefined ? "—" : `${Math.round(dbm)} dBm`}
    </span>
  );
}

export function Meter({
  value,
  max = 100,
}: {
  value: number | null | undefined;
  max?: number;
}) {
  const v =
    value === null || value === undefined
      ? 0
      : Math.min(100, (value / max) * 100);
  const level = v >= 80 ? "high" : v >= 50 ? "mid" : "low";
  return (
    <span
      className="meter"
      title={
        value === null || value === undefined
          ? "unknown"
          : `${Math.round(value)}`
      }
    >
      <span
        className={`meter-fill meter-${level}`}
        style={{ width: `${v}%` }}
      />
    </span>
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
 * A query's data, or else its error, or else "Loading…". With `panel`, the
 * error and loading states sit in a panel, so the layout doesn't jump when the
 * data (rendered by `children`, usually a panel itself) arrives.
 */
export function QueryState<T>({
  q,
  panel = false,
  children,
}: {
  q: { data: T | undefined; error: unknown };
  panel?: boolean;
  children: (data: T) => ReactNode;
}) {
  if (q.data !== undefined) return <>{children(q.data)}</>;
  const note = q.error ? <ErrorNote error={q.error} /> : <Loading />;
  return panel ? <div className="panel">{note}</div> : note;
}

/** An action's outcome, shown under its buttons. */
export type RunResult = { ok: boolean; text: string } | null;

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
    try {
      const r = await fn();
      const text = typeof r === "string" && r ? r : done;
      if (text) setMsg({ ok: true, text });
    } catch (e) {
      setMsg({ ok: false, text: errorText(e) });
    }
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
  inline = false,
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

export function Tabs<K extends string>({
  tabs,
  value,
  onChange,
}: {
  tabs: readonly (readonly [K, string])[];
  value: K;
  onChange: (k: K) => void;
}) {
  return (
    <div className="segmented" role="tablist">
      {tabs.map(([k, label]) => (
        <button
          key={k}
          role="tab"
          aria-selected={value === k}
          className={value === k ? "active" : ""}
          onClick={() => onChange(k)}
        >
          {label}
        </button>
      ))}
    </div>
  );
}

/** Picks one AP, or "" for all of them. */
export function ApSelect({
  value,
  onChange,
}: {
  value: string;
  onChange: (mac: string) => void;
}) {
  const devices = useDevices();
  return (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value)}
      aria-label="Access point"
    >
      <option value="">All APs</option>
      {(devices.data ?? []).map((d) => (
        <option key={d.mac} value={d.mac}>
          {d.name ?? d.mac}
        </option>
      ))}
    </select>
  );
}

export function DeviceLink({
  mac,
  names,
}: {
  mac: string | null;
  names: Names;
}) {
  if (!mac) return <span className="muted">—</span>;
  return <Link to={`/devices/${mac}`}>{names[mac] ?? mac}</Link>;
}

type Tone = "bad" | "warn" | "info" | "neutral";

interface EventSpec<K extends EventKind> {
  label: string;
  tone: Tone | ((d: Partial<EventPayloads[K]>) => Tone);
  /** The detail line; a method so the table below can hold every kind. */
  describe?(d: Partial<EventPayloads[K]>, names: Names): string;
}

const parts = (...xs: (string | null | undefined | false)[]) =>
  xs.filter(Boolean).join(" · ");

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
    describe: (d) =>
      d.last_seen !== undefined ? `last seen ${clock(d.last_seen)}` : "",
  },
  ap_restarted: {
    label: "AP restarted",
    tone: "bad",
    describe: (d) => `uptime ${duration(d.uptime)}`,
  },
  ap_firmware_changed: {
    label: "Firmware changed",
    tone: "neutral",
    describe: (d) => `${d.from} → ${d.to}`,
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
        !!d.rssi && `${d.rssi} dBm`,
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
        !!d.rogue_channel && `channel ${d.rogue_channel}`,
        !!d.signal_strength && `${d.signal_strength} dBm`,
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
        d.signal != null && `signal ${d.signal} dBm`,
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
      d.step === "downloading"
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
        `asked to move (802.11v)${d.signal != null ? ` at ${d.signal} dBm` : ""}`,
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
        d.signal != null && `signal ${d.signal} dBm`,
      ),
  },
  ap_crash: {
    label: "AP crash",
    tone: "bad",
    describe: (d) =>
      parts(d.process ? `${d.process}: ${d.kind}` : d.kind, (d.lines ?? [])[0]),
  },
  ap_process_restarted: {
    label: "Process restarted",
    tone: "warn",
    describe: (d) =>
      `${d.proc ?? "a process"} exited with code ${d.exit_status ?? "?"} and was restarted by ${d.caller ?? "the system"}`,
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
      `${band(d.radio)}: ch ${d.from?.channel}/${d.from?.bw} MHz/${d.from?.tx_power} dBm → ch ${d.to?.channel}/${d.to?.bw} MHz/${d.to?.tx_power} dBm`,
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
        d.signal !== undefined && d.signal !== null && `${d.signal} dBm`,
        d.new && "first time seen",
      ),
  },
  client_disconnected: {
    label: "Client disconnected",
    tone: "warn",
    describe: (d) =>
      `${d.reason === "ap_offline" ? "AP went offline" : "no longer seen"}${d.connected_for ? ` after ${duration(d.connected_for)}` : ""}${d.last_signal ? `, last ${d.last_signal} dBm` : ""}`,
  },
  client_roamed: {
    label: "Client roamed",
    tone: "info",
    describe: (d, names) =>
      `from ${names[d.from?.ap ?? ""] ?? "?"} (${band(d.from?.radio)}, ${d.from?.signal ?? "?"} dBm) to ${names[d.to?.ap ?? ""] ?? "?"} (${band(d.to?.radio)}, ${d.to?.signal ?? "?"} dBm)`,
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
    describe: (d) => {
      const moves = d.changes ?? [];
      return `${d.band ? band(d.band) : d.band} (${d.trigger}): ${
        moves.length === 0
          ? "nothing to move"
          : moves
              .map((m) => `${m.name ?? m.mac} ${m.from ?? "?"} → ${m.to}`)
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

/** The kind's entry, or a plain one for kinds this UI doesn't know yet. */
function eventSpec(kind: string): EventSpec<EventKind> {
  return (
    (EVENTS as Record<string, EventSpec<EventKind>>)[kind] ?? {
      label: kind,
      tone: kind.startsWith("client") ? "info" : "neutral",
    }
  );
}

export function EventList({
  events,
  names,
  clientNames,
  showDevice = true,
}: {
  events: AppEvent[];
  names: Names;
  clientNames?: Names;
  showDevice?: boolean;
}) {
  if (events.length === 0)
    return <div className="muted pad">No events yet</div>;
  return (
    <ul className="events">
      {events.map((e) => {
        const spec = eventSpec(e.kind);
        const d = eventData(e);
        const tone = typeof spec.tone === "function" ? spec.tone(d) : spec.tone;
        const detail = spec.describe?.(d, names);
        const threat = eventData<"network_threat">(e);
        const diff = eventData<"config_pushed">(e).system_cfg?.diff;
        return (
          <li key={e.id} className={`event event-${tone}`}>
            <span className="event-time">{clock(e.ts)}</span>
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
                  !e.kind.startsWith("client_roamed") && (
                    <>
                      {e.client_mac && <span className="muted"> on </span>}
                      <DeviceLink mac={e.device_mac} names={names} />
                    </>
                  )}
              </span>
              {detail ? <span className="event-detail">{detail}</span> : null}
              {e.kind === "config_pushed" &&
                typeof diff === "string" &&
                diff && (
                  <details>
                    <summary>diff</summary>
                    <pre className="diff">{diff}</pre>
                  </details>
                )}
            </span>
          </li>
        );
      })}
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

export function LogList({
  logs,
  names,
  showDevice = true,
}: {
  logs: LogLine[];
  names: Names;
  showDevice?: boolean;
}) {
  if (logs.length === 0) return <div className="muted pad">No log lines</div>;
  return (
    <div className={showDevice ? "logs" : "logs logs-no-device"}>
      {logs.map((l) => (
        <div key={l.id} className={`log-line sev-${l.severity ?? 6}`}>
          <span className="log-time">{clock(l.ts)}</span>
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
      ))}
    </div>
  );
}
