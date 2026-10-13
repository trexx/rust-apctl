import { Link } from "react-router-dom";
import { displayName } from "../api";
import type { AppEvent, ClientView, DeviceSummary, LogLine } from "../api";
import { band, clock, duration, signalClass } from "../format";

export function Stat({
  label,
  value,
  sub,
}: {
  label: string;
  value: React.ReactNode;
  sub?: React.ReactNode;
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

export function ErrorNote({ error }: { error: unknown }) {
  return (
    <div className="error pad">
      {error instanceof Error ? error.message : String(error)}
    </div>
  );
}

/** Names devices by MAC for event and log rows. */
export type DeviceNames = Map<string, string>;

/** Client display names (alias, else hostname) by MAC, for event rows. */
export function clientNames(
  clients: ClientView[] | undefined,
): Map<string, string> {
  return new Map(
    (clients ?? [])
      .filter((c) => c.alias || c.sample.hostname)
      .map((c) => [c.sample.mac, displayName(c)]),
  );
}

export function deviceNames(devices: DeviceSummary[] | undefined): DeviceNames {
  return new Map((devices ?? []).map((d) => [d.mac, d.name ?? d.mac]));
}

export function DeviceLink({
  mac,
  names,
}: {
  mac: string | null;
  names: DeviceNames;
}) {
  if (!mac) return <span className="muted">—</span>;
  return <Link to={`/devices/${mac}`}>{names.get(mac) ?? mac}</Link>;
}

const EVENT_LABELS: Record<string, string> = {
  ap_seen: "AP discovered",
  ap_online: "AP back online",
  ap_offline: "AP offline",
  ap_restarted: "AP restarted",
  ap_firmware_changed: "Firmware changed",
  // Older events (before 0.3.2) guessed a restart; it was a config being applied.
  ap_radios_restarting: "Applying configuration",
  ap_config_applied: "Configuration applied",
  config_applied: "Config applied",
  client_connect_failed: "Connection failed",
  dfs_radar: "Radar detected (DFS)",
  rogue_ap: "Rogue AP (reported by AP)",
  network_threat: "Suspicious network",
  client_kicked: "Client kicked",
  client_wrong_password: "Wrong password?",
  client_steered: "Client steering",
  client_experience: "Poor experience",
  ap_crash: "AP crash",
  ap_process_restarted: "Process restarted",
  ap_isolated: "AP isolated",
  ap_scan_done: "Scan finished",
  ap_event: "AP event",
  radio_changed: "Radio settings changed",
  config_pushed: "Config pushed",
  client_connected: "Client connected",
  client_disconnected: "Client disconnected",
  client_roamed: "Client roamed",
  client_renamed: "Client renamed",
  dryrun_compared: "Dry run",
  settings_imported: "Settings imported",
};

function eventTone(kind: string, d?: Record<string, unknown>): string {
  if (kind === "ap_offline" || kind === "ap_restarted") return "bad";
  if (
    kind === "client_disconnected" ||
    kind === "client_connect_failed" ||
    kind === "dfs_radar"
  )
    return "warn";
  if (kind === "rogue_ap" || kind === "ap_crash" || kind === "ap_isolated")
    return "bad";
  if (
    kind === "client_kicked" ||
    kind === "client_experience" ||
    kind === "ap_process_restarted" ||
    kind === "client_wrong_password"
  )
    return "warn";
  if (kind === "network_threat")
    return d?.severity === "low"
      ? "info"
      : d?.severity === "medium"
        ? "warn"
        : "bad";
  if (kind.startsWith("client")) return "info";
  return "neutral";
}

function describe(e: AppEvent, names: DeviceNames): React.ReactNode {
  const d = (e.data ?? {}) as Record<string, any>;
  switch (e.kind) {
    case "client_connected":
      return [
        d.essid,
        `${band(d.radio)} channel ${d.channel ?? "?"}`,
        d.signal !== undefined && d.signal !== null ? `${d.signal} dBm` : null,
        d.new ? "first time seen" : null,
      ]
        .filter(Boolean)
        .join(" · ");
    case "client_disconnected":
      return `${d.reason === "ap_offline" ? "AP went offline" : "no longer seen"}${d.connected_for ? ` after ${duration(d.connected_for)}` : ""}${d.last_signal ? `, last ${d.last_signal} dBm` : ""}`;
    case "client_roamed":
      return `from ${names.get(d.from?.ap) ?? "?"} (${band(d.from?.radio)}, ${d.from?.signal ?? "?"} dBm) to ${names.get(d.to?.ap) ?? "?"} (${band(d.to?.radio)}, ${d.to?.signal ?? "?"} dBm)`;
    case "radio_changed":
      return `${band(d.radio)}: ch ${d.from?.channel}/${d.from?.bw} MHz/${d.from?.tx_power} dBm → ch ${d.to?.channel}/${d.to?.bw} MHz/${d.to?.tx_power} dBm`;
    case "config_pushed": {
      const s = d.system_cfg;
      if (!s) return "";
      return s.baseline
        ? `baseline captured (${s.lines} lines)`
        : `${s.added} added, ${s.removed} removed, ${s.changed} changed`;
    }
    case "config_applied":
      return d.seconds_after_push !== null && d.seconds_after_push !== undefined
        ? `${d.seconds_after_push}s after the push`
        : "";
    case "client_connect_failed":
      return [
        d.essid,
        d.reason ? `reason: ${d.reason}` : null,
        d.rssi ? `${d.rssi} dBm` : null,
      ]
        .filter(Boolean)
        .join(" · ");
    case "dfs_radar":
      return d.channel ? `channel ${d.channel}` : "";
    case "client_wrong_password":
      return `failed the Wi-Fi handshake: the password it used is probably wrong${d.vap ? ` · ${d.vap}` : ""}`;
    case "client_kicked":
      return [
        d.reason ? `reason: ${d.reason}` : null,
        d.signal != null ? `signal ${d.signal} dBm` : null,
        d.vap,
      ]
        .filter(Boolean)
        .join(" · ");
    case "client_steered":
      return [
        `asked to move (802.11v)${d.signal != null ? ` at ${d.signal} dBm` : ""}`,
        d.result,
        (d.candidates ?? []).length
          ? `offered ${(d.candidates as { bssid: string; channel: number | null }[]).map((c) => `${c.bssid}${c.channel ? ` ch ${c.channel}` : ""}`).join(", ")}`
          : null,
      ]
        .filter(Boolean)
        .join(" · ");
    case "client_experience":
      return [
        (d.anomalies ?? []).map((a: string) => a.replace(/_/g, " ")).join(", "),
        d.satisfaction != null ? `experience ${d.satisfaction}` : null,
        d.signal != null ? `signal ${d.signal} dBm` : null,
      ]
        .filter(Boolean)
        .join(" · ");
    case "ap_crash":
      return [
        d.process ? `${d.process}: ${d.kind}` : d.kind,
        (d.lines ?? [])[0],
      ]
        .filter(Boolean)
        .join(" · ");
    case "ap_process_restarted":
      return `${d.proc ?? "a process"} exited with code ${d.exit_status ?? "?"} and was restarted by ${d.caller ?? "the system"}`;
    case "ap_isolated":
      return `its beacon says it lost its uplink${d.heard_by ? ` (heard by ${names.get(d.heard_by) ?? d.heard_by})` : ""}`;
    case "network_threat":
      return d.detail ?? "";
    case "rogue_ap":
      return [
        d.essid,
        d.rogue_channel ? `channel ${d.rogue_channel}` : null,
        d.signal_strength ? `${d.signal_strength} dBm` : null,
      ]
        .filter(Boolean)
        .join(" · ");
    case "ap_config_applied": {
      const secs = `in ${d.seconds}s`;
      if (d.reconnected > 0)
        return `${secs}, ${d.reconnected} of ${d.clients_before} clients had to reconnect`;
      return d.clients_before > 0 ? `${secs}, no clients dropped` : secs;
    }
    case "ap_offline":
      return `last seen ${clock(d.last_seen)}`;
    case "ap_online":
      return d.offline_for ? `after ${duration(d.offline_for)}` : "";
    case "ap_restarted":
      return `uptime ${duration(d.uptime)}`;
    case "ap_seen":
      return [d.model, d.version, d.ip].filter(Boolean).join(" · ");
    case "dryrun_compared":
      if (d.error) return `generator error: ${d.error}`;
      return d.matches
        ? "apctl would have pushed the identical config"
        : `differs: ${d.system_cfg?.added ?? 0} extra, ${d.system_cfg?.removed ?? 0} missing, ${d.system_cfg?.changed ?? 0} different lines`;
    case "settings_imported":
      return `${(d.wlans ?? []).length} SSIDs, ${(d.networks ?? []).length} networks`;
    case "client_renamed":
      return d.to
        ? `${d.from ? `"${d.from}" → ` : ""}"${d.to}"`
        : `alias "${d.from}" removed`;
    case "ap_firmware_changed":
      return `${d.from} → ${d.to}`;
    default:
      return "";
  }
}

export function EventList({
  events,
  names,
  clientNames,
  showDevice = true,
}: {
  events: AppEvent[];
  names: DeviceNames;
  clientNames?: Map<string, string>;
  showDevice?: boolean;
}) {
  if (events.length === 0)
    return <div className="muted pad">No events yet</div>;
  return (
    <ul className="events">
      {events.map((e, i) => (
        <li
          key={`${e.ts}-${e.kind}-${i}`}
          className={`event event-${eventTone(e.kind, e.data as Record<string, unknown>)}`}
        >
          <span className="event-time">{clock(e.ts)}</span>
          <span className="event-kind">{EVENT_LABELS[e.kind] ?? e.kind}</span>
          <span className="event-what">
            <span className="event-subject">
              {e.kind === "network_threat" && (
                <>
                  {(e.data as any)?.essid
                    ? `"${(e.data as any).essid}"`
                    : "Hidden network"}
                  <span className="muted"> heard by </span>
                </>
              )}
              {e.client_mac && (
                <Link
                  to={`/clients/${e.client_mac}`}
                  className={clientNames?.get(e.client_mac) ? "" : "mono"}
                >
                  {clientNames?.get(e.client_mac) ?? e.client_mac}
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
            {(() => {
              const detail = describe(e, names);
              return detail ? (
                <span className="event-detail">{detail}</span>
              ) : null;
            })()}
            {e.kind === "config_pushed" &&
              typeof (e.data as any)?.system_cfg?.diff === "string" &&
              (e.data as any).system_cfg.diff && (
                <details>
                  <summary>diff</summary>
                  <pre className="diff">{(e.data as any).system_cfg.diff}</pre>
                </details>
              )}
          </span>
        </li>
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

export function LogList({
  logs,
  names,
  showDevice = true,
}: {
  logs: LogLine[];
  names: DeviceNames;
  showDevice?: boolean;
}) {
  if (logs.length === 0) return <div className="muted pad">No log lines</div>;
  return (
    <div className={showDevice ? "logs" : "logs logs-no-device"}>
      {logs.map((l, i) => (
        <div key={`${l.ts}-${i}`} className={`log-line sev-${l.severity ?? 6}`}>
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
