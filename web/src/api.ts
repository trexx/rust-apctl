import { useEffect } from "react";
import { hashKey, keepPreviousData, useQuery, useQueryClient } from "@tanstack/react-query";
import type { QueryKey } from "@tanstack/react-query";
import { canonicalMac } from "./format";

export type Mac = string;

export interface RadioSummary {
  radio: string;
  channel: number | null;
  bw: number | null;
  tx_power: number | null;
  cu_total: number | null;
  noise_floor: number | null;
  clients: number;
}

export interface DeviceSummary {
  mac: Mac;
  name: string | null;
  model: string | null;
  model_display: string | null;
  version: string | null;
  ip: string | null;
  online: boolean;
  first_seen: number;
  last_seen: number;
  uptime: number | null;
  cpu: number | null;
  mem: number | null;
  load1: number | null;
  satisfaction: number | null;
  clients: number;
  uplink: { speed: number | null; up: boolean | null; full_duplex: boolean | null } | null;
  radios: RadioSummary[];
  last_config_push: number | null;
  locating?: boolean;
  /** Known from the database only: hasn't reported since apctl started. */
  stored_only?: boolean;
}

export interface ClientSample {
  mac: Mac;
  ap_mac: Mac;
  bssid: string;
  essid: string | null;
  radio: string | null;
  channel: number | null;
  hostname: string | null;
  ip: string | null;
  rssi: number | null;
  signal: number | null;
  noise: number | null;
  tx_rate: number | null;
  rx_rate: number | null;
  tx_bytes: number | null;
  rx_bytes: number | null;
  tx_retries: number | null;
  idletime: number | null;
  uptime: number | null;
  satisfaction: number | null;
  anomalies: number | null;
  nss: number | null;
  wifi_gen: string | null;
  vlan_id: number | null;
  latency_avg: number | null;
  is_11r: boolean | null;
  /** Only on a client's own page (`useClient`), not in the list or an AP's page. */
  multicast?: Multicast | null;
}

/** `tx` is what the AP delivered to the client, `rx` what the client sent. */
export interface McastCounts {
  tx_pkts: number;
  tx_bytes: number;
  rx_pkts: number;
  rx_bytes: number;
}

/** Traffic to or from one multicast service (mDNS, SSDP, …). */
export interface ServiceCount {
  name: string;
  pkts: number;
  bytes: number;
}

export interface Multicast {
  types: Record<string, McastCounts>;
  groups: (McastCounts & { group_ip: string; dst_port: number | null; type: string | null })[];
  memberships: string[];
  services: ServiceCount[];
}

/** A client as an AP's page lists it: its latest sample (without the multicast tables), and when it was seen. */
export interface ListedClientView {
  sample: ClientSample;
  connected: boolean;
  first_seen: number;
  last_seen: number;
}

/** A client with its name, manufacturer and controls, as the client list and its own page send it. */
export interface ClientView extends ListedClientView {
  vendor: string | null;
  alias: string | null;
  note: string | null;
  /** From the settings: blocked from every SSID. */
  blocked: boolean;
  /** From the settings: the only AP the client may connect to. */
  locked_to: Mac | null;
  /** From the settings: the client's own speed limit (user group). */
  usergroup_id: string | null;
}

/** A client in the client list: its view, and the name of the AP it is on (null when that AP has no name, or is not reporting). */
export interface ListedClient extends ClientView {
  ap_name: string | null;
}

/** A client in a multicast group, as a client's page lists its peers. */
export type GroupMember = { mac: Mac; name: string };

/** A client's page: its view, with the multicast tables and the peers in its groups. */
export interface ClientDetail extends ClientView {
  /** For each group it joined, the other connected clients that joined it too (groups without any are left out). */
  peers: Record<string, GroupMember[]>;
}

/** The name to show for a client: the user's alias, else its hostname, else its MAC. */
export const displayName = (c: ClientView) => c.alias || c.sample.hostname || c.sample.mac;

export interface VapSample {
  bssid: string;
  essid: string | null;
  radio: string | null;
  name: string | null;
  channel: number | null;
  num_sta: number | null;
  ccq: number | null;
  satisfaction: number | null;
  avg_client_signal: number | null;
  latency_avg: number | null;
  /** Counters since the AP started. */
  rx_bytes: number | null;
  tx_bytes: number | null;
  rx_packets: number | null;
  tx_packets: number | null;
  tx_retries: number | null;
  tx_dropped: number | null;
  tx_mcast: number | null;
  rx_mcast: number | null;
  tx_bcast: number | null;
  rx_bcast: number | null;
  rx_dropped: number | null;
  tx_errors: number | null;
  wifi_tx_attempts: number | null;
  wifi_tx_dropped: number | null;
}

export interface RadioSample {
  radio: string;
  name: string | null;
  channel: number | null;
  bw: number | null;
  tx_power: number | null;
  cu_total: number | null;
  cu_self_rx: number | null;
  cu_self_tx: number | null;
  cu_interf: number | null;
  noise_floor: number | null;
  num_sta: number;
  /** Counters since the AP started. */
  tx_packets: number | null;
  rx_packets: number | null;
  antenna_gain: number | null;
  min_txpower: number | null;
  max_txpower: number | null;
}

export interface DeviceDetail {
  device: {
    snapshot: {
      ap: {
        mac: Mac;
        hostname: string | null;
        model: string | null;
        model_display: string | null;
        version: string | null;
        ip: string | null;
        serial: string | null;
        uptime: number | null;
        cpu: number | null;
        mem: number | null;
        load1: number | null;
        load5: number | null;
        load15: number | null;
        mem_total: number | null;
        mem_used: number | null;
        satisfaction: number | null;
      };
      uplink: {
        ifname: string;
        speed: number | null;
        up: boolean | null;
        full_duplex: boolean | null;
        rx_bytes: number | null;
        tx_bytes: number | null;
        rx_packets: number | null;
        tx_packets: number | null;
      } | null;
      radios: RadioSample[];
      vaps: VapSample[];
      has_vap_table: boolean;
    };
    online: boolean;
    first_seen: number;
    last_seen: number;
    peer: string;
    interval: number;
    last_config_push: number | null;
    /** Known from the database only: hasn't reported since apctl started. */
    stored_only?: boolean;
  };
  /** Its connected clients, without their names (`useClientNames` has them). */
  clients: ListedClientView[];
  locating: boolean;
}

export interface Series {
  tier: "raw" | "5m" | "1h";
  step: number;
  ts: number[];
  fields: Record<string, (number | null)[]>;
}

export interface AppEvent {
  /** The row's id: stable, and newer events have larger ones. */
  id: number;
  ts: number;
  kind: string;
  device_mac: Mac | null;
  client_mac: Mac | null;
  data: Record<string, unknown> | null;
}

/** What a config push records for one config file (system_cfg or mgmt_cfg). */
export interface CfgChange {
  diff?: string;
  /** The first config seen for the AP: nothing to compare with. */
  baseline?: boolean;
  lines?: number;
  added?: number;
  removed?: number;
  changed?: number;
  /** A dry run's: the same key=value pairs, maybe in another order. */
  same_content?: boolean;
}

interface RadioLevels {
  channel?: number | null;
  bw?: number | null;
  tx_power?: number | null;
}

/** One end of a roam as its event records it: the connection log's fields, and the signal. */
type RoamEndData = Partial<Pick<RoamEnd, "ap" | "radio">> & { signal?: number | null };

/** A config push's payload, also the shape of a settings preview's per-AP entry. */
export interface ConfigPushed {
  system_cfg?: CfgChange;
  mgmt_cfg?: CfgChange;
  /** Names for numbered config sections ("wireless.3" → "Home (5 GHz)"). */
  labels?: Record<string, string>;
}

export interface ChannelPlanRun {
  band?: string;
  trigger?: string;
  changes?: { mac: Mac; name?: string | null; from?: number | null; to: number | null }[];
  applied?: boolean;
  error?: string | null;
}

/** Event payloads by kind: the fields the UI reads (all optional; older events may lack some). */
export interface EventPayloads {
  ap_seen: { model?: string | null; version?: string | null; ip?: string | null };
  ap_online: { offline_for?: number | null };
  ap_offline: { last_seen?: number };
  ap_restarted: { uptime?: number | null };
  ap_firmware_changed: { from?: string | null; to?: string | null };
  ap_radios_restarting: object;
  ap_config_applied: { seconds?: number; reconnected?: number; clients_before?: number };
  config_applied: { seconds_after_push?: number | null };
  client_connect_failed: { essid?: string | null; reason?: string | null; rssi?: number | null };
  dfs_radar: { channel?: number | null };
  /** The AP's notification as it came; its channel may be text, and the signal's unit isn't documented (probably dBm when negative). */
  rogue_ap: { essid?: string | null; bssid?: string | null; channel?: number | string | null; signal?: number | null };
  network_threat: { essid?: string | null; detail?: string; severity?: "high" | "medium" | "low" };
  client_kicked: { reason?: string | null; signal?: number | null; vap?: string | null };
  ap_upgrade_sent: { target?: string | null };
  ap_upgrade_started: { by?: string | null };
  ap_upgrade_progress: { step?: "preparing" | "downloading" | "writing" | null };
  ap_upgrade_failed: { detail?: string | null; reason?: string | null };
  ap_upgraded: { from?: string | null; to?: string | null; custom?: boolean };
  client_wrong_password: { vap?: string | null };
  client_steered: { signal?: number | null; result?: string | null; candidates?: { bssid: string; channel: number | null }[] };
  client_experience: { anomalies?: string[]; satisfaction?: number | null; signal?: number | null };
  /** `lines`: from the fault on (`source` "syslog"), or the last 200 lines of the AP's crash store ("crashlog", "recovery"). */
  ap_crash: { process?: string | null; kind?: string | null; source?: string; lines?: string[] };
  ap_process_restarted: { proc?: string | null; exit_status?: number | null; caller?: string | null };
  ap_isolated: { heard_by?: Mac | null };
  ap_scan_done: object;
  /** Any other AP notification, as it came: `event_string` names it ("EVT_AP_…"). */
  ap_event: { event_string?: string; msg?: string };
  radio_changed: { radio?: string | null; from?: RadioLevels; to?: RadioLevels };
  config_pushed: ConfigPushed;
  client_connected: { essid?: string | null; radio?: string | null; channel?: number | null; signal?: number | null; new?: boolean };
  client_disconnected: { reason?: string | null; connected_for?: number | null; last_signal?: number | null };
  client_roamed: { from?: RoamEndData; to?: RoamEndData };
  client_renamed: { from?: string | null; to?: string | null };
  /** `mgmt_cfg` is missing from comparisons recorded before it was added. */
  dryrun_compared: { error?: string | null; matches?: boolean; system_cfg?: CfgChange; mgmt_cfg?: CfgChange };
  settings_imported: { wlans?: unknown[]; networks?: unknown[] };
  settings_changed: { what?: string };
  channel_plan: ChannelPlanRun;
  ap_pending: object;
  ap_adopting: object;
  ap_adopted: object;
  ap_forgotten: object;
  ap_host_key_mismatch: object;
  ap_restart_requested: object;
  ap_provision_requested: object;
  client_reconnect_requested: object;
  client_blocked: object;
  client_unblocked: object;
}

export type EventKind = keyof EventPayloads;

/** An event's payload as its kind's type: `eventData<"config_pushed">(e)`. */
export const eventData = <K extends EventKind>(e: AppEvent) => (e.data ?? {}) as Partial<EventPayloads[K]>;

export interface LogLine {
  id: number;
  ts: number;
  device_mac: Mac | null;
  src_ip: string | null;
  facility: number | null;
  severity: number | null;
  program: string | null;
  msg: string;
}

export interface Status {
  version: string;
  /** Active: apctl manages the APs; shadow: it watches another controller's traffic. */
  mode: "active" | "shadow";
  source: string;
  started: number;
  now: number;
  devices: number;
  devices_online: number;
  clients_connected: number;
  /** Connected clients by radio ("ng", "na", …). */
  clients_by_band: Record<string, number>;
  /** Connected clients with a signal below -75 dBm. */
  clients_weak: number;
  counters: Record<string, number>;
}

/** Raised for 401s; the app shell then shows the login page. */
export class AuthError extends Error {}

/** A failed request, with the server's message and the HTTP status. */
export class HttpError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

/** Tells the app shell the session is gone: it checks /api/me, and shows the login page. */
const announceUnauthorized = () => window.dispatchEvent(new Event("apctl:unauthorized"));

function unauthorized(): never {
  announceUnauthorized();
  throw new AuthError("login required");
}

/** Throws for a failed response: AuthError for a 401 (unless the caller handles those), else HttpError with the server's message. */
async function check(res: Response, handles401 = false): Promise<Response> {
  if (res.status === 401 && !handles401) unauthorized();
  if (!res.ok) {
    let msg = `${res.status} ${res.statusText}`;
    try {
      msg = (await res.json()).error ?? msg;
    } catch {
      /* not JSON */
    }
    throw new HttpError(res.status, msg);
  }
  return res;
}

/** Sends a JSON request. With `handles401`, a 401 is the caller's HttpError (a failed login) rather than a lost session. */
async function send<T>(method: string, path: string, body: unknown, { handles401 = false } = {}): Promise<T> {
  const res = await fetch(path, {
    method,
    // The server requires this header on writes (CSRF protection).
    headers: { "Content-Type": "application/json", "X-Requested-With": "apctl" },
    body: JSON.stringify(body),
  });
  return (await check(res, handles401)).json() as Promise<T>;
}

export const setAlias = (mac: Mac, alias: string, note: string) =>
  send<{ ok: boolean }>("PUT", `/api/clients/${mac}/alias`, { alias, note });

// Device and client actions (active mode only): each goes to the AP with its next report.
export const restartAp = (mac: Mac) => send("POST", `/api/devices/${mac}/restart`, {});
export const locateAp = (mac: Mac, on: boolean) => send("POST", `/api/devices/${mac}/locate`, { on });
export const provisionAp = (mac: Mac) => send("POST", `/api/devices/${mac}/provision`, {});
export const kickClient = (mac: Mac) => send("POST", `/api/clients/${mac}/kick`, {});
export const blockClient = (mac: Mac, blocked: boolean) => send("POST", `/api/clients/${mac}/block`, { blocked });
export const lockClient = (mac: Mac, ap: Mac | null) => send("POST", `/api/clients/${mac}/lock`, { ap });

/** GETs JSON; `signal` (React Query's) cancels it when nothing needs the answer any more. */
async function get<T>(path: string, signal?: AbortSignal): Promise<T> {
  return (await check(await fetch(path, { signal }))).json() as Promise<T>;
}

/** A query function that GETs `path`. */
const getting = <T>(path: string) => ({ signal }: { signal: AbortSignal }) => get<T>(path, signal);

function qs(params: Record<string, string | number | undefined | null>): string {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== "") p.set(k, String(v));
  }
  const s = p.toString();
  return s ? `?${s}` : "";
}

/** A family of query keys: `f()` is the prefix that matches all of them (for invalidation), `f(a, b)` one query. */
const family = <A extends unknown[] = []>(root: string) => (...args: Partial<A>): QueryKey => [root, ...args];

/**
 * Every query key, used by the hooks below and by everything that invalidates
 * them, so the two can't drift apart.
 */
export const keys = {
  me: family("me"),
  status: family("status"),
  devices: family("devices"),
  deviceNames: family("device-names"),
  device: family<[mac: Mac]>("device"),
  clients: family("clients"),
  clientNames: family("client-names"),
  client: family<[mac: Mac]>("client"),
  series: family<[table: string, key: string, span: TimeSpan, fields: string]>("series"),
  events: family<[filter: EventFilter]>("events"),
  logs: family<[filter: LogFilter]>("logs"),
  alerts: family("alerts"),
  settingsState: family("settings-state"),
  dryrun: family("dryrun"),
  threats: family("threats"),
  siteActivity: family<[span: TimeSpan, band: string, mac: Mac | undefined]>("site-activity"),
  siteTop: family<[span: TimeSpan, mac: Mac | undefined]>("site-top"),
  connectivity: family<[span: TimeSpan]>("connectivity"),
  retries: family<[span: TimeSpan]>("retries"),
  density: family<[span: TimeSpan]>("density"),
  connections: family<[span: TimeSpan, opts: object]>("connections"),
  roaming: family<[span: TimeSpan]>("roaming"),
  wlans: family<[span: TimeSpan]>("wlans"),
  multicast: family<[span: TimeSpan, mac: Mac | undefined]>("multicast"),
  backups: family("backups"),
  firmware: family("firmware"),
  rfRadios: family<[range: number]>("rf-radios"),
  rfNeighbors: family<[range: number, band: string]>("rf-neighbors"),
  rfLinks: family<[range: number]>("rf-links"),
  rfPlan: family<[band: string, dfs: boolean]>("rf-plan"),
  channelAi: family("channel-ai"),
  adoption: family("adoption"),
  /** The settings editor's data: `settings("site")`, `settings("device", mac)`, … */
  settings: family<[what: "site" | "wlans" | "device" | "usergroups", mac: Mac]>("settings"),
  settingsPreview: family<[target: SettingsTarget, patch: unknown]>("settings-preview"),
};

export interface Me {
  auth: boolean;
  user: string | null;
  /** Changes are refused: no users are configured. */
  read_only: boolean;
}

/** What /api/me says while nobody is signed in (it answers 401). */
export const SIGNED_OUT: Me = { auth: true, user: null, read_only: true };

/** The logged-in user. `user` is null when a login is required. */
export const useMe = () =>
  useQuery({
    queryKey: keys.me(),
    queryFn: async ({ signal }): Promise<Me> => {
      const res = await fetch("/api/me", { signal });
      if (res.status === 401) return SIGNED_OUT;
      return (await check(res, true)).json() as Promise<Me>;
    },
    staleTime: 60_000,
  });

/** Whether this user may change things: false until /api/me has answered. */
export const useCanEdit = () => useMe().data?.read_only === false;

export const login = (username: string, password: string) => send<{ user: string }>("POST", "/api/login", { username, password }, { handles401: true });
export const logout = () => send<{ ok: boolean }>("POST", "/api/logout", {});

export interface StateSummary {
  imported_at: number | null;
  summary: { sites: number; wlans: string[]; networks: string[]; ap_groups: string[]; devices: number; clients: number; settings: number } | null;
}

export const useSettingsState = () => useQuery({ queryKey: keys.settingsState(), queryFn: getting<StateSummary>("/api/settings/state") });

export const importState = (snapshot: unknown) => send<{ ok: boolean }>("POST", "/api/settings/state", snapshot);

export interface FieldComparison {
  expected_lines: number;
  actual_lines: number;
  identical: boolean;
  same_content: boolean;
  equivalent?: boolean;
  added: number;
  removed: number;
  changed: number;
  diff: string;
}

export type StoredComparison = Omit<FieldComparison, "diff">;

export interface DryRun {
  settings_imported_at: number | null;
  devices: {
    mac: Mac;
    name: string | null;
    status: "match" | "equivalent" | "differs" | "error" | "no_settings" | "no_config_seen";
    comparison?: { mgmt_cfg: FieldComparison; system_cfg: FieldComparison };
    against_redacted?: boolean;
    error?: string;
    /** The AP runs a different config version than when the settings were imported. */
    settings_stale: boolean;
  }[];
  /** The comparison made at each push, stored without the diffs. */
  history: { id: number; ts: number; mac: Mac; cfgversion: string | null; matches: boolean; comparison: { mgmt_cfg?: StoredComparison; system_cfg?: StoredComparison; error?: string } | null }[];
}

/** Refreshed by the live socket when a comparison is recorded or settings are imported. */
export const useDryRun = () => useQuery({ queryKey: keys.dryrun(), queryFn: getting<DryRun>("/api/dryrun") });

export interface SiteActivity {
  bucket: number;
  activity: {
    ts: number[];
    download_bps: number[];
    upload_bps: number[];
    tx_retry_pct: (number | null)[];
    clients: number[];
    multicast_pct: (number | null)[];
    tx_pps: number[];
    rx_pps: number[];
    tx_dropped_pct: (number | null)[];
  };
  /** Null in a bucket where no radio reported the figure. */
  airtime: { ts: number[]; total: (number | null)[]; external_interference: (number | null)[]; own_traffic: (number | null)[]; own_rx: (number | null)[]; own_tx: (number | null)[] };
}

export interface TopEntry {
  mac: Mac;
  name: string | null;
  vendor?: string | null;
  connected?: boolean;
  download_bytes: number;
  upload_bytes: number;
}

export interface Connectivity {
  attempts: number;
  clients: number;
  failed_clients: number;
  association_pct: number | null;
  authentication_pct: number | null;
  dhcp_pct: number | null;
  dns_pct: number | null;
  success_pct: number | null;
  failed_at: Record<string, number>;
  /** Average milliseconds per stage, over the attempts that have it. */
  latency_ms: Timings;
}

export interface RadioRetries {
  mac: Mac;
  name: string | null;
  radio: string;
  tx_retry_pct: number;
  retries: number;
  attempts: number;
  dropped: number;
}

export interface DensityAp {
  mac: Mac;
  name: string | null;
  bands: { band: string; weakest_signal: number; signal_avg: number; clients: number; traffic_pct: number; tx_retry_pct: number | null }[];
}

export interface SiteMulticast {
  bucket: number;
  ts: number[];
  types: Record<string, { tx_pps: number[]; rx_pps: number[]; tx_pkts: number; rx_pkts: number; tx_bytes: number; rx_bytes: number }>;
  clients: {
    mac: Mac;
    name: string | null;
    vendor: string | null;
    connected: boolean;
    ap: string | null;
    radio: string | null;
    tx_pkts: number;
    rx_pkts: number;
    tx_bytes: number;
    rx_bytes: number;
    services: ServiceCount[];
    delivery: "optimized" | "flooding" | null;
    memberships: number;
  }[];
}

export interface RadioOverview {
  mac: Mac;
  name: string | null;
  radio: string;
  channel: number | null;
  bw: number | null;
  tx_power: number | null;
  eirp: number | null;
  clients: number;
  noise_floor: number | null;
  avg_utilization: number | null;
  avg_interference: number | null;
  tx_retry_pct: number | null;
  usage_bytes: number;
  avg_client_signal: number | null;
}

export interface Neighbor {
  bssid: string;
  ap_mac: Mac;
  radio: string | null;
  essid: string | null;
  channel: number | null;
  bw: number | null;
  center_freq: number | null;
  security: string | null;
  signal: number | null;
  best_signal: number | null;
  is_unifi: boolean;
  ap_name: string | null;
  last_seen: number;
  first_seen: number;
  vendor: string | null;
  nearest_ap: string | null;
}

export interface OwnLink {
  from: Mac;
  from_name: string | null;
  to: Mac;
  to_name: string | null;
  radio: string | null;
  signal: number | null;
}

export interface PlanEntry {
  mac: Mac;
  name: string | null;
  width: number;
  clients: number;
  current_channel: number;
  current_score: number;
  current_reasons: string[];
  suggested_channel: number;
  suggested_score: number;
  suggested_reasons: string[];
  change: boolean;
  /** Kept as is: excluded, on a wireless uplink, or being upgraded. */
  pinned: boolean;
  /** Its channel is not one Channel AI may use, so it moves regardless. */
  not_allowed: boolean;
}

export interface ThreatFinding {
  kind: "spoofed_bssid" | "impersonation" | "lookalike" | "bridged" | "new_nearby";
  severity: "high" | "medium" | "low";
  bssid: string;
  essid: string | null;
  security: string | null;
  channel: number | null;
  radio: string | null;
  best_signal: number | null;
  heard_by: { mac: Mac; name: string | null; signal: number | null; last_seen: number }[];
  first_seen: number;
  last_seen: number;
  target: string | null;
  detail: string;
  first_reported: number | null;
  acknowledged: { note: string | null; ts: number } | null;
  vendor: string | null;
}

/** A new finding is announced (as a network_threat event); the slow poll catches the ones that go away. */
export const useThreats = () =>
  useQuery({
    queryKey: keys.threats(),
    queryFn: getting<{ watching_since: number; findings: ThreatFinding[] }>("/api/rf/threats"),
    refetchInterval: 300_000,
  });

export const ackThreat = (kind: string, bssid: string, ack: boolean, note?: string) => send("PUT", "/api/rf/threats/ack", { kind, bssid, ack, note });

const bandParam = (band: string) => (band === "all" ? undefined : band);

/** A chart time range: the last N seconds (follows the clock), or a fixed window. */
export type TimeSpan = { last: number } | { from: number; to: number };

export const isFixed = (s: TimeSpan): s is { from: number; to: number } => "from" in s;

/** [from, to] in Unix seconds, as of now. */
export function spanBounds(s: TimeSpan): [number, number] {
  if (isFixed(s)) return [s.from, s.to];
  const now = Math.floor(Date.now() / 1000);
  return [now - s.last, now];
}

const spanParams = (s: TimeSpan) => (isFixed(s) ? { from: s.from, to: s.to } : { range: s.last });

const spanLength = (s: TimeSpan) => (isFixed(s) ? s.to - s.from : s.last);

/** A fixed window that ended over ten minutes ago: its data no longer changes. */
const settled = (s: TimeSpan) => isFixed(s) && s.to < Date.now() / 1000 - 600;

/** Live ranges refresh; fixed windows in the past don't change. Pass it as `refetchInterval: () => refreshFor(…)`, so it is asked again after
 *  each fetch: a fixed window ending at about now stops refreshing once it is ten minutes past. */
const refreshFor = (s: TimeSpan, live: number) => (settled(s) ? false : live);

/** A settled window's data stays fresh, so a focus or remount doesn't fetch it again; others keep the default staleness. */
const freshFor = (s: TimeSpan) => (settled(s) ? { staleTime: Infinity } : {});

/** Whether two keys of a span family differ in the span alone (the family's first argument, as in every one of `keys`). */
const onlySpanDiffers = (a: QueryKey, b: QueryKey) => hashKey([a[0], ...a.slice(2)]) === hashKey([b[0], ...b.slice(2)]);

/**
 * A query over a time span: refreshes while the span is live, and keeps the old data on screen (`isPlaceholderData`) while
 * another span loads. Another choice (a band, an AP) shows as loading instead, unless `keepAcrossChoices`, for a caller that
 * dims the old data while it shows it. The server keeps a view's answer for a window longer than 8 days for 5 minutes, so such
 * a window is asked again only that often, unless the view is `unmemoised`.
 */
function useSpanQuery<T>(key: QueryKey, path: string, span: TimeSpan, extra: Record<string, string | number | undefined> = {}, opts: { keepAcrossChoices?: boolean; unmemoised?: boolean } = {}) {
  return useQuery<T>({
    queryKey: key,
    queryFn: getting<T>(`${path}${qs({ ...spanParams(span), ...extra })}`),
    refetchInterval: () => refreshFor(span, !opts.unmemoised && spanLength(span) > 8 * 86400 ? 300_000 : 60_000),
    ...freshFor(span),
    placeholderData: (prev, prevQuery) => (prevQuery && (opts.keepAcrossChoices || onlySpanDiffers(prevQuery.queryKey, key)) ? prev : undefined),
  });
}

export const useSiteActivity = (span: TimeSpan, band: string, mac?: Mac) =>
  useSpanQuery<SiteActivity>(keys.siteActivity(span, band, mac), "/api/site/activity", span, { band: bandParam(band), mac });

export const useSiteTop = (span: TimeSpan, mac?: Mac) =>
  useSpanQuery<{ aps: TopEntry[]; clients: TopEntry[] }>(keys.siteTop(span, mac), "/api/site/top", span, { mac });

export const useConnectivity = (span: TimeSpan) => useSpanQuery<{ bands: Record<string, Connectivity> }>(keys.connectivity(span), "/api/site/connectivity", span);

export const useRetries = (span: TimeSpan) => useSpanQuery<RadioRetries[]>(keys.retries(span), "/api/site/retries", span);

export const useDensity = (span: TimeSpan) => useSpanQuery<{ aps: DensityAp[] }>(keys.density(span), "/api/site/density", span);

/** Milliseconds each stage of joining took. */
export interface Timings {
  association: number | null;
  authentication: number | null;
  dhcp: number | null;
  dns: number | null;
  total: number | null;
}

export interface ConnAttempt {
  ts: number;
  client: Mac;
  ap: Mac;
  essid: string | null;
  radio: string | null;
  channel: number | null;
  bw: number | null;
  success: boolean;
  stage: number;
  failure: string | null;
  rssi: number | null;
  timings: Timings;
  roam: boolean;
  fixed_up: boolean;
  reason: string | null;
}

export interface RoamEnd {
  ap: Mac;
  essid: string | null;
  radio: string | null;
  channel: number | null;
  bw: number | null;
  rssi: number | null;
}

export interface Roam {
  ts: number;
  client: Mac;
  from: RoamEnd;
  to: RoamEnd;
  success: boolean;
  gap_s: number | null;
  fast: boolean;
  min_rssi: boolean;
  assistant: boolean;
}

export interface RoamDir {
  attempts: number;
  successes: number;
  fast: number;
  assistant: number;
  min_rssi: number;
}

export interface Roaming {
  from: number;
  to: number;
  /** Over every roam in the window. */
  total: { roams: number; successes: number; fast: number };
  /** The newest roams (the server lists 100). */
  roams: Roam[];
  pairs: {
    ap_1: Mac;
    ap_2: Mac;
    attempts: number;
    successes: number;
    success_pct: number;
    forward: RoamDir;
    backward: RoamDir;
    top_clients: { mac: Mac; roams: number }[];
  }[];
  clients: { mac: Mac; roams: number; failed: number; fast: number; avg_leave_rssi: number | null; to_weaker: number; quick_returns: number }[];
  ap_names: Record<string, string>;
  client_names: Record<string, string>;
}

export interface Wlan {
  essid: string;
  settings: {
    enabled: boolean;
    security: string;
    hidden: boolean;
    guest: boolean;
    network: string | null;
    vlan: string | number | null;
    bands: string[] | null;
    fast_roaming: boolean;
    bss_transition: boolean;
    pmf: string | null;
  } | null;
  security_on_air: string | null;
  broadcast: { ap: Mac; name: string | null; radio: string | null; channel: number | null; bssid: string; clients: number | null; online: boolean }[];
  bands: string[];
  ap_count: number;
  clients: number;
  peak_clients: number;
  satisfaction: number | null;
  satisfaction_avg: number | null;
  signal_avg: number | null;
  download_bytes: number;
  upload_bytes: number;
  tx_retry_pct: number | null;
  multicast_pct: number | null;
  series: { ts: number[]; clients: number[]; download_bps: number[]; upload_bps: number[] };
}

/** What `useConnections` returns. */
export type Connections = { attempts: ConnAttempt[]; roams: Roam[]; ap_names: Record<string, string>; client_names: Record<string, string> };

/**
 * Connection attempts and roams, newest first: at most `limit` of each (the server's default is 500); `roams: false` skips the roams.
 * The old list stays on screen while another `opts` loads too (the attempt list dims it).
 */
export const useConnections = (span: TimeSpan, opts: { client?: Mac; failed?: boolean; limit?: number; roams?: boolean } = {}) =>
  useSpanQuery<Connections>(
    keys.connections(span, opts),
    "/api/connections",
    span,
    { client: opts.client, failed: opts.failed ? "true" : undefined, limit: opts.limit, roams: opts.roams === false ? "false" : undefined },
    { keepAcrossChoices: true, unmemoised: true },
  );

export const useRoaming = (span: TimeSpan) => useSpanQuery<Roaming>(keys.roaming(span), "/api/roaming", span);

export const useWlans = (span: TimeSpan) => useSpanQuery<{ bucket: number; wlans: Wlan[] }>(keys.wlans(span), "/api/wlans", span);

export interface BackupSettings {
  enabled: boolean;
  frequency: "daily" | "weekly" | "monthly";
  minute_utc: number;
  weekday: number;
  monthday: number;
  keep: number;
  days: number;
}

export interface BackupMeta {
  name: string;
  kind: "auto" | "manual" | "pre-restore";
  version: string;
  created: number;
  days: number;
  size: number;
  encrypted: boolean;
}

export interface BackupManifest {
  version: string;
  created: number;
  days: number;
  files: Record<string, { size: number; sha256: string }>;
}

interface Backups {
  encrypted: boolean;
  version: string;
  settings: BackupSettings;
  next_run: number | null;
  backups: BackupMeta[];
  restore_pending: boolean;
  restore_failed: string | null;
}

export const useBackups = () => useQuery({ queryKey: keys.backups(), queryFn: getting<Backups>("/api/backups") });

export const saveBackupSettings = (s: BackupSettings) => send("PUT", "/api/backups/settings", s);
export const createBackup = (days: number) => send<BackupMeta>("POST", "/api/backups", { days });
export const deleteBackup = (name: string) => send("DELETE", `/api/backups/file/${encodeURIComponent(name)}`, {});
export const restoreBackup = (target: { name?: string; staged?: string }) => send<{ ok: boolean }>("POST", "/api/backups/restore", target);

/** Uploads a backup file to be checked and staged (not restored yet). */
export async function uploadBackup(file: File): Promise<{ staged: string; manifest: BackupManifest }> {
  const res = await fetch("/api/backups/upload", {
    method: "POST",
    headers: { "Content-Type": "application/octet-stream", "X-Requested-With": "apctl" },
    body: file,
  });
  return (await check(res)).json();
}

export interface FirmwareRelease {
  platform: string;
  version: string;
  url: string;
  md5: string | null;
  sha256: string | null;
  size: number | null;
  created: string | null;
}

export interface FirmwareJob {
  mac: Mac;
  name: string | null;
  from: string | null;
  target: string;
  custom: boolean;
  /** Queued, sent with an inform reply, then the AP's own steps. */
  state: "queued" | "sent" | "preparing" | "downloading" | "writing";
  sent_at: number | null;
  expires: number | null;
}

export interface FirmwareInfo {
  checked: number | null;
  error: string | null;
  channel: string;
  active: boolean;
  aps: {
    mac: Mac;
    name: string | null;
    model: string | null;
    platform: string | null;
    version: string | null;
    online: boolean;
    release: FirmwareRelease | null;
    status: "update_available" | "up_to_date" | "ahead" | "unknown";
  }[];
  jobs: { current: FirmwareJob | null; queue: FirmwareJob[]; stopped: string | null };
}

/** Polls quickly while an upgrade is under way or queued. */
export const useFirmware = () =>
  useQuery({
    queryKey: keys.firmware(),
    queryFn: getting<FirmwareInfo>("/api/firmware"),
    refetchInterval: (q) => (q.state.data?.jobs.current || q.state.data?.jobs.queue.length ? 5_000 : 60_000),
  });
export const checkFirmware = () => send<{ platforms: number }>("POST", "/api/firmware/check", {});
export const upgradeFirmware = (macs: Mac[]) => send<{ queued: number; skipped: { mac: Mac; why: string }[] }>("POST", "/api/firmware/upgrade", { macs });
export const upgradeFirmwareUrl = (mac: Mac, url: string) => send<{ queued: number }>("POST", "/api/firmware/upgrade-url", { mac, url });
export const cancelFirmware = () => send<{ cancelled: number }>("POST", "/api/firmware/cancel", {});
export const resumeFirmware = () => send<{ resumed: boolean }>("POST", "/api/firmware/resume", {});

export const useMulticast = (span: TimeSpan, mac?: Mac) => useSpanQuery<SiteMulticast>(keys.multicast(span, mac), "/api/site/multicast", span, { mac });

// The RF views cover the last `range` seconds.
export const useRadios = (range: number) => useSpanQuery<RadioOverview[]>(keys.rfRadios(range), "/api/rf/radios", { last: range });

export const useNeighbors = (range: number, band: string) =>
  useSpanQuery<{ neighbors: Neighbor[] }>(keys.rfNeighbors(range, band), "/api/rf/neighbors", { last: range }, { band: bandParam(band), neighbors_only: "true" }, { unmemoised: true });

/** Only how loudly our APs hear each other (no neighbour list). */
export const useOwnLinks = (range: number) => useSpanQuery<{ own_links: OwnLink[] }>(keys.rfLinks(range), "/api/rf/neighbors", { last: range }, { links_only: "true" }, { unmemoised: true });

/** `enabled` false waits, for a caller that doesn't know `dfs` yet. */
export const useChannelPlan = (band: string, dfs: boolean, enabled = true) =>
  useQuery({
    enabled,
    queryKey: keys.rfPlan(band, dfs),
    queryFn: getting<ChannelPlanResult>(`/api/rf/channel-plan${qs({ band, dfs: dfs ? "true" : undefined })}`),
  });

/** The server's status; only the overview's counters need it to `poll`. */
export const useStatus = (poll = false) =>
  useQuery({ queryKey: keys.status(), queryFn: getting<Status>("/api/status"), refetchInterval: poll ? 15_000 : false });

const fetchDevices = getting<DeviceSummary[]>("/api/devices");

/** Every AP with its latest report, refreshed by the live socket as they report: for the overview's cards. */
export const useDevices = () => useQuery({ queryKey: keys.devices(), queryFn: fetchDevices });

export const useDevice = (mac: Mac) =>
  useQuery({ queryKey: keys.device(mac), queryFn: getting<DeviceDetail>(`/api/devices/${mac}`) });

/** Every client of the past year, with its latest sample: for the client list. */
export const useClients = () => useQuery({ queryKey: keys.clients(), queryFn: getting<ListedClient[]>("/api/clients") });

/** Names by MAC, for links. */
export type Names = Readonly<Record<Mac, string>>;

const NO_NAMES: Names = Object.freeze({});
const deviceNames = (devices: DeviceSummary[]): Names => Object.fromEntries(devices.map((d) => [d.mac, d.name ?? d.mac]));

/**
 * AP names (else their MAC) by MAC, in the server's order; the same object until a name changes. Kept apart
 * from `useDevices`, which refetches as the APs report: the live socket refreshes the names when an AP is
 * adopted, forgotten or renamed (its new name comes with the config), and the slow poll catches the rest.
 */
export function useDeviceNames(): Names {
  const qc = useQueryClient();
  return (
    useQuery({
      queryKey: keys.deviceNames(),
      // Through the devices query, so that a page showing both (the overview, at mount) makes one request; always
      // a new one, unless that query's is under way, since a name may have changed since it was cached.
      queryFn: async () => deviceNames(await qc.fetchQuery({ queryKey: keys.devices(), queryFn: fetchDevices, staleTime: 0 })),
      refetchInterval: 300_000,
    }).data ?? NO_NAMES
  );
}

/**
 * Client display names by MAC, for the clients that have one; the same object until a name changes.
 * The live socket refreshes them when a client is renamed or an unnamed one connects; the slow poll
 * catches a hostname an AP reports later.
 */
export const useClientNames = (): Names =>
  useQuery({ queryKey: keys.clientNames(), queryFn: getting<Names>("/api/clients/names"), refetchInterval: 300_000 }).data ?? NO_NAMES;

/** One client, with the peers in its multicast groups; a 404 (HttpError) means it hasn't been seen since apctl started. */
export const useClient = (mac: Mac) =>
  useQuery({ queryKey: keys.client(mac), queryFn: getting<ClientDetail>(`/api/clients/${mac}`) });

/** `prev` with the samples of `add` (all newer) appended, and those before `from` dropped. */
function appendSeries(prev: Series, add: Series, from: number): Series {
  const keep = prev.ts.findIndex((t) => t >= from);
  const start = keep < 0 ? prev.ts.length : keep;
  const fields: Series["fields"] = {};
  for (const [f, values] of Object.entries(prev.fields)) fields[f] = [...values.slice(start), ...(add.fields[f] ?? add.ts.map(() => null))];
  return { ...prev, ts: [...prev.ts.slice(start), ...add.ts], fields };
}

/**
 * Time-series for one entity over a time span: only the columns `fields` names (the charts draw). A live chart of raw samples
 * (up to 6 hours) asks only for what is newer than its last sample.
 */
export function useSeries(table: string, key: string, span: TimeSpan, fields: readonly string[]) {
  const qc = useQueryClient();
  const only = fields.join(",");
  const queryKey = keys.series(table, key, span, only);
  return useQuery({
    queryKey,
    queryFn: async ({ signal }) => {
      const [from, to] = spanBounds(span);
      const url = (from: number) => `/api/series/${table}${qs({ key, fields: only, from, to })}`;
      const prev = isFixed(span) ? undefined : qc.getQueryData<Series>(queryKey);
      const last = prev?.tier === "raw" ? prev.ts.at(-1) : undefined;
      if (prev && last !== undefined && last >= from) {
        const add = await get<Series>(url(last + 1), signal);
        if (add.tier === "raw") return appendSeries(prev, add, from);
      }
      return get<Series>(url(from), signal);
    },
    refetchInterval: () => refreshFor(span, spanLength(span) <= 6 * 3600 ? 15_000 : 300_000),
    ...freshFor(span),
    placeholderData: keepPreviousData,
  });
}

export type EventFilter = { device?: Mac; client?: Mac; kind?: string; limit?: number };
export type LogFilter = { device?: Mac; q?: string; limit?: number };

/**
 * When the live socket last reconnected or was told to resync: a list cached before then is
 * fetched whole, since what it missed was never announced (and a restored backup restarts the ids).
 */
let liveResetAt = 0;

/** `prev` with the rows of `add` (stored after them), newest first as the server sorts them, and only the `limit` newest. */
function mergeNewest<T extends { id: number; ts: number }>(prev: T[], add: T[], limit: number): T[] {
  return [...add, ...prev].sort((a, b) => b.ts - a.ts || b.id - a.id).slice(0, limit);
}

/**
 * A newest-first list whose rows have rising ids (events, log lines). A refetch with something
 * cached asks only for the rows stored after its newest, and keeps the `limit` newest; the
 * previous list stays up (`isPlaceholderData`) while another filter's loads.
 */
function useNewestList<T extends { id: number; ts: number }>(queryKey: QueryKey, path: string, filter: Record<string, string | number | undefined> & { limit?: number }, defaultLimit: number) {
  const qc = useQueryClient();
  return useQuery({
    queryKey,
    queryFn: async ({ signal }) => {
      const cached = qc.getQueryState<T[]>(queryKey);
      const prev = cached?.data;
      if (cached && prev?.length && cached.dataUpdatedAt > liveResetAt) {
        const after = prev.reduce((max, r) => Math.max(max, r.id), 0);
        const add = await get<T[]>(`${path}${qs({ ...filter, after })}`, signal);
        return add.length ? mergeNewest(prev, add, filter.limit ?? defaultLimit) : prev;
      }
      return get<T[]>(`${path}${qs(filter)}`, signal);
    },
    placeholderData: keepPreviousData,
  });
}

// The server's default limits: 200 events, 500 log lines.
export const useEvents = (filter: EventFilter) => useNewestList<AppEvent>(keys.events(filter), "/api/events", filter, 200);

export const useLogs = (filter: LogFilter) => useNewestList<LogLine>(keys.logs(filter), "/api/logs", filter, 500);

/** A filter's MAC against a message's (canonical), as the server compares them: it reads the filter in any form it accepts. */
const sameMac = (filter: Mac | undefined, mac: Mac | null) => !filter || canonicalMac(filter) === mac;

/** Whether a list fetched with `f` would show the event, filtered as the server does: MACs exactly, kinds by comma-separated prefixes. */
function eventMatches(f: EventFilter, e: { kind: string; device_mac: Mac | null; client_mac: Mac | null }): boolean {
  if (!sameMac(f.device, e.device_mac) || !sameMac(f.client, e.client_mac)) return false;
  const kinds = (f.kind ?? "").split(",").map((k) => k.trim().toLowerCase()).filter(Boolean);
  return kinds.length === 0 || kinds.some((k) => e.kind.toLowerCase().startsWith(k));
}

/** Whether a log list fetched with `f` may show a new line from `device` (the text isn't announced, so a search always may). */
const logMatches = (f: LogFilter, device: Mac | null) => sameMac(f.device, device);

type LiveMsg =
  | { type: "device"; mac: Mac }
  | { type: "clients" }
  | ({ type: "event" } & Pick<AppEvent, "kind" | "device_mac" | "client_mac">)
  | { type: "log"; device_mac: Mac | null }
  | ({ type: "alert"; action: "raised" | "resolved" } & AlertItem)
  | { type: "resync" };

export type AlertCategory = "ap_status" | "security" | "health" | "changes";

export interface AlertItem {
  id: string;
  ts: number;
  key: string;
  category: AlertCategory;
  severity: "high" | "medium" | "low" | "info";
  entity: string;
  title: string;
  message: string;
  link: string | null;
  tag: string;
  resolved_ts: number | null;
  read?: boolean;
}

export const useAlerts = () =>
  useQuery({ queryKey: keys.alerts(), queryFn: getting<{ alerts: AlertItem[]; unread: number }>("/api/alerts?limit=50"), refetchInterval: 120_000 });

export const markAlertsRead = () => send("POST", "/api/alerts/read", {});

/** Event kinds that change what the adoption panel shows. */
const ADOPTION_EVENTS = new Set(["ap_pending", "ap_adopting", "ap_adopted", "ap_forgotten"]);

/** Event kinds that may change an AP's name, or which APs there are. */
const NAME_EVENTS = new Set(["ap_seen", "ap_adopted", "ap_forgotten", "config_applied", "settings_changed", "settings_imported"]);

/** Event kinds that change the channel plan and the RF views. */
const RF_EVENTS = new Set(["ap_scan_done", "channel_plan", "radio_changed"]);

/**
 * Keeps queries fresh from the server's WebSocket: device and client changes
 * invalidate the cached lists, new events and logs refetch the lists whose
 * filters they match.
 *
 * Invalidations are batched (a burst of messages causes one refetch), the busy
 * lists are refreshed at most every few seconds, and nothing is refetched while
 * the tab is hidden: what changed meanwhile is only marked stale, and React
 * Query's own refetch on return catches it up (once). After a reconnect
 * everything is refetched, since messages sent meanwhile are lost.
 */
export function useLiveUpdates(): void {
  const qc = useQueryClient();
  useEffect(() => {
    let ws: WebSocket | null = null;
    let closed = false;
    let dropped = false;
    let retry = 1000;
    let reconnectTimer: number | undefined;
    let flushTimer: number | undefined;
    let flushAt = Infinity;
    // Waiting invalidations by key, each with the earliest time it may run.
    const pending = new Map<string, { key: QueryKey; due: number }>();
    // When each key was last invalidated, for the minimum gaps.
    const last = new Map<string, number>();

    /** Marks `key` stale without refetching: the refetch on the tab's return picks it up. */
    const markStale = (key: QueryKey) => void qc.invalidateQueries({ queryKey: key, refetchType: "none" });
    const flush = () => {
      flushTimer = undefined;
      flushAt = Infinity;
      if (document.hidden) {
        for (const p of pending.values()) markStale(p.key);
        pending.clear();
        return;
      }
      const now = Date.now();
      for (const [id, p] of pending) {
        if (p.due > now) continue;
        pending.delete(id);
        last.set(id, now);
        void qc.invalidateQueries({ queryKey: p.key });
      }
      schedule();
    };
    // One timer, for the earliest due invalidation.
    const schedule = () => {
      if (pending.size === 0 || document.hidden) return;
      const due = Math.min(...[...pending.values()].map((p) => p.due));
      if (due >= flushAt) return;
      window.clearTimeout(flushTimer);
      flushAt = due;
      flushTimer = window.setTimeout(flush, Math.max(0, due - Date.now()));
    };
    /**
     * Invalidates `key` in `delay` ms (a burst of messages in that time causes one refetch), but no sooner
     * than `gap` ms after the last time. While the tab is hidden, it is only marked stale.
     */
    const invalidate = (key: QueryKey, gap = 0, delay = 750) => {
      if (document.hidden) return markStale(key);
      const id = JSON.stringify(key);
      if (pending.has(id)) return;
      pending.set(id, { key, due: Math.max(Date.now() + delay, (last.get(id) ?? 0) + gap) });
      schedule();
    };
    /**
     * Invalidates (as above) each query in `family` on screen whose filter `matches`. The rest
     * are only marked stale, all at once, so that they refetch when shown again.
     */
    const invalidateWhere = <F>(family: QueryKey, matches: (filter: F) => boolean, gap: number) => {
      for (const q of qc.getQueryCache().findAll({ queryKey: family, type: "active" })) {
        if (matches((q.queryKey[1] ?? {}) as F)) invalidate(q.queryKey, gap);
      }
      void qc.invalidateQueries({ queryKey: family, type: "inactive", refetchType: "none" });
    };
    /** Refetches everything (on return, if hidden): messages were missed. The event and log lists are fetched whole. */
    const refetchAll = () => {
      liveResetAt = Date.now();
      void qc.invalidateQueries({ refetchType: document.hidden ? "none" : "active" });
    };

    const onMessage = (m: MessageEvent) => {
      let msg: LiveMsg;
      try {
        msg = JSON.parse(m.data as string) as LiveMsg;
      } catch {
        return;
      }
      switch (msg.type) {
        case "device":
          // Only the overview's cards use the whole list; the names have their own query.
          invalidate(keys.devices(), 4000);
          invalidate(keys.device(msg.mac));
          // A client page changes when its AP reports (or with an event for the client, below).
          for (const q of qc.getQueryCache().findAll({ queryKey: keys.client(), type: "active" }))
            if ((q.state.data as ClientDetail | undefined)?.sample.ap_mac === msg.mac) invalidate(q.queryKey, 4000);
          break;
        case "clients":
          // Sent with every report that has clients, without saying which changed. The list holds every
          // client of the past year, so it follows more slowly.
          invalidate(keys.clients(), 20_000);
          break;
        case "event": {
          const e = msg;
          invalidateWhere<EventFilter>(keys.events(), (f) => eventMatches(f, e), 2000);
          if (msg.kind === "dryrun_compared" || msg.kind === "settings_imported") {
            // Each AP pushed to records one, and every fetch renders and compares every AP's config: follow at most every 5 s.
            invalidate(keys.dryrun(), 5000);
            invalidate(keys.settingsState());
          }
          // An editor keeps what it was opened with (it saves only the fields changed in it); the rest follows.
          if (msg.kind === "settings_changed" || msg.kind === "settings_imported") invalidate(keys.settings());
          if (ADOPTION_EVENTS.has(msg.kind)) invalidate(keys.adoption());
          if (NAME_EVENTS.has(msg.kind)) invalidate(keys.deviceNames(), 5000);
          if (msg.kind.startsWith("ap_upgrade")) invalidate(keys.firmware());
          if (RF_EVENTS.has(msg.kind)) {
            // A scan, a plan run or a channel change can change the plan, and what the radios hear.
            for (const key of [keys.rfPlan(), keys.rfRadios(), keys.rfNeighbors(), keys.rfLinks()]) invalidate(key, 5000);
          }
          if (msg.kind === "channel_plan") invalidate(keys.channelAi());
          if (msg.kind === "network_threat") invalidate(keys.threats());
          // Connected, gone, roamed, renamed, blocked: its page shows it.
          if (msg.client_mac) invalidate(keys.client(msg.client_mac));
          if (msg.kind === "client_renamed") invalidate(keys.clientNames());
          // A client without a name may have reported one as it connected.
          else if (msg.kind === "client_connected" && msg.client_mac && !qc.getQueryData<Names>(keys.clientNames())?.[msg.client_mac])
            invalidate(keys.clientNames(), 10_000);
          break;
        }
        case "log": {
          const device = msg.device_mac;
          invalidateWhere<LogFilter>(keys.logs(), (f) => logMatches(f, device), 3000);
          break;
        }
        case "alert":
          // The server stores alerts within a second of announcing them: look then.
          invalidate(keys.alerts(), 0, 1500);
          // The notifier decides whether this browser shows it.
          window.dispatchEvent(new CustomEvent("apctl:alert", { detail: msg }));
          break;
        case "resync":
          refetchAll();
          break;
      }
    };
    const connect = () => {
      reconnectTimer = undefined;
      if (closed) return;
      const proto = location.protocol === "https:" ? "wss" : "ws";
      const socket = new WebSocket(`${proto}://${location.host}/api/ws`);
      ws = socket;
      socket.onopen = () => {
        retry = 1000;
        // Whatever changed while disconnected (e.g. during a restart) was never announced.
        if (dropped) refetchAll();
      };
      socket.onmessage = onMessage;
      socket.onclose = (e) => {
        if (closed) return;
        // 1008 (policy): the server closed it because the session ended (logged out or expired).
        if (e.code === 1008) announceUnauthorized();
        dropped = true;
        reconnectTimer = window.setTimeout(connect, retry);
        retry = Math.min(retry * 2, 30_000);
      };
    };
    connect();
    return () => {
      closed = true;
      ws?.close();
      window.clearTimeout(reconnectTimer);
      window.clearTimeout(flushTimer);
    };
  }, [qc]);
}

// ---- Settings editor ----

/** A time an SSID is off: from a start on some days, for a while. */
export interface Blackout {
  start_days_of_week: string[];
  start_hour: number;
  start_minute: number;
  duration_minutes: number;
  name?: string;
}

/**
 * An SSID's settings fields, as the server sends them (null when unset) and
 * the editor changes them; the protection and APs are worked out from them.
 */
export interface WlanFields {
  name: string;
  enabled?: boolean | null;
  hide_ssid?: boolean | null;
  protection: "wpa2" | "wpa2_wpa3" | "wpa3" | "open" | null;
  /** Unset: the server derives it from the protection. */
  pmf_mode?: "disabled" | "optional" | "required" | null;
  wlan_bands?: string[] | null;
  /** null: broadcast from every AP. */
  aps: Mac[] | null;
  networkconf_id?: string | null;
  usergroup_id?: string | null;
  schedule_with_duration?: Blackout[] | null;

  fast_roaming_enabled?: boolean | null;
  wpa3_fast_roaming?: boolean | null;
  rrm_enabled?: boolean | null;
  bss_transition?: boolean | null;
  roaming_assistant_na_enabled?: boolean | null;
  roaming_assistant_na_rssi?: number | null;
  no2ghz_oui?: boolean | null;

  enhanced_iot?: boolean | null;
  iot_channel_lock?: boolean | null;
  iot_dtim_lock?: boolean | null;

  mdns_proxy_mode?: "off" | "auto" | "custom" | null;
  mdns_proxy_custom?: MdnsRule[] | null;

  mcastenhance_enabled?: boolean | null;
  multicast_suppressor_mode?: "off" | "conservative" | "aggressive" | null;
  bc_filter_enabled?: boolean | null;
  bc_filter_list?: string[] | null;
  proxy_arp?: boolean | null;

  dns_assistance_mode?: "off" | "auto" | "manual" | null;
  dns_assistance_servers?: string[] | null;
  advertise_device_name_in_beacon?: boolean | null;
  l2_isolation?: boolean | null;
  is_guest?: boolean | null;
  uapsd_enabled?: boolean | null;
  country_beacon?: boolean | null;
  minrate_setting_preference?: "auto" | "manual" | null;
  minrate_ng_enabled?: boolean | null;
  minrate_ng_data_rate_kbps?: number | null;
  minrate_na_enabled?: boolean | null;
  minrate_na_data_rate_kbps?: number | null;
  dtim_mode?: "default" | "custom" | null;
  dtim_ng?: number | null;
  dtim_na?: number | null;
  group_rekey?: number | null;
  sae_anti_clogging?: number | null;
  sae_sync?: number | null;
  tdls_prohibit?: boolean | null;
  p2p?: boolean | null;
  p2p_cross_connect?: boolean | null;
  log_level?: number | null;
  mac_filter_enabled?: boolean | null;
  mac_filter_policy?: "allow" | "deny" | null;
  mac_filter_list?: string[] | null;

  // Sent and kept as they are: the protection stands for these.
  security?: string | null;
  wpa_mode?: string | null;
  wpa3_support?: boolean | null;
  wpa3_transition?: boolean | null;
  ap_group_mode?: string | null;
}

/** An SSID in the settings editor's list. */
export interface WlanSettings extends WlanFields {
  id: string;
  /** False for SSIDs the settings mark as not editable. */
  editable: boolean;
  has_passphrase: boolean;
}

export interface WlanSettingsList {
  active: boolean;
  wlans: WlanSettings[];
  networks: { id: string; name: string; vlan: number | null; purpose: string | null }[];
  aps: { mac: Mac; name: string | null }[];
  /** For each optional SSID feature, the APs that would broadcast without it. */
  unsupported: Record<string, Mac[]>;
  /** APs whose feature support is not known yet (no inform). */
  unknown: Mac[];
  /** The predefined mDNS service codes. */
  mdns_services: { code: string; name: string }[];
}

export interface MdnsRule {
  ap_scope_mode: "all" | "specific" | "group";
  ap_macs?: Mac[];
  ap_group_ids?: string[];
  services_mode: "all" | "specific" | "none";
  predefined_services?: { code: string }[];
  custom_services?: { address: string; name?: string }[];
  networkconf_ids?: string[];
  isolation_enabled?: boolean;
}

/** An AP's radio as its settings document holds it: imported documents can hold a number as text ("20"), which `radioForm` reads. */
export interface RadioSettings {
  radio: string;
  name: string;
  /** "auto", or the channel. */
  channel: number | string;
  /** The width in MHz. */
  ht: number | string;
  tx_power_mode: string;
  tx_power: number | string | null;
  min_rssi_enabled: boolean | null;
  min_rssi: number | null;
  hard_noise_floor_enabled: boolean | null;
  sens_level_enabled: boolean | null;
  sens_level: number | null;
  antenna_gain: number | null;
  antenna_id: number | null;
  vwire_enabled: boolean | null;
  loadbalance_enabled: boolean | null;
  maxsta: number | null;
  has_blocker: boolean;
  caps: { min_txpower: number | null; max_txpower: number | null; has_ht160: boolean | null } | null;
  /** Legal channels by width (MHz) in the site's country, indoors and in outdoor mode. */
  channels: Record<string, number[]>;
  channels_outdoor: Record<string, number[]>;
}

export interface ConfigNetwork {
  type: "dhcp" | "static";
  ip?: string;
  netmask?: string;
  gateway?: string;
  dns1?: string;
  dns2?: string;
  dnssuffix?: string;
}

export interface DeviceSettings {
  active: boolean;
  mac: Mac;
  name: string | null;
  model: string | null;
  led_override: "default" | "on" | "off" | null;
  led_override_color: string | null;
  led_override_color_brightness: number | null;
  outdoor_mode_override: "default" | "on" | "off" | null;
  bandsteering_mode: "off" | "equal" | "prefer_5g" | null;
  atf_enabled: boolean | null;
  green_ap_enabled: boolean | null;
  resetbtn_enabled: "on" | "off" | null;
  jumboframe_enabled: boolean | null;
  config_network: ConfigNetwork | null;
  snmp_location: string | null;
  snmp_contact: string | null;
  radios: RadioSettings[];
  /** AP-wide features its capability bits allow (all of them until it reports). */
  features: string[];
  reported: boolean;
  site_outdoor: boolean;
  /** The site's "advanced features" switch, which band steering, minimum signal and client limits need. */
  advanced_features: boolean;
  antennas: { id: number; name: string; default?: boolean }[];
  ports: number;
}

/** What a settings change would send each AP (the shape of a config push). `error`: its config would
 *  not render; `fixes`: why its config does not render now, which the change mends. */
export interface SettingsPreview {
  what: string;
  aps: (ConfigPushed & { mac: Mac; name: string | null; error?: string; fixes?: string })[];
}

export type SettingsTarget =
  | { kind: "wlan"; id: string | null; remove?: boolean }
  | { kind: "device"; mac: Mac }
  | { kind: "usergroup"; id: string | null; remove?: boolean }
  | { kind: "site" };

export interface SshKey { name: string; type: string; key: string; comment: string }

/** Site-wide device settings (secrets are never sent back). */
export interface SiteSettings {
  active: boolean;
  mgmt: {
    has_ssh_password: boolean;
    led_enabled: boolean | null;
    outdoor_mode_enabled: boolean | null;
    x_ssh_enabled: boolean | null;
    x_ssh_username: string | null;
    x_ssh_auth_password_enabled: boolean | null;
    x_ssh_bind_wildcard: boolean | null;
    x_ssh_keys: SshKey[] | null;
  };
  rsyslogd: {
    mode: "off" | "controller" | "server";
    ip: string | null;
    port: number | string | null;
    debug: boolean | null;
    netconsole_enabled: boolean | null;
    netconsole_host: string | null;
    netconsole_port: number | string | null;
  };
  snmp: { enabled: boolean | null; enabledV3: boolean | null; community: string | null; username: string | null; has_v3_password: boolean };
  ntp: { setting_preference: "auto" | "manual" | null; ntp_server_1: string | null; ntp_server_2: string | null; ntp_server_3: string | null; ntp_server_4: string | null };
  country: number | null;
  timezone: string | null;
  countries: { code: number; name: string }[];
  timezones: string[];
}

export const useSiteSettings = () => useQuery({ queryKey: keys.settings("site"), queryFn: getting<SiteSettings>("/api/settings/site") });
export const useWlanSettings = () => useQuery({ queryKey: keys.settings("wlans"), queryFn: getting<WlanSettingsList>("/api/settings/wlans") });
export const useDeviceSettings = (mac: Mac) =>
  useQuery({ queryKey: keys.settings("device", mac), queryFn: getting<DeviceSettings>(`/api/settings/devices/${mac}`) });
export const wlanPassphrase = (id: string) => get<{ passphrase: string | null }>(`/api/settings/wlans/${id}/passphrase`);

/** Previews (or, with `save`, saves) a change to an SSID, a speed limit, an AP or the site. */
export function changeSettings<T>(target: SettingsTarget, patch: Record<string, unknown>, save: boolean): Promise<T> {
  const q = save ? "" : "?preview=true";
  if (target.kind === "device") return send<T>("PUT", `/api/settings/devices/${target.mac}${q}`, { patch });
  if (target.kind === "site") return send<T>("PUT", `/api/settings/site${q}`, { patch });
  // SSIDs and speed limits (user groups): create, change or remove.
  const base = `/api/settings/${target.kind === "usergroup" ? "usergroups" : "wlans"}`;
  if (target.remove) return send<T>("DELETE", `${base}/${target.id}${q}`, {});
  if (target.id === null) return send<T>("POST", `${base}${q}`, { patch });
  return send<T>("PUT", `${base}/${target.id}${q}`, { patch });
}

// ---- Channel AI ----

export interface ChannelPlanResult {
  band: string;
  dfs: boolean;
  /** The channels the plan could use (from the Channel AI settings); null: any. */
  allowed: number[] | null;
  plan: PlanEntry[];
  current_total: number;
  suggested_total: number;
  /** The plan is worth applying (clearly better, or an AP must move). */
  accepted: boolean;
}

export interface ChannelAiStatus {
  active: boolean;
  has_settings: boolean;
  settings: { enabled: boolean; hour: number; minute: number; radios: string[]; dfs: boolean; exclude_devices: Mac[] };
  timezone: string | null;
  next_run: number | null;
  running: boolean;
  scans: { mac: Mac; band: string; started: number }[];
  allowed: { ng: number[] | null; na: number[] | null };
}

/** Polls quickly while a run or a scan is under way. */
export const useChannelAi = () =>
  useQuery({
    queryKey: keys.channelAi(),
    queryFn: getting<ChannelAiStatus>("/api/rf/channel-ai"),
    refetchInterval: (q) => (q.state.data?.running || q.state.data?.scans.length ? 5_000 : 60_000),
  });
export const startScan = (band: string) => send<{ scanning: Mac[] }>("POST", "/api/rf/scan", { band });
export const runChannelAi = (bands?: string[]) => send<{ started: boolean }>("POST", "/api/rf/channel-ai/run", { bands });
export const applyChannelPlan = (band: string, changes: { mac: Mac; name: string | null; from: number | null; to: number | null }[]) =>
  send<{ applied: number }>("POST", "/api/rf/channel-plan/apply", { band, changes });
export const saveChannelAi = (patch: Record<string, unknown>) => send<{ saved: boolean; what: string }>("PUT", "/api/rf/channel-ai", { patch });

// ---- Speed limits ----

export interface UserGroup {
  id: string;
  name: string;
  default: boolean;
  /** kbps; -1: no limit. */
  qos_rate_max_down: number | null;
  qos_rate_max_up: number | null;
  /** SSIDs and clients using it. */
  used_by: string[];
}

export const useUserGroups = (enabled = true) =>
  useQuery({ queryKey: keys.settings("usergroups"), queryFn: getting<{ active: boolean; groups: UserGroup[] }>("/api/settings/usergroups"), enabled });
export const setClientSpeedLimit = (mac: Mac, usergroup_id: string | null) => send<{ saved: boolean; what: string }>("PUT", `/api/clients/${mac}/speed-limit`, { usergroup_id });

// ---- Adoption ----

export interface PendingAp {
  mac: Mac;
  ip: string | null;
  model: string | null;
  model_display: string | null;
  version: string | null;
  hostname: string | null;
  serial: string | null;
  /** apctl managed it before: it was reset. */
  known: boolean;
  first_seen: number;
  last_seen: number;
}

export interface AdoptionStatus {
  active: boolean;
  pending: PendingAp[];
  adopting: { mac: Mac; since: number }[];
  forgetting: { mac: Mac; since: number }[];
  ssh: { possible: boolean; inform_url: string | null };
}

/** APs waiting for adoption (only fetched when `enabled`); polls quickly while one is waiting, adopting or being forgotten. */
export const useAdoption = (enabled = true) =>
  useQuery({
    queryKey: keys.adoption(),
    queryFn: getting<AdoptionStatus>("/api/devices/pending"),
    enabled,
    refetchInterval: (q) => {
      const d = q.state.data;
      return d && (d.pending.length || d.adopting.length || d.forgetting.length) ? 5_000 : 60_000;
    },
  });
export const adoptAp = (mac: Mac) => send<{ adopting: boolean }>("POST", `/api/devices/${mac}/adopt`, {});
export const adoptOverSsh = (ip: string, username: string, password: string) =>
  send<{ adopting: boolean; mac: Mac }>("POST", "/api/devices/adopt-ssh", { ip, username: username || null, password: password || null });
export const forgetAp = (mac: Mac) => send<{ forgetting?: boolean; forgotten?: boolean }>("POST", `/api/devices/${mac}/forget`, {});
