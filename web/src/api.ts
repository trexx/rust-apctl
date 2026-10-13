import { useEffect } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";

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
  reconfiguring: boolean;
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
  multicast: Multicast | null;
}

/** `tx` is what the AP delivered to the client, `rx` what the client sent. */
export interface McastCounts {
  tx_pkts: number;
  tx_bytes: number;
  rx_pkts: number;
  rx_bytes: number;
}

export interface Multicast {
  types: Record<string, McastCounts>;
  groups: (McastCounts & { group_ip: string; dst_port: number | null; type: string | null })[];
  memberships: string[];
  services: { name: string; pkts: number; bytes: number }[];
}

export interface ClientView {
  sample: ClientSample;
  connected: boolean;
  first_seen: number;
  last_seen: number;
  ap_name?: string | null;
  vendor?: string | null;
  alias?: string | null;
  note?: string | null;
  /** From the settings: blocked from every SSID. */
  blocked?: boolean;
  /** From the settings: the only AP the client may connect to. */
  locked_to?: Mac | null;
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
    reconfiguring: boolean;
    last_config_push: number | null;
    /** Known from the database only: hasn't reported since apctl started. */
    stored_only?: boolean;
  };
  clients: ClientView[];
  locating?: boolean;
}

export interface Series {
  tier: "raw" | "5m" | "1h";
  step: number;
  ts: number[];
  fields: Record<string, (number | null)[]>;
}

export interface AppEvent {
  ts: number;
  kind: string;
  device_mac: Mac | null;
  client_mac: Mac | null;
  data: Record<string, unknown> | null;
}

export interface LogLine {
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
  mode: string;
  source: string;
  started: number;
  now: number;
  devices: number;
  devices_online: number;
  clients_connected: number;
  counters: Record<string, number>;
}

/** Raised for 401s; the app shell then shows the login page. */
export class AuthError extends Error {}

function unauthorized(): never {
  window.dispatchEvent(new Event("apctl:unauthorized"));
  throw new AuthError("login required");
}

async function send<T>(method: string, path: string, body: unknown): Promise<T> {
  const res = await fetch(path, {
    method,
    // The server requires this header on writes (CSRF protection).
    headers: { "Content-Type": "application/json", "X-Requested-With": "apctl" },
    body: JSON.stringify(body),
  });
  if (res.status === 401 && path !== "/api/login") unauthorized();
  if (!res.ok) {
    let msg = `${res.status} ${res.statusText}`;
    try {
      msg = (await res.json()).error ?? msg;
    } catch {
      /* not JSON */
    }
    throw new Error(msg);
  }
  return res.json() as Promise<T>;
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

async function get<T>(path: string): Promise<T> {
  const res = await fetch(path);
  if (res.status === 401) unauthorized();
  if (!res.ok) {
    let msg = `${res.status} ${res.statusText}`;
    try {
      msg = (await res.json()).error ?? msg;
    } catch {
      /* not JSON */
    }
    throw new Error(msg);
  }
  return res.json() as Promise<T>;
}

function qs(params: Record<string, string | number | undefined | null>): string {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== "") p.set(k, String(v));
  }
  const s = p.toString();
  return s ? `?${s}` : "";
}

export interface Me {
  auth: boolean;
  user: string | null;
  read_only?: boolean;
}

/** The logged-in user. `user` is null when a login is required. */
export const useMe = () =>
  useQuery({
    queryKey: ["me"],
    queryFn: async (): Promise<Me> => {
      const res = await fetch("/api/me");
      if (res.status === 401) return { auth: true, user: null };
      if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
      return res.json() as Promise<Me>;
    },
    staleTime: 60_000,
  });

export const login = (username: string, password: string) => send<{ user: string }>("POST", "/api/login", { username, password });
export const logout = () => send<{ ok: boolean }>("POST", "/api/logout", {});

export interface StateSummary {
  imported_at: number | null;
  summary: { sites: number; wlans: string[]; networks: string[]; ap_groups: string[]; devices: number; clients: number; settings: number } | null;
}

export const useSettingsState = () => useQuery({ queryKey: ["settings-state"], queryFn: () => get<StateSummary>("/api/settings/state") });

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

export interface DryRun {
  generator: boolean;
  settings_imported_at: number | null;
  devices: {
    mac: Mac;
    name: string | null;
    status: "match" | "equivalent" | "differs" | "error" | "no_generator" | "no_settings" | "no_config_seen";
    comparison?: { mgmt_cfg: FieldComparison; system_cfg: FieldComparison };
    against_redacted?: boolean;
    error?: string;
    /** The AP runs a different config version than when the settings were imported. */
    settings_stale?: boolean;
  }[];
  history: { ts: number; mac: Mac; cfgversion: string | null; matches: boolean; comparison: { system_cfg?: FieldComparison; error?: string } | null }[];
}

export const useDryRun = () => useQuery({ queryKey: ["dryrun"], queryFn: () => get<DryRun>("/api/dryrun"), refetchInterval: 30_000 });

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
  airtime: { ts: number[]; total: number[]; external_interference: number[]; own_traffic: number[]; own_rx: number[]; own_tx: number[] };
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
  latency_ms: { association: number | null; authentication: number | null; dhcp: number | null; dns: number | null; total: number | null };
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
    services: { name: string; pkts: number; bytes: number }[];
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
  cu_total_now: number | null;
  noise_floor: number | null;
  avg_utilization: number | null;
  avg_interference: number | null;
  tx_retry_pct: number | null;
  usage_bytes: number;
  avg_client_signal: number | null;
  spectrum: { channel: number; width: number | null; utilization: number | null; interference: number | null; ts: number }[];
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
  current_channel: number | null;
  current_score: number | null;
  current_reasons: string[] | null;
  suggested_channel: number;
  suggested_score: number;
  suggested_reasons: string[];
  change: boolean;
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

export const useThreats = () =>
  useQuery({
    queryKey: ["threats"],
    queryFn: () => get<{ watching_since: number; findings: ThreatFinding[] }>("/api/rf/threats"),
    refetchInterval: 60_000,
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

/** Live ranges refresh; fixed windows in the past don't change. */
const refreshFor = (s: TimeSpan, live: number) => (isFixed(s) && s.to < Date.now() / 1000 - 600 ? false : live);

export const useSiteActivity = (span: TimeSpan, band: string, mac?: Mac) =>
  useQuery({
    queryKey: ["site-activity", span, band, mac],
    queryFn: () => get<SiteActivity>(`/api/site/activity${qs({ ...spanParams(span), band: bandParam(band), mac })}`),
    refetchInterval: refreshFor(span, 60_000),
    placeholderData: (p) => p,
  });

export const useSiteTop = (span: TimeSpan, mac?: Mac) =>
  useQuery({
    queryKey: ["site-top", span, mac],
    queryFn: () => get<{ aps: TopEntry[]; clients: TopEntry[] }>(`/api/site/top${qs({ ...spanParams(span), mac })}`),
    refetchInterval: refreshFor(span, 60_000),
    placeholderData: (p) => p,
  });

export const useConnectivity = (span: TimeSpan) =>
  useQuery({
    queryKey: ["connectivity", span],
    queryFn: () => get<{ bands: Record<string, Connectivity> }>(`/api/site/connectivity${qs(spanParams(span))}`),
    refetchInterval: refreshFor(span, 60_000),
    placeholderData: (p) => p,
  });

export const useRetries = (span: TimeSpan) =>
  useQuery({
    queryKey: ["retries", span],
    queryFn: () => get<RadioRetries[]>(`/api/site/retries${qs(spanParams(span))}`),
    refetchInterval: refreshFor(span, 60_000),
    placeholderData: (p) => p,
  });

export const useDensity = (span: TimeSpan) =>
  useQuery({
    queryKey: ["density", span],
    queryFn: () => get<{ aps: DensityAp[] }>(`/api/site/density${qs(spanParams(span))}`),
    refetchInterval: refreshFor(span, 60_000),
    placeholderData: (p) => p,
  });

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

export const useConnections = (span: TimeSpan, opts: { client?: Mac; failed?: boolean } = {}) =>
  useQuery({
    queryKey: ["connections", span, opts],
    queryFn: () =>
      get<{ attempts: ConnAttempt[]; roams: Roam[]; ap_names: Record<string, string>; client_names: Record<string, string> }>(
        `/api/connections${qs({ ...spanParams(span), client: opts.client, failed: opts.failed ? "true" : undefined })}`,
      ),
    refetchInterval: refreshFor(span, 60_000),
    placeholderData: (p) => p,
  });

export const useRoaming = (span: TimeSpan) =>
  useQuery({
    queryKey: ["roaming", span],
    queryFn: () => get<Roaming>(`/api/roaming${qs(spanParams(span))}`),
    refetchInterval: refreshFor(span, 60_000),
    placeholderData: (p) => p,
  });

export const useWlans = (span: TimeSpan) =>
  useQuery({
    queryKey: ["wlans", span],
    queryFn: () => get<{ bucket: number; wlans: Wlan[] }>(`/api/wlans${qs(spanParams(span))}`),
    refetchInterval: refreshFor(span, 60_000),
    placeholderData: (p) => p,
  });

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

export const useBackups = () =>
  useQuery({
    queryKey: ["backups"],
    queryFn: () =>
      get<{ encrypted: boolean; version: string; settings: BackupSettings; next_run: number | null; backups: BackupMeta[]; restore_pending: boolean }>("/api/backups"),
  });

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
  if (res.status === 401) unauthorized();
  if (!res.ok) {
    let msg = `${res.status} ${res.statusText}`;
    try {
      msg = (await res.json()).error ?? msg;
    } catch {
      /* not JSON */
    }
    throw new Error(msg);
  }
  return res.json();
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
  state: "queued" | "sent" | "downloading" | "writing";
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

export const useFirmware = () => useQuery({ queryKey: ["firmware"], queryFn: () => get<FirmwareInfo>("/api/firmware"), refetchInterval: 10_000 });
export const checkFirmware = () => send<{ platforms: number }>("POST", "/api/firmware/check", {});
export const upgradeFirmware = (macs: Mac[]) => send<{ queued: number; skipped: { mac: Mac; why: string }[] }>("POST", "/api/firmware/upgrade", { macs });
export const upgradeFirmwareUrl = (mac: Mac, url: string) => send("POST", "/api/firmware/upgrade-url", { mac, url });
export const cancelFirmware = () => send<{ cancelled: number }>("POST", "/api/firmware/cancel", {});

export const useMulticast = (span: TimeSpan, mac?: Mac) =>
  useQuery({
    queryKey: ["multicast", span, mac],
    queryFn: () => get<SiteMulticast>(`/api/site/multicast${qs({ ...spanParams(span), mac })}`),
    refetchInterval: refreshFor(span, 60_000),
    placeholderData: (p) => p,
  });

export const useRadios = (range: number) =>
  useQuery({ queryKey: ["rf-radios", range], queryFn: () => get<RadioOverview[]>(`/api/rf/radios${qs({ range })}`), refetchInterval: 60_000 });

export const useNeighbors = (range: number, band: string) =>
  useQuery({
    queryKey: ["rf-neighbors", range, band],
    queryFn: () => get<{ neighbors: Neighbor[]; own_links: OwnLink[] }>(`/api/rf/neighbors${qs({ range, band: bandParam(band) })}`),
    refetchInterval: 60_000,
  });

export const useChannelPlan = (band: string, dfs: boolean) =>
  useQuery({
    queryKey: ["rf-plan", band, dfs],
    queryFn: () => get<{ band: string; dfs: boolean; plan: PlanEntry[] }>(`/api/rf/channel-plan${qs({ band, dfs: dfs ? "true" : undefined })}`),
  });

export const useStatus = () => useQuery({ queryKey: ["status"], queryFn: () => get<Status>("/api/status"), refetchInterval: 15_000 });

export const useDevices = () => useQuery({ queryKey: ["devices"], queryFn: () => get<DeviceSummary[]>("/api/devices") });

export const useDevice = (mac: Mac) =>
  useQuery({ queryKey: ["device", mac], queryFn: () => get<DeviceDetail>(`/api/devices/${mac}`) });

export const useClients = () => useQuery({ queryKey: ["clients"], queryFn: () => get<ClientView[]>("/api/clients") });

export const useClient = (mac: Mac) =>
  useQuery({ queryKey: ["client", mac], queryFn: () => get<ClientView>(`/api/clients/${mac}`), retry: false });

/** Time-series for one entity over a time span. */
export const useSeries = (table: string, key: string, span: TimeSpan) =>
  useQuery({
    queryKey: ["series", table, key, span],
    queryFn: () => {
      const [from, to] = spanBounds(span);
      return get<Series>(`/api/series/${table}${qs({ key, from, to })}`);
    },
    refetchInterval: refreshFor(span, spanLength(span) <= 6 * 3600 ? 15_000 : 300_000),
    placeholderData: (prev) => prev,
  });

export const useEvents = (filter: { device?: Mac; client?: Mac; kind?: string; limit?: number }) =>
  useQuery({ queryKey: ["events", filter], queryFn: () => get<AppEvent[]>(`/api/events${qs(filter)}`) });

export const useLogs = (filter: { device?: Mac; q?: string; limit?: number }) =>
  useQuery({ queryKey: ["logs", filter], queryFn: () => get<LogLine[]>(`/api/logs${qs(filter)}`) });

type LiveMsg =
  | { type: "device"; mac: Mac }
  | { type: "clients" }
  | ({ type: "event" } & AppEvent)
  | ({ type: "log" } & LogLine)
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
  useQuery({ queryKey: ["alerts"], queryFn: () => get<{ alerts: AlertItem[]; unread: number }>("/api/alerts?limit=50"), refetchInterval: 120_000 });

export const markAlertsRead = () => send("POST", "/api/alerts/read", {});

/**
 * Keeps queries fresh from the server's WebSocket: device and client changes
 * invalidate the cached lists, new events and logs refetch their lists.
 * Invalidations are batched so a burst of messages causes one refetch.
 */
export function useLiveUpdates(): void {
  const qc = useQueryClient();
  useEffect(() => {
    let ws: WebSocket | null = null;
    let closed = false;
    let retry = 1000;
    const pending = new Set<string>();
    let flushTimer: number | undefined;
    const invalidate = (key: string) => {
      pending.add(key);
      flushTimer ??= window.setTimeout(() => {
        flushTimer = undefined;
        for (const k of pending) void qc.invalidateQueries({ queryKey: [k] });
        pending.clear();
      }, 750);
    };
    const connect = () => {
      const proto = location.protocol === "https:" ? "wss" : "ws";
      ws = new WebSocket(`${proto}://${location.host}/api/ws`);
      ws.onopen = () => {
        retry = 1000;
      };
      ws.onmessage = (m) => {
        const msg = JSON.parse(m.data as string) as LiveMsg;
        switch (msg.type) {
          case "device":
            invalidate("devices");
            invalidate("device");
            break;
          case "clients":
            invalidate("clients");
            invalidate("client");
            break;
          case "event":
            invalidate("events");
            if (msg.kind === "dryrun_compared" || msg.kind === "settings_imported") {
              invalidate("dryrun");
              invalidate("settings-state");
            }
            break;
          case "log":
            invalidate("logs");
            break;
          case "alert":
            invalidate("alerts");
            // The server stores alerts within a second of announcing them: look again then.
            window.setTimeout(() => void qc.invalidateQueries({ queryKey: ["alerts"] }), 1500);
            // The notifier decides whether this browser shows it.
            window.dispatchEvent(new CustomEvent("apctl:alert", { detail: msg }));
            break;
          case "resync":
            void qc.invalidateQueries();
            break;
        }
      };
      ws.onclose = () => {
        if (closed) return;
        window.setTimeout(connect, retry);
        retry = Math.min(retry * 2, 30_000);
      };
    };
    connect();
    return () => {
      closed = true;
      ws?.close();
      if (flushTimer) window.clearTimeout(flushTimer);
    };
  }, [qc]);
}
