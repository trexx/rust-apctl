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
  };
  clients: ClientView[];
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

export interface Stage {
  stage: string;
  ok: number;
  failed: number;
  success_pct: number | null;
  median_ms: number | null;
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

const bandParam = (band: string) => (band === "all" ? undefined : band);

export const useSiteActivity = (range: number, band: string, mac?: Mac) =>
  useQuery({
    queryKey: ["site-activity", range, band, mac],
    queryFn: () => get<SiteActivity>(`/api/site/activity${qs({ range, band: bandParam(band), mac })}`),
    refetchInterval: 60_000,
    placeholderData: (p) => p,
  });

export const useSiteTop = (range: number, mac?: Mac) =>
  useQuery({
    queryKey: ["site-top", range, mac],
    queryFn: () => get<{ aps: TopEntry[]; clients: TopEntry[] }>(`/api/site/top${qs({ range, mac })}`),
    refetchInterval: 60_000,
  });

export const useConnectivity = (range: number, band: string) =>
  useQuery({
    queryKey: ["connectivity", range, band],
    queryFn: () => get<{ stages: Stage[] }>(`/api/site/connectivity${qs({ range, band: bandParam(band) })}`),
    refetchInterval: 60_000,
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

/** Time-series for one entity. `range` is in seconds back from now. */
export const useSeries = (table: string, key: string, range: number) =>
  useQuery({
    queryKey: ["series", table, key, range],
    queryFn: () => {
      const to = Math.floor(Date.now() / 1000);
      return get<Series>(`/api/series/${table}${qs({ key, from: to - range, to })}`);
    },
    refetchInterval: range <= 6 * 3600 ? 15_000 : 300_000,
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
  | { type: "resync" };

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
