import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import {
  displayName,
  useClients,
  useDevice,
  useDevices,
  useEvents,
  useLogs,
  useSeries,
  useSiteActivity,
  useSiteTop,
} from "../api";
import type { ClientView, RadioSample, TimeSpan, VapSample } from "../api";
import {
  COLORS,
  Chart,
  RangePicker,
  SpanContext,
  ZoomContext,
  useTimeSpan,
} from "../components/Chart";
import {
  Dot,
  ErrorNote,
  EventList,
  Loading,
  LogList,
  Signal,
  Stat,
  clientNames,
  deviceNames,
} from "../components/common";
import { ago, band, bitrate, bytes, duration, pct, phy } from "../format";
import { MulticastPanel } from "../components/Insights";
import { DeviceActions } from "../components/Actions";
import { DeviceSettingsPanel } from "../components/SettingsEditor";

export function Device() {
  const { mac = "" } = useParams();
  const [range, setRange] = useTimeSpan(6 * 3600);
  const detail = useDevice(mac);
  const devices = useDevices();
  const names = deviceNames(devices.data);
  const cnames = clientNames(useClients().data);
  const events = useEvents({ device: mac, limit: 50 });
  const logs = useLogs({ device: mac, limit: 100 });

  if (detail.isLoading) return <Loading />;
  if (detail.error || !detail.data)
    return <ErrorNote error={detail.error ?? "Unknown device"} />;
  const { device: d, clients } = detail.data;
  const ap = d.snapshot.ap;
  const up = d.snapshot.uplink;

  return (
    <ZoomContext.Provider value={(from, to) => setRange({ from, to })}>
      <SpanContext.Provider value={range}>
        <div className="page">
          <div className="page-head">
            <h1>
              <Dot ok={d.online} warn={d.reconfiguring} /> {ap.hostname ?? mac}
            </h1>
            <span className="muted">
              {ap.model_display ?? ap.model} · {ap.version} · {ap.ip} ·{" "}
              <span className="mono">{mac}</span>
            </span>
            <span className="spacer" />
            <RangePicker value={range} onChange={setRange} />
          </div>
          <DeviceActions
            mac={mac}
            name={ap.hostname ?? mac}
            online={d.online}
            locating={detail.data.locating ?? false}
          />
          <DeviceSettingsPanel mac={mac} />
          {d.reconfiguring && (
            <div className="banner">
              Applying a configuration change. Client data resumes in a moment.
            </div>
          )}
          {d.stored_only && (
            <div className="banner">
              This AP hasn't reported since apctl started, so only its stored
              details and history are shown. Radios and clients appear with its
              next report.
            </div>
          )}

          <div className="stats">
            <Stat
              label="Status"
              value={d.online ? "Online" : "Offline"}
              sub={
                d.interval
                  ? `seen ${ago(d.last_seen)}, every ~${d.interval}s`
                  : `last seen ${ago(d.last_seen)}`
              }
            />
            <Stat label="Uptime" value={duration(ap.uptime)} />
            <Stat
              label="CPU / memory"
              value={`${pct(ap.cpu)} / ${pct(ap.mem)}`}
              sub={`load ${ap.load1 ?? "—"} · ${ap.load5 ?? "—"} · ${ap.load15 ?? "—"}`}
            />
            <Stat
              label="Clients"
              value={clients.length}
              sub={`satisfaction ${ap.satisfaction ?? "—"}`}
            />
            <Stat
              label="Memory"
              value={ap.mem_used !== null ? bytes(ap.mem_used) : "—"}
              sub={`of ${bytes(ap.mem_total)}${up ? ` · uplink ${up.ifname} ${up.speed ? `${up.speed} Mbps${up.full_duplex ? " FD" : ""}` : "down"}` : ""}`}
            />
            {up && (
              <Stat
                label="Uplink received"
                value={bytes(up.rx_bytes)}
                sub={`sent ${bytes(up.tx_bytes)} · packets ${count(up.rx_packets)} in, ${count(up.tx_packets)} out · since start`}
              />
            )}
          </div>

          <div className="grid2">
            <ApCharts mac={mac} range={range} />
            <UplinkChart mac={mac} range={range} />
          </div>

          <h2>Radios</h2>
          <div className="grid2">
            {d.snapshot.radios.map((r) => (
              <RadioPanel
                key={r.radio}
                mac={mac}
                radio={r}
                vaps={d.snapshot.vaps.filter((v) => v.radio === r.radio)}
                clients={clients.filter((c) => c.sample.radio === r.radio)}
                range={range}
              />
            ))}
          </div>
          <div className="grid2">
            {d.snapshot.radios.map((r) => (
              <RadioActivity
                key={r.radio}
                mac={mac}
                radio={r.radio}
                range={range}
              />
            ))}
          </div>
          <div className="grid1">
            <ActiveClients mac={mac} range={range} />
          </div>
          <div className="grid1">
            <MulticastPanel
              mac={mac}
              span={range}
              title="Multicast and broadcast on this AP"
            />
          </div>

          <h2>SSIDs</h2>
          <VapTable vaps={d.snapshot.vaps} range={range} />

          <h2>Connected clients</h2>
          <div className="panel">
            <table className="table">
              <thead>
                <tr>
                  <th>Client</th>
                  <th>SSID</th>
                  <th>Band</th>
                  <th>Signal</th>
                  <th>Rate (down/up)</th>
                  <th>Connected</th>
                </tr>
              </thead>
              <tbody>
                {clients
                  .slice()
                  .sort(
                    (a, b) =>
                      (b.sample.signal ?? -100) - (a.sample.signal ?? -100),
                  )
                  .map((c) => (
                    <tr key={c.sample.mac}>
                      <td>
                        <Link to={`/clients/${c.sample.mac}`}>
                          {displayName(c)}
                        </Link>
                      </td>
                      <td>{c.sample.essid}</td>
                      <td>
                        {band(c.sample.radio)} ch {c.sample.channel}
                      </td>
                      <td>
                        <Signal dbm={c.sample.signal} />
                      </td>
                      <td>
                        {phy(c.sample.tx_rate)} / {phy(c.sample.rx_rate)}
                      </td>
                      <td>{duration(c.sample.uptime)}</td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>

          <div className="grid2">
            <div>
              <h2>Events</h2>
              <div className="panel scroll">
                {events.data ? (
                  <EventList
                    events={events.data}
                    names={names}
                    clientNames={cnames}
                    showDevice={false}
                  />
                ) : (
                  <Loading />
                )}
              </div>
            </div>
            <div>
              <h2>
                Logs{" "}
                <Link to={`/logs?device=${mac}`} className="small">
                  all logs →
                </Link>
              </h2>
              <div className="panel scroll">
                {logs.data ? (
                  <LogList logs={logs.data} names={names} showDevice={false} />
                ) : (
                  <Loading />
                )}
              </div>
            </div>
          </div>
        </div>
      </SpanContext.Provider>
    </ZoomContext.Provider>
  );
}

function ApCharts({ mac, range }: { mac: string; range: TimeSpan }) {
  const s = useSeries("ap", mac, range);
  if (!s.data)
    return (
      <div className="panel">
        {s.error ? <ErrorNote error={s.error} /> : <Loading />}
      </div>
    );
  const f = s.data.fields;
  return (
    <div className="panel">
      <Chart
        title="CPU and memory"
        ts={s.data.ts}
        format={(v) => `${Math.round(v)}%`}
        min={0}
        max={100}
        series={[
          { label: "CPU", values: f.cpu, color: COLORS.blue, fill: true },
          { label: "Memory", values: f.mem, color: COLORS.orange },
        ]}
      />
      <Chart
        title="Clients"
        ts={s.data.ts}
        height={120}
        format={(v) => `${Math.round(v)}`}
        series={[
          {
            label: "Clients",
            values: f.num_sta,
            color: COLORS.green,
            fill: true,
          },
        ]}
      />
    </div>
  );
}

function UplinkChart({ mac, range }: { mac: string; range: TimeSpan }) {
  const s = useSeries("uplink", mac, range);
  if (!s.data)
    return (
      <div className="panel">
        {s.error ? <ErrorNote error={s.error} /> : <Loading />}
      </div>
    );
  const f = s.data.fields;
  const toBits = (a: (number | null)[]) =>
    a.map((v) => (v === null ? null : v * 8));
  return (
    <div className="panel">
      <Chart
        title="Uplink throughput"
        ts={s.data.ts}
        format={(v) => bitrate(v / 8)}
        series={[
          {
            label: "Download (to AP)",
            values: toBits(f.rx_bytes),
            color: COLORS.blue,
            fill: true,
          },
          {
            label: "Upload (from AP)",
            values: toBits(f.tx_bytes),
            color: COLORS.purple,
          },
        ]}
      />
      <Chart
        title="Uplink errors and drops"
        ts={s.data.ts}
        height={120}
        format={(v) => `${v.toFixed(v < 1 ? 2 : 0)}/s`}
        series={[
          { label: "RX errors", values: f.rx_errors, color: COLORS.red },
          { label: "TX errors", values: f.tx_errors, color: COLORS.orange },
          { label: "RX drops", values: f.rx_dropped, color: COLORS.purple },
        ]}
      />
    </div>
  );
}

const count = (n: number | null | undefined) =>
  n === null || n === undefined
    ? "—"
    : new Intl.NumberFormat("en-GB", { notation: "compact" }).format(n);
const share = (part: number, whole: number) =>
  whole > 0 ? `${((100 * part) / whole).toFixed(1)}%` : "—";

const SIGNAL_BUCKETS: [number, string, string][] = [
  [-60, "Excellent", "good"],
  [-67, "Good", "good"],
  [-75, "Fair", "fair"],
  [-200, "Poor", "poor"],
];

/** How many of the radio's clients are in each signal band. */
function SignalDistribution({ clients }: { clients: ClientView[] }) {
  const counts = SIGNAL_BUCKETS.map(([min], i) => {
    const max = i === 0 ? Infinity : SIGNAL_BUCKETS[i - 1][0];
    return clients.filter(
      (c) =>
        (c.sample.signal ?? -200) >= min && (c.sample.signal ?? -200) < max,
    ).length;
  });
  const total = clients.length;
  return (
    <div className="dist">
      <div className="dist-bar">
        {counts.map((n, i) =>
          n ? (
            <span
              key={i}
              className={`dist-${SIGNAL_BUCKETS[i][2]}`}
              style={{ flex: n }}
              title={`${SIGNAL_BUCKETS[i][1]}: ${n}`}
            />
          ) : null,
        )}
        {total === 0 && <span className="dist-empty" style={{ flex: 1 }} />}
      </div>
      <div className="dist-legend small muted">
        {SIGNAL_BUCKETS.map(([min, label], i) => (
          <span key={label}>
            {label} {i < 3 ? `≥ ${min}` : `< ${SIGNAL_BUCKETS[2][0]}`}:{" "}
            <b>{counts[i]}</b>
          </span>
        ))}
      </div>
    </div>
  );
}

function RadioPanel({
  mac,
  radio,
  vaps,
  clients,
  range,
}: {
  mac: string;
  radio: RadioSample;
  vaps: VapSample[];
  clients: ClientView[];
  range: TimeSpan;
}) {
  const s = useSeries("radio", `${mac},${radio.radio}`, range);
  const f = s.data?.fields;
  // The radio's own retry counters stay at zero on this firmware, so totals come from its SSIDs.
  const sum = (k: keyof VapSample) =>
    vaps.reduce((a, v) => a + ((v[k] as number | null) ?? 0), 0);
  const txPkts = sum("tx_packets");
  const retries = sum("tx_retries");
  const attempts = sum("wifi_tx_attempts");
  const dropped = sum("tx_dropped");
  const mcast =
    sum("tx_mcast") + sum("rx_mcast") + sum("tx_bcast") + sum("rx_bcast");
  const mcastShare = (100 * mcast) / Math.max(1, txPkts + sum("rx_packets"));
  const eirp =
    radio.tx_power !== null && radio.antenna_gain !== null
      ? radio.tx_power + radio.antenna_gain
      : null;
  return (
    <div className="panel">
      <div className="panel-head">
        <b>{band(radio.radio)}</b>
        <span className="muted">
          {radio.channel !== null
            ? `channel ${radio.channel} · ${radio.bw} MHz`
            : "no SSIDs on this radio"}{" "}
          · noise {radio.noise_floor} dBm
        </span>
      </div>
      <dl className="kv">
        <dt>TX power</dt>
        <dd>
          {radio.tx_power ?? "—"} dBm
          {eirp !== null && <span className="muted"> · {eirp} dBm EIRP</span>}
          {radio.min_txpower !== null && radio.max_txpower !== null && (
            <span className="muted small">
              {" "}
              (range {radio.min_txpower}–{radio.max_txpower})
            </span>
          )}
        </dd>
        <dt>Channel use now</dt>
        <dd>
          {radio.cu_total ?? "—"}% busy{" "}
          <span className="muted">
            · own RX {radio.cu_self_rx ?? "—"}% · own TX{" "}
            {radio.cu_self_tx ?? "—"}% · interference {radio.cu_interf ?? "—"}%
          </span>
        </dd>
        <dt>TX</dt>
        <dd>
          {count(txPkts)} packets · {bytes(sum("tx_bytes"))}
        </dd>
        <dt>RX</dt>
        <dd>
          {count(sum("rx_packets"))} packets · {bytes(sum("rx_bytes"))}
        </dd>
        <dt>TX retries</dt>
        <dd>{share(retries, retries + attempts + sum("wifi_tx_dropped"))}</dd>
        <dt>TX dropped</dt>
        <dd>{share(dropped, txPkts + dropped)}</dd>
        <dt>Multicast / broadcast</dt>
        <dd>
          <span
            className={mcastShare >= 30 ? "tone-warn" : ""}
            title="Share of all packets on this radio"
          >
            {mcastShare.toFixed(1)}% of packets
          </span>
          <span className="muted">
            {" "}
            · to clients {count(sum("tx_mcast") + sum("tx_bcast"))}, from
            clients {count(sum("rx_mcast") + sum("rx_bcast"))}
          </span>
        </dd>
        <dt>Clients ({clients.length})</dt>
        <dd>
          <SignalDistribution clients={clients} />
        </dd>
      </dl>
      <div className="muted small">Counters are since the AP last started.</div>
      {s.data && f ? (
        <Chart
          title="Airtime (channel utilisation)"
          ts={s.data.ts}
          format={(v) => `${Math.round(v)}%`}
          min={0}
          max={100}
          series={[
            {
              label: "Total",
              values: f.cu_total,
              color: COLORS.blue,
              fill: true,
            },
            { label: "Own RX", values: f.cu_self_rx, color: COLORS.green },
            { label: "Own TX", values: f.cu_self_tx, color: COLORS.purple },
            { label: "Interference", values: f.cu_interf, color: COLORS.red },
          ]}
        />
      ) : (
        <Loading />
      )}
    </div>
  );
}

/** Client activity, network performance and multicast for one radio, from its SSIDs' counters. */
function RadioActivity({
  mac,
  radio,
  range,
}: {
  mac: string;
  radio: string;
  range: TimeSpan;
}) {
  const a = useSiteActivity(range, radio, mac);
  if (!a.data)
    return (
      <div className="panel">
        {a.error ? <ErrorNote error={a.error} /> : <Loading />}
      </div>
    );
  const x = a.data.activity;
  return (
    <div className="panel">
      <div className="panel-head">
        <b>{band(radio)} activity</b>
      </div>
      <Chart
        title="Client activity"
        ts={x.ts}
        format={(v) => bitrate(v / 8)}
        formatRight={(v) => `${Math.round(v)}`}
        series={[
          {
            label: "To clients",
            values: x.download_bps,
            color: COLORS.blue,
            fill: true,
          },
          { label: "From clients", values: x.upload_bps, color: COLORS.purple },
          {
            label: "Clients",
            values: x.clients,
            color: COLORS.green,
            right: true,
            dashed: true,
          },
        ]}
      />
      <Chart
        title="Network performance"
        ts={x.ts}
        height={130}
        min={0}
        format={(v) => `${v.toFixed(v < 10 ? 1 : 0)}%`}
        series={[
          { label: "TX retries", values: x.tx_retry_pct, color: COLORS.orange },
          { label: "TX dropped", values: x.tx_dropped_pct, color: COLORS.red },
        ]}
      />
      <Chart
        title="Packets and multicast"
        ts={x.ts}
        height={130}
        format={(v) => `${v.toFixed(v < 10 ? 1 : 0)}/s`}
        formatRight={(v) => `${Math.round(v)}%`}
        rightMax={100}
        series={[
          { label: "TX packets", values: x.tx_pps, color: COLORS.blue },
          { label: "RX packets", values: x.rx_pps, color: COLORS.purple },
          {
            label: "Multicast + broadcast share",
            values: x.multicast_pct,
            color: COLORS.teal,
            right: true,
            dashed: true,
          },
        ]}
      />
    </div>
  );
}

function ActiveClients({ mac, range }: { mac: string; range: TimeSpan }) {
  const t = useSiteTop(range, mac);
  return (
    <div className="panel">
      <div className="panel-head">
        <b>Most active clients</b>
        <span className="muted small">on this AP, in the selected range</span>
      </div>
      {!t.data ? (
        <Loading />
      ) : t.data.clients.length === 0 ? (
        <div className="muted small">No client traffic in this range.</div>
      ) : (
        <table className="table">
          <thead>
            <tr>
              <th>Client</th>
              <th>Vendor</th>
              <th>Download</th>
              <th>Upload</th>
            </tr>
          </thead>
          <tbody>
            {t.data.clients.slice(0, 10).map((c) => (
              <tr key={c.mac}>
                <td>
                  <Link to={`/clients/${c.mac}`}>{c.name ?? c.mac}</Link>
                  {c.connected === false && (
                    <span className="muted small"> (gone)</span>
                  )}
                </td>
                <td className="small">{c.vendor ?? "—"}</td>
                <td>{bytes(c.download_bytes)}</td>
                <td>{bytes(c.upload_bytes)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

function VapTable({ vaps, range }: { vaps: VapSample[]; range: TimeSpan }) {
  const [open, setOpen] = useState<string | null>(null);
  return (
    <div className="panel">
      <table className="table">
        <thead>
          <tr>
            <th>SSID</th>
            <th>Band</th>
            <th>Clients</th>
            <th>Avg signal</th>
            <th>Satisfaction</th>
            <th>BSSID</th>
          </tr>
        </thead>
        <tbody>
          {vaps.map((v) => (
            <VapRow
              key={v.bssid}
              vap={v}
              open={open === v.bssid}
              toggle={() => setOpen(open === v.bssid ? null : v.bssid)}
              range={range}
            />
          ))}
        </tbody>
      </table>
    </div>
  );
}

function VapRow({
  vap,
  open,
  toggle,
  range,
}: {
  vap: VapSample;
  open: boolean;
  toggle: () => void;
  range: TimeSpan;
}) {
  return (
    <>
      <tr className="clickable" onClick={toggle}>
        <td>
          {open ? "▾" : "▸"} {vap.essid}
        </td>
        <td>
          {band(vap.radio)} ch {vap.channel}
        </td>
        <td>{vap.num_sta}</td>
        <td>
          <Signal dbm={vap.avg_client_signal} />
        </td>
        <td>{vap.satisfaction ?? "—"}</td>
        <td className="mono muted">{vap.bssid}</td>
      </tr>
      {open && (
        <tr>
          <td colSpan={6}>
            <VapChart bssid={vap.bssid} range={range} />
          </td>
        </tr>
      )}
    </>
  );
}

function VapChart({ bssid, range }: { bssid: string; range: TimeSpan }) {
  const s = useSeries("vap", bssid, range);
  if (!s.data) return <Loading />;
  const f = s.data.fields;
  const toBits = (a: (number | null)[]) =>
    a.map((v) => (v === null ? null : v * 8));
  return (
    <Chart
      title="SSID traffic on this radio"
      ts={s.data.ts}
      format={(v) => bitrate(v / 8)}
      series={[
        {
          label: "To clients",
          values: toBits(f.tx_bytes),
          color: COLORS.blue,
          fill: true,
        },
        {
          label: "From clients",
          values: toBits(f.rx_bytes),
          color: COLORS.purple,
        },
      ]}
    />
  );
}
