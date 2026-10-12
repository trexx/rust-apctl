import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useClients, useDevice, useDevices, useEvents, useLogs, useSeries } from "../api";
import type { RadioSample, VapSample } from "../api";
import { COLORS, Chart, RangePicker } from "../components/Chart";
import { Dot, ErrorNote, EventList, Loading, LogList, Signal, Stat, clientNames, deviceNames } from "../components/common";
import { ago, band, bitrate, duration, pct, phy } from "../format";

export function Device() {
  const { mac = "" } = useParams();
  const [range, setRange] = useState(6 * 3600);
  const detail = useDevice(mac);
  const devices = useDevices();
  const names = deviceNames(devices.data);
  const cnames = clientNames(useClients().data);
  const events = useEvents({ device: mac, limit: 50 });
  const logs = useLogs({ device: mac, limit: 100 });

  if (detail.isLoading) return <Loading />;
  if (detail.error || !detail.data) return <ErrorNote error={detail.error ?? "Unknown device"} />;
  const { device: d, clients } = detail.data;
  const ap = d.snapshot.ap;

  return (
    <div className="page">
      <div className="page-head">
        <h1>
          <Dot ok={d.online} warn={d.reconfiguring} /> {ap.hostname ?? mac}
        </h1>
        <span className="muted">
          {ap.model_display ?? ap.model} · {ap.version} · {ap.ip} · <span className="mono">{mac}</span>
        </span>
        <span className="spacer" />
        <RangePicker value={range} onChange={setRange} />
      </div>
      {d.reconfiguring && <div className="banner">Radios are restarting after a configuration change. Client data resumes shortly.</div>}

      <div className="stats">
        <Stat label="Status" value={d.online ? "Online" : "Offline"} sub={`seen ${ago(d.last_seen)}, every ~${d.interval}s`} />
        <Stat label="Uptime" value={duration(ap.uptime)} />
        <Stat label="CPU / memory" value={`${pct(ap.cpu)} / ${pct(ap.mem)}`} sub={`load ${ap.load1 ?? "—"} · ${ap.load5 ?? "—"} · ${ap.load15 ?? "—"}`} />
        <Stat label="Clients" value={clients.length} sub={`satisfaction ${ap.satisfaction ?? "—"}`} />
      </div>

      <div className="grid2">
        <ApCharts mac={mac} range={range} />
        <UplinkChart mac={mac} range={range} />
      </div>

      <h2>Radios</h2>
      <div className="grid2">
        {d.snapshot.radios.map((r) => (
          <RadioPanel key={r.radio} mac={mac} radio={r} range={range} />
        ))}
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
              .sort((a, b) => (b.sample.signal ?? -100) - (a.sample.signal ?? -100))
              .map((c) => (
                <tr key={c.sample.mac}>
                  <td>
                    <Link to={`/clients/${c.sample.mac}`}>{c.sample.hostname ?? c.sample.mac}</Link>
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
          <div className="panel scroll">{events.data ? <EventList events={events.data} names={names} clientNames={cnames} showDevice={false} /> : <Loading />}</div>
        </div>
        <div>
          <h2>
            Logs <Link to={`/logs?device=${mac}`} className="small">all logs →</Link>
          </h2>
          <div className="panel scroll">{logs.data ? <LogList logs={logs.data} names={names} showDevice={false} /> : <Loading />}</div>
        </div>
      </div>
    </div>
  );
}

function ApCharts({ mac, range }: { mac: string; range: number }) {
  const s = useSeries("ap", mac, range);
  if (!s.data) return <div className="panel">{s.error ? <ErrorNote error={s.error} /> : <Loading />}</div>;
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
        series={[{ label: "Clients", values: f.num_sta, color: COLORS.green, fill: true }]}
      />
    </div>
  );
}

function UplinkChart({ mac, range }: { mac: string; range: number }) {
  const s = useSeries("uplink", mac, range);
  if (!s.data) return <div className="panel">{s.error ? <ErrorNote error={s.error} /> : <Loading />}</div>;
  const f = s.data.fields;
  const toBits = (a: (number | null)[]) => a.map((v) => (v === null ? null : v * 8));
  return (
    <div className="panel">
      <Chart
        title="Uplink throughput"
        ts={s.data.ts}
        format={(v) => bitrate(v / 8)}
        series={[
          { label: "Download (to AP)", values: toBits(f.rx_bytes), color: COLORS.blue, fill: true },
          { label: "Upload (from AP)", values: toBits(f.tx_bytes), color: COLORS.purple },
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

function RadioPanel({ mac, radio, range }: { mac: string; radio: RadioSample; range: number }) {
  const s = useSeries("radio", `${mac},${radio.radio}`, range);
  const f = s.data?.fields;
  return (
    <div className="panel">
      <div className="panel-head">
        <b>{band(radio.radio)}</b>
        <span className="muted">
          {radio.channel !== null ? `channel ${radio.channel} · ${radio.bw} MHz · ${radio.tx_power} dBm` : "no SSIDs on this radio"} · noise{" "}
          {radio.noise_floor} dBm
        </span>
      </div>
      {s.data && f ? (
        <>
          <Chart
            title="Channel utilisation"
            ts={s.data.ts}
            format={(v) => `${Math.round(v)}%`}
            min={0}
            max={100}
            series={[
              { label: "Total", values: f.cu_total, color: COLORS.blue, fill: true },
              { label: "Own RX", values: f.cu_self_rx, color: COLORS.green },
              { label: "Own TX", values: f.cu_self_tx, color: COLORS.purple },
              { label: "Interference", values: f.cu_interf, color: COLORS.red },
            ]}
          />
          <Chart
            title="Retries"
            ts={s.data.ts}
            height={120}
            format={(v) => `${v.toFixed(v < 10 ? 1 : 0)}/s`}
            series={[
              { label: "TX packets", values: f.tx_packets, color: COLORS.teal },
              { label: "TX retries", values: f.tx_retries, color: COLORS.orange },
            ]}
          />
        </>
      ) : (
        <Loading />
      )}
    </div>
  );
}

function VapTable({ vaps, range }: { vaps: VapSample[]; range: number }) {
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
            <VapRow key={v.bssid} vap={v} open={open === v.bssid} toggle={() => setOpen(open === v.bssid ? null : v.bssid)} range={range} />
          ))}
        </tbody>
      </table>
    </div>
  );
}

function VapRow({ vap, open, toggle, range }: { vap: VapSample; open: boolean; toggle: () => void; range: number }) {
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

function VapChart({ bssid, range }: { bssid: string; range: number }) {
  const s = useSeries("vap", bssid, range);
  if (!s.data) return <Loading />;
  const f = s.data.fields;
  const toBits = (a: (number | null)[]) => a.map((v) => (v === null ? null : v * 8));
  return (
    <Chart
      title="SSID traffic on this radio"
      ts={s.data.ts}
      format={(v) => bitrate(v / 8)}
      series={[
        { label: "To clients", values: toBits(f.tx_bytes), color: COLORS.blue, fill: true },
        { label: "From clients", values: toBits(f.rx_bytes), color: COLORS.purple },
      ]}
    />
  );
}
