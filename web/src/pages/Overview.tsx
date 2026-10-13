import { Link } from "react-router-dom";
import { useClients, useDevices, useEvents, useStatus } from "../api";
import { Dot, ErrorNote, EventList, Loading, Meter, Stat, clientNames, deviceNames } from "../components/common";
import { ago, band, duration, pct } from "../format";
import { ApDensity, Connectivity, RetryBuckets, SiteActivity, TopTalkers } from "../components/Insights";

export function Overview() {
  const devices = useDevices();
  const clients = useClients();
  const events = useEvents({ limit: 30 });
  const status = useStatus();
  const names = deviceNames(devices.data);
  const cnames = clientNames(clients.data);

  if (devices.isLoading) return <Loading />;
  if (devices.error) return <ErrorNote error={devices.error} />;
  const list = devices.data ?? [];
  const connected = (clients.data ?? []).filter((c) => c.connected);
  const byBand = new Map<string, number>();
  for (const c of connected) byBand.set(band(c.sample.radio), (byBand.get(band(c.sample.radio)) ?? 0) + 1);
  const weak = connected.filter((c) => (c.sample.signal ?? 0) < -75).length;

  return (
    <div className="page">
      <div className="stats">
        <Stat label="Access points" value={`${list.filter((d) => d.online).length} / ${list.length}`} sub="online" />
        <Stat
          label="Clients"
          value={connected.length}
          sub={[...byBand.entries()].map(([b, n]) => `${n} on ${b}`).join(" · ") || "none connected"}
        />
        <Stat label="Weak signal" value={weak} sub="clients below −75 dBm" />
        <Stat
          label="Shadow feed"
          value={status.data ? status.data.counters.informs : "—"}
          sub={status.data ? `informs since start, ${status.data.counters.decode_errors} errors` : ""}
        />
      </div>

      <h2>Activity</h2>
      <SiteActivity />
      <div className="grid2">
        <TopTalkers />
        <div className="stack">
          <RetryBuckets />
          <Connectivity />
        </div>
      </div>
      <div className="grid1">
        <ApDensity />
      </div>

      <h2>Access points</h2>
      <div className="cards">
        {list.map((d) => (
          <Link key={d.mac} to={`/devices/${d.mac}`} className="card card-link">
            <div className="card-head">
              <Dot ok={d.online} warn={d.reconfiguring} />
              <span className="card-title" title={d.name ?? d.mac}>
                {d.name ?? d.mac}
              </span>
              <span className="muted">{d.model_display ?? d.model}</span>
            </div>
            <div className="kv">
              <span>Clients</span>
              <b>{d.clients}</b>
              <span>CPU</span>
              <span className="meter-row">
                <Meter value={d.cpu} /> {pct(d.cpu)}
              </span>
              <span>Memory</span>
              <span className="meter-row">
                <Meter value={d.mem} /> {pct(d.mem)}
              </span>
              {d.radios
                .filter((r) => r.channel !== null)
                .map((r) => (
                  <RadioRow key={r.radio} band={band(r.radio)} channel={r.channel} bw={r.bw} util={r.cu_total} clients={r.clients} />
                ))}
              <span>Uplink</span>
              <span>{d.uplink?.speed ? `${d.uplink.speed} Mbps${d.uplink.full_duplex ? " FD" : ""}` : "—"}</span>
              <span>Uptime</span>
              <span>{duration(d.uptime)}</span>
            </div>
            <div className="card-foot muted" title={`${d.version} · ${d.ip}`}>
              {d.version} · {d.ip} · {d.online ? `seen ${ago(d.last_seen)}` : `offline since ${ago(d.last_seen)}`}
            </div>
          </Link>
        ))}
      </div>

      <h2>Recent events</h2>
      <div className="panel">{events.data ? <EventList events={events.data} names={names} clientNames={cnames} /> : <Loading />}</div>
    </div>
  );
}

function RadioRow(p: { band: string; channel: number | null; bw: number | null; util: number | null; clients: number }) {
  return (
    <>
      <span>{p.band}</span>
      <span className="meter-row" title={`Channel utilisation ${p.util ?? "?"}% · channel ${p.channel}, ${p.bw} MHz · ${p.clients} clients`}>
        <Meter value={p.util} />
        <span className="meter-text">
          ch {p.channel} · {p.bw} MHz · {p.clients} {p.clients === 1 ? "client" : "clients"}
        </span>
      </span>
    </>
  );
}
