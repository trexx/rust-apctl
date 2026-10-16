import { Link } from "react-router-dom";
import {
  useClientNames,
  useDeviceNames,
  useDevices,
  useEvents,
  useStatus,
} from "../api";
import {
  Dot,
  ErrorNote,
  EventList,
  Loading,
  Meter,
  QueryState,
  Stat,
} from "../components/common";
import { SIGNAL, ago, band, dbm, duration, pct } from "../format";
import { Connectivity } from "../components/insights/Connectivity";
import { DeploymentDensity } from "../components/insights/DeploymentDensity";
import { MulticastPanel } from "../components/insights/Multicast";
import { RetryBuckets } from "../components/insights/RetryBuckets";
import { SiteActivity } from "../components/insights/SiteActivity";
import { TopTalkers } from "../components/insights/TopTalkers";
import { useTimeSpan } from "../components/Chart";
import { ThreatBanner } from "../components/Threats";
import { AdoptionPanel } from "../components/Adoption";

export function Overview() {
  const devices = useDevices();
  const events = useEvents({ limit: 12 });
  // Also the client counters: the server counts them, so the overview needs no client list.
  const status = useStatus(true);
  const s = status.data;
  const names = useDeviceNames();
  const cnames = useClientNames();

  if (devices.isLoading) return <Loading />;
  if (devices.error) return <ErrorNote error={devices.error} />;
  const list = devices.data ?? [];

  return (
    <div className="page">
      <div className="stats">
        <Stat
          label="Access points"
          value={`${list.filter((d) => d.online).length} / ${list.length}`}
          sub="online"
        />
        <Stat
          label="Clients"
          value={s?.clients_connected ?? 0}
          sub={
            Object.entries(s?.clients_by_band ?? {})
              .map(([r, n]) => `${n} on ${band(r)}`)
              .join(" · ") || "none connected"
          }
        />
        <Stat
          label="Weak signal"
          value={s?.clients_weak ?? 0}
          sub={`clients below ${dbm(SIGNAL.fair)}`}
        />
        <Stat
          label="Shadow feed"
          value={status.data ? status.data.counters.informs : "—"}
          sub={
            status.data
              ? `informs since start, ${status.data.counters.decode_errors} errors`
              : ""
          }
        />
      </div>

      <ThreatBanner />
      <AdoptionPanel />
      <h2>Access points</h2>
      <div className="cards cards-fill">
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
                  <RadioRow
                    key={r.radio}
                    band={band(r.radio)}
                    channel={r.channel}
                    bw={r.bw}
                    util={r.cu_total}
                    clients={r.clients}
                  />
                ))}
              <span>Uplink</span>
              <span>
                {d.uplink?.speed
                  ? `${d.uplink.speed} Mbps${d.uplink.full_duplex ? " FD" : ""}`
                  : "—"}
              </span>
              <span>Uptime</span>
              <span>{duration(d.uptime)}</span>
            </div>
            <div className="card-foot muted" title={`${d.version} · ${d.ip}`}>
              {d.version} · {d.ip} ·{" "}
              {d.online
                ? `seen ${ago(d.last_seen)}`
                : `offline since ${ago(d.last_seen)}`}
            </div>
          </Link>
        ))}
      </div>

      <h2>Activity</h2>
      <SiteActivity />
      <div className="grid3">
        <RetryBuckets />
        <Connectivity />
        <DeploymentDensity />
      </div>
      <div className="grid1">
        <TopTalkers />
      </div>
      <div className="grid1">
        <SiteMulticast />
      </div>

      <h2>
        Recent events{" "}
        <Link to="/events" className="small">
          all events →
        </Link>
      </h2>
      <div className="panel">
        <QueryState q={events}>
          {(data) => (
            <EventList events={data} names={names} clientNames={cnames} />
          )}
        </QueryState>
      </div>
    </div>
  );
}

function RadioRow(p: {
  band: string;
  channel: number | null;
  bw: number | null;
  util: number | null;
  clients: number;
}) {
  return (
    <>
      <span>{p.band}</span>
      <span
        className="meter-row"
        title={`Channel utilisation ${p.util ?? "?"}% · channel ${p.channel}, ${p.bw} MHz · ${p.clients} clients`}
      >
        <Meter value={p.util} />
        <span className="meter-text">
          ch {p.channel} · {p.bw} MHz · {p.clients}{" "}
          {p.clients === 1 ? "client" : "clients"}
        </span>
      </span>
    </>
  );
}

function SiteMulticast() {
  const [span] = useTimeSpan(86400);
  return <MulticastPanel span={span} />;
}
