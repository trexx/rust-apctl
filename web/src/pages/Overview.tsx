import { Suspense } from "react";
import { Link } from "react-router";
import {
  useClientNames,
  useDeviceNames,
  useCanEdit,
  useDevices,
  useEvents,
  useStatus,
} from "../api";
import type { DeviceSummary } from "../api";
import {
  Dot,
  EventList,
  Meter,
  QueryNote,
  QueryState,
  Stat,
} from "../components/common";
import {
  SIGNAL,
  ago,
  band,
  dbm,
  duration,
  pct,
  unit,
  uplinkText,
  useNow,
} from "../format";
import { Connectivity } from "../components/insights/Connectivity";
import { DeploymentDensity } from "../components/insights/DeploymentDensity";
import { MulticastPanel } from "../components/insights/Multicast";
import { RetryBuckets } from "../components/insights/RetryBuckets";
import { SiteActivity } from "../components/insights/SiteActivity";
import { TopTalkers } from "../components/insights/TopTalkers";
import { useTimeSpan } from "../components/Chart";
import { SpanScope } from "../components/span";
import { ThreatBanner } from "../components/Threats";
import { lazyNamed } from "../lazy";

/** An AP's firmware and address, as far as they are known. */
const about = (d: DeviceSummary) =>
  [d.version, d.ip].filter(Boolean).join(" · ");

// Only editors in active mode adopt APs: everyone else never loads the panel.
const AdoptionPanel = lazyNamed(
  () => import("../components/Adoption"),
  "AdoptionPanel",
);

export function Overview() {
  const devices = useDevices();
  const events = useEvents({ limit: 12 });
  // Also the client counters: the server counts them, so the overview needs no client list.
  const status = useStatus(true);
  const s = status.data;
  const names = useDeviceNames();
  const canEdit = useCanEdit();
  const cnames = useClientNames();
  const now = useNow();

  if (!devices.data) return <QueryNote q={devices} />;
  const list = devices.data;

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
          label={s?.mode === "shadow" ? "Shadow feed" : "AP reports"}
          value={s ? s.counters.informs : "—"}
          sub={
            s
              ? `informs since start, ${s.counters.decode_errors} errors`
              : ""
          }
        />
      </div>

      <ThreatBanner />
      {canEdit && s?.mode === "active" && (
        <Suspense fallback={null}>
          <AdoptionPanel />
        </Suspense>
      )}
      <h2>Access points</h2>
      <div className="cards cards-fill">
        {list.map((d) => (
          <Link key={d.mac} to={`/devices/${d.mac}`} className="card card-link">
            <div className="card-head">
              <Dot ok={d.online} />
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
                <Meter value={d.cpu} label="CPU" /> {pct(d.cpu)}
              </span>
              <span>Memory</span>
              <span className="meter-row">
                <Meter value={d.mem} label="Memory" /> {pct(d.mem)}
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
              <span>{d.uplink ? uplinkText(d.uplink) : "—"}</span>
              <span>Uptime</span>
              <span>{duration(d.uptime)}</span>
            </div>
            <div className="card-foot muted" title={about(d) || undefined}>
              {about(d) && `${about(d)} · `}
              {d.online
                ? `seen ${ago(d.last_seen, now)}`
                : `offline since ${ago(d.last_seen, now)}`}
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
        title={`Channel utilisation ${pct(p.util)} · channel ${p.channel ?? "—"}, ${unit(p.bw, "MHz")} · ${p.clients} clients`}
      >
        <Meter value={p.util} label={`${p.band} channel utilisation`} />
        <span className="meter-text">
          ch {p.channel ?? "—"} · {unit(p.bw, "MHz")} · {p.clients}{" "}
          {p.clients === 1 ? "client" : "clients"}
        </span>
      </span>
    </>
  );
}

/** Outside SiteActivity's zoom: dragging across its chart zooms the page all the same. */
function SiteMulticast() {
  const [span, setSpan] = useTimeSpan(86400);
  return (
    <SpanScope span={span} onSpan={setSpan}>
      <MulticastPanel span={span} />
    </SpanScope>
  );
}
