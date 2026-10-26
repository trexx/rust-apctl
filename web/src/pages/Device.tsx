import { Suspense } from "react";
import { Link, Navigate, useLocation, useParams } from "react-router";
import {
  useCanEdit,
  useClientNames,
  useDevice,
  useDeviceNames,
  useEvents,
  useLogs,
  useSeries,
  useSiteTop,
} from "../api";
import type { TimeSpan } from "../api";
import { COLORS, Chart, SpanPage, useTimeSpan } from "../components/Chart";
import {
  Dot,
  EventList,
  LogList,
  QueryNote,
  QueryState,
  Signal,
  Stat,
  THead,
} from "../components/common";
import {
  ago,
  bandChannel,
  bytes,
  canonicalMac,
  compact,
  duration,
  pct,
  rate,
  rates,
  uplinkText,
  useNow,
} from "../format";
import { MulticastPanel } from "../components/insights/Multicast";
import {
  RadioActivity,
  RadioPanel,
  VapTable,
} from "../components/DeviceRadios";
import { DeviceActions } from "../components/Actions";
import { lazyNamed } from "../lazy";

// The settings editor is large and only used by those who can edit: load it on demand.
const DeviceSettingsPanel = lazyNamed(
  () => import("../components/SettingsEditor"),
  "DeviceSettingsPanel",
);

/**
 * Keyed by MAC: nothing typed or shown for one AP carries over to the next
 * (Back, a link), so one AP's settings edits are never diffed against, and
 * saved to, another.
 */
export function Device() {
  const typed = useParams().mac ?? "";
  const { search } = useLocation();
  // A MAC pasted in another form: the series, live updates and names all key by this one.
  const mac = canonicalMac(typed);
  if (mac !== typed)
    return <Navigate replace to={{ pathname: `/devices/${mac}`, search }} />;
  return <DevicePage key={mac} mac={mac} />;
}

function DevicePage({ mac }: { mac: string }) {
  const [range, setRange] = useTimeSpan(6 * 3600);
  const detail = useDevice(mac);
  const cnames = useClientNames();
  const now = useNow();
  // Read-only users get neither the editor's code nor the AP's settings.
  const canEdit = useCanEdit();

  if (!detail.data) return <QueryNote q={detail} />;
  const { device: d, clients } = detail.data;
  const ap = d.snapshot.ap;
  const up = d.snapshot.uplink;
  // A stored AP not heard from yet may know neither its firmware nor its address.
  const about = [ap.model_display ?? ap.model, ap.version, ap.ip]
    .filter(Boolean)
    .join(" · ");

  return (
    <SpanPage
      span={range}
      onSpan={setRange}
      head={
        <>
          <h1>
            <Dot ok={d.online} /> {ap.hostname ?? mac}
          </h1>
          <span className="muted">
            {about && `${about} · `}
            <span className="mono">{mac}</span>
          </span>
        </>
      }
    >
      <DeviceActions
        mac={mac}
        name={ap.hostname ?? mac}
        online={d.online}
        locating={detail.data.locating}
      />
      {canEdit && (
        <Suspense fallback={null}>
          <DeviceSettingsPanel mac={mac} />
        </Suspense>
      )}
      {d.stored_only && (
        <div className="banner">
          This AP hasn't reported since apctl started, so only its stored
          details and history are shown. Radios and clients appear with its next
          report.
        </div>
      )}

      <div className="stats">
        <Stat
          label="Status"
          value={d.online ? "Online" : "Offline"}
          sub={
            d.interval
              ? `seen ${ago(d.last_seen, now)}, every ~${d.interval}s`
              : `last seen ${ago(d.last_seen, now)}`
          }
        />
        <Stat label="Uptime" value={duration(ap.uptime)} />
        <Stat
          label="CPU"
          value={pct(ap.cpu)}
          sub={`load ${ap.load1 ?? "—"} · ${ap.load5 ?? "—"} · ${ap.load15 ?? "—"}`}
        />
        <Stat
          label="Memory"
          value={pct(ap.mem)}
          sub={`${bytes(ap.mem_used)} of ${bytes(ap.mem_total)}`}
        />
        <Stat
          label="Clients"
          value={clients.length}
          sub={`satisfaction ${ap.satisfaction ?? "—"}`}
        />
        {up && (
          <Stat
            label={`Uplink ${up.ifname}`}
            value={uplinkText(up)}
            sub={`${bytes(up.rx_bytes)} received, ${bytes(up.tx_bytes)} sent · packets ${compact(up.rx_packets)} in, ${compact(up.tx_packets)} out · since start`}
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
          <THead
            columns={[
              "Client",
              "SSID",
              "Band",
              "Signal",
              "Rate (down/up)",
              "Connected",
            ]}
          />
          <tbody>
            {clients
              .slice()
              .sort(
                (a, b) => (b.sample.signal ?? -100) - (a.sample.signal ?? -100),
              )
              .map((c) => (
                <tr key={c.sample.mac}>
                  <td>
                    <Link to={`/clients/${c.sample.mac}`}>
                      {cnames[c.sample.mac] ?? c.sample.mac}
                    </Link>
                  </td>
                  <td>{c.sample.essid ?? "—"}</td>
                  <td>{bandChannel(c.sample.radio, c.sample.channel)}</td>
                  <td>
                    <Signal dbm={c.sample.signal} />
                  </td>
                  <td>{rates(c.sample)}</td>
                  <td>{duration(c.sample.uptime)}</td>
                </tr>
              ))}
          </tbody>
        </table>
      </div>

      <div className="grid2">
        <DeviceEvents mac={mac} />
        <DeviceLogs mac={mac} />
      </div>
    </SpanPage>
  );
}

function DeviceEvents({ mac }: { mac: string }) {
  const events = useEvents({ device: mac, limit: 50 });
  const names = useDeviceNames();
  const cnames = useClientNames();
  return (
    <div>
      <h2>Events</h2>
      <div className="panel scroll">
        <QueryState q={events}>
          {(data) => (
            <EventList
              events={data}
              names={names}
              clientNames={cnames}
              showDevice={false}
            />
          )}
        </QueryState>
      </div>
    </div>
  );
}

function DeviceLogs({ mac }: { mac: string }) {
  const logs = useLogs({ device: mac, limit: 100 });
  const names = useDeviceNames();
  return (
    <div>
      <h2>
        Logs{" "}
        <Link to={`/logs?device=${mac}`} className="small">
          all logs →
        </Link>
      </h2>
      <div className="panel scroll">
        <QueryState q={logs}>
          {(data) => <LogList logs={data} names={names} showDevice={false} />}
        </QueryState>
      </div>
    </div>
  );
}

function ApCharts({ mac, range }: { mac: string; range: TimeSpan }) {
  const s = useSeries("ap", mac, range, ["cpu", "mem", "num_sta"]);
  return (
    <QueryState q={s} panel>
      {({ ts, fields: f }) => (
        <div className="panel">
          <Chart
            title="CPU and memory"
            ts={ts}
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
            ts={ts}
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
      )}
    </QueryState>
  );
}

function UplinkChart({ mac, range }: { mac: string; range: TimeSpan }) {
  const s = useSeries("uplink", mac, range, [
    "rx_bytes",
    "tx_bytes",
    "rx_errors",
    "tx_errors",
    "rx_dropped",
  ]);
  return (
    <QueryState q={s} panel>
      {({ ts, fields: f }) => (
        <div className="panel">
          <Chart
            title="Uplink throughput"
            ts={ts}
            format={rate}
            series={[
              {
                label: "Download (to AP)",
                values: f.rx_bytes,
                scale: 8,
                color: COLORS.blue,
                fill: true,
              },
              {
                label: "Upload (from AP)",
                values: f.tx_bytes,
                scale: 8,
                color: COLORS.purple,
              },
            ]}
          />
          <Chart
            title="Uplink errors and drops"
            ts={ts}
            height={120}
            format={(v) => `${v.toFixed(v < 1 ? 2 : 0)}/s`}
            series={[
              { label: "RX errors", values: f.rx_errors, color: COLORS.red },
              { label: "TX errors", values: f.tx_errors, color: COLORS.orange },
              { label: "RX drops", values: f.rx_dropped, color: COLORS.purple },
            ]}
          />
        </div>
      )}
    </QueryState>
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
      <QueryState q={t}>
        {(data) =>
          data.clients.length === 0 ? (
            <div className="muted small">No client traffic in this range.</div>
          ) : (
            <table className="table">
              <THead columns={["Client", "Vendor", "Download", "Upload"]} />
              <tbody>
                {data.clients.map((c) => (
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
          )
        }
      </QueryState>
    </div>
  );
}
