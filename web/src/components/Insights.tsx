import { useState } from "react";
import { Link } from "react-router-dom";
import { useConnectivity, useNeighbors, useRadios, useSiteActivity, useSiteTop } from "../api";
import { bitrate, bytes } from "../format";
import { COLORS, Chart, RangePicker } from "./Chart";
import { Loading } from "./common";

export function BandPicker({ value, onChange, all = true }: { value: string; onChange: (b: string) => void; all?: boolean }) {
  const bands = [...(all ? [["all", "All radios"]] : []), ["ng", "2.4 GHz"], ["na", "5 GHz"]];
  return (
    <div className="segmented" role="group" aria-label="Band">
      {bands.map(([v, l]) => (
        <button key={v} className={value === v ? "active" : ""} onClick={() => onChange(v)}>
          {l}
        </button>
      ))}
    </div>
  );
}

/** Site-wide Wi-Fi activity and airtime, the first thing on the overview. */
export function SiteActivity() {
  const [view, setView] = useState<"activity" | "airtime">("activity");
  const [range, setRange] = useState(86400);
  const [band, setBand] = useState("all");
  const a = useSiteActivity(range, band);
  return (
    <div className="panel">
      <div className="panel-head">
        <div className="segmented" role="group" aria-label="View">
          <button className={view === "activity" ? "active" : ""} onClick={() => setView("activity")}>
            Activity
          </button>
          <button className={view === "airtime" ? "active" : ""} onClick={() => setView("airtime")}>
            Airtime
          </button>
        </div>
        <BandPicker value={band} onChange={setBand} />
        <span className="spacer" />
        <RangePicker value={range} onChange={setRange} />
      </div>
      {!a.data ? (
        <Loading />
      ) : view === "activity" ? (
        <>
          <Chart
            title="Wi-Fi traffic"
            ts={a.data.activity.ts}
            height={200}
            format={(v) => bitrate(v / 8)}
            formatRight={(v) => `${Math.round(v)}`}
            series={[
              { label: "Download", values: a.data.activity.download_bps, color: COLORS.blue, fill: true },
              { label: "Upload", values: a.data.activity.upload_bps, color: COLORS.purple },
              { label: "Clients", values: a.data.activity.clients, color: COLORS.green, right: true, dashed: true },
            ]}
          />
          <Chart
            title="TX retries and multicast"
            ts={a.data.activity.ts}
            height={120}
            min={0}
            format={(v) => `${v.toFixed(0)}%`}
            series={[
              { label: "TX retries", values: a.data.activity.tx_retry_pct, color: COLORS.orange },
              { label: "Multicast share", values: a.data.activity.multicast_pct, color: COLORS.teal, dashed: true },
            ]}
          />
        </>
      ) : (
        <Chart
          title="Airtime (channel utilisation, average across radios)"
          ts={a.data.airtime.ts}
          height={240}
          min={0}
          format={(v) => `${v.toFixed(0)}%`}
          series={[
            { label: "Total", values: a.data.airtime.total, color: COLORS.orange, fill: true },
            { label: "Own traffic", values: a.data.airtime.own_traffic, color: COLORS.blue },
            { label: "External interference", values: a.data.airtime.external_interference, color: COLORS.red },
          ]}
        />
      )}
    </div>
  );
}

function TopList({ title, items, link }: { title: string; items: { mac: string; name: string | null; sub?: string | null; total: number }[]; link: string }) {
  return (
    <div className="top-list">
      <div className="muted small">{title}</div>
      <div className="chips">
        {items.map((i) => (
          <Link key={i.mac} to={`/${link}/${i.mac}`} className="chip" title={i.sub ?? undefined}>
            <span className="chip-name">{i.name ?? i.mac}</span>
            <span className="muted small">{bytes(i.total)}</span>
          </Link>
        ))}
        {items.length === 0 && <span className="muted small">No traffic in this range</span>}
      </div>
    </div>
  );
}

export function TopTalkers({ range = 86400 }: { range?: number }) {
  const t = useSiteTop(range);
  if (!t.data) return <Loading />;
  const total = (x: { download_bytes: number; upload_bytes: number }) => x.download_bytes + x.upload_bytes;
  return (
    <div className="panel">
      <div className="panel-head">
        <b>Top traffic</b>
        <span className="muted small">last 24 hours</span>
      </div>
      <TopList title="Access points" link="devices" items={t.data.aps.map((a) => ({ mac: a.mac, name: a.name, total: total(a) }))} />
      <TopList
        title="Clients"
        link="clients"
        items={t.data.clients.slice(0, 15).map((c) => ({ mac: c.mac, name: c.name, sub: c.vendor, total: total(c) }))}
      />
    </div>
  );
}

const RETRY_BUCKETS: [number, string][] = [
  [35, "35%+"],
  [25, "25%"],
  [20, "20%"],
  [15, "15%"],
  [10, "10%"],
  [5, "5%"],
  [0, "0%"],
];

export function RetryBuckets() {
  const [band, setBand] = useState("na");
  const r = useRadios(86400);
  if (!r.data) return <Loading />;
  const radios = r.data.filter((x) => x.radio === band && x.tx_retry_pct !== null);
  return (
    <div className="panel">
      <div className="panel-head">
        <b>AP radio TX retries</b>
        <span className="muted small">last 24 hours</span>
        <span className="spacer" />
        <BandPicker value={band} onChange={setBand} all={false} />
      </div>
      <div className="buckets">
        {RETRY_BUCKETS.map(([min, label], i) => {
          const upper = i === 0 ? Infinity : RETRY_BUCKETS[i - 1][0];
          const inBucket = radios.filter((x) => (x.tx_retry_pct ?? 0) >= min && (x.tx_retry_pct ?? 0) < upper);
          const tone = min >= 25 ? "bad" : min >= 15 ? "warn" : "good";
          return (
            <div key={label} className="bucket">
              <div className={`bucket-bar ${inBucket.length ? `bucket-${tone}` : ""}`} title={inBucket.map((x) => `${x.name}: ${x.tx_retry_pct?.toFixed(1)}%`).join("\n")}>
                {inBucket.length || ""}
              </div>
              <div className="muted small">{label}</div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

const STAGE_LABELS: Record<string, string> = { association: "Association", authentication: "Authentication", dhcp: "DHCP", dns: "DNS" };

export function Connectivity() {
  const c = useConnectivity(86400, "all");
  if (!c.data) return <Loading />;
  const stages = c.data.stages;
  const any = stages.some((s) => s.ok + s.failed > 0);
  return (
    <div className="panel">
      <div className="panel-head">
        <b>Wi-Fi connectivity</b>
        <span className="muted small">last 24 hours</span>
      </div>
      {!any ? (
        <div className="muted small">No connection attempts recorded yet. They come from the APs' connection-tracking notifications.</div>
      ) : (
        <div className="stages">
          {stages.map((s) => {
            const pct = s.success_pct;
            const tone = pct === null ? "" : pct >= 98 ? "good" : pct >= 90 ? "warn" : "bad";
            return (
              <div key={s.stage} className="stage">
                <div className={`stage-bar stage-${tone}`}>{STAGE_LABELS[s.stage] ?? s.stage}</div>
                <div className="small">
                  {pct === null ? "—" : `${pct.toFixed(pct >= 99.95 ? 0 : 1)}%`}
                  <span className="muted">
                    {" "}
                    · {s.ok + s.failed} attempts{s.median_ms !== null ? ` · median ${s.median_ms} ms` : ""}
                  </span>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

/** Our APs' signal to each other: too strong means they crowd each other. */
export function ApDensity() {
  const n = useNeighbors(7 * 86400, "all");
  if (!n.data) return <Loading />;
  const links = n.data.own_links.filter((l) => l.signal !== null);
  const pos = (s: number) => `${Math.min(100, Math.max(0, ((s + 90) / 60) * 100))}%`;
  const worst = links.reduce((m, l) => Math.max(m, l.signal ?? -100), -100);
  const verdict = links.length === 0 ? "No AP-to-AP measurements yet" : worst > -55 ? "APs may be too close" : worst > -65 ? "AP density is fine" : "AP density is good";
  return (
    <div className="panel">
      <div className="panel-head">
        <b>{verdict}</b>
        <span className="muted small">how loudly your APs hear each other (from background scans)</span>
      </div>
      <div className="density">
        <div className="density-scale" />
        {links.map((l, i) => (
          <div
            key={i}
            className="density-mark"
            style={{ left: pos(l.signal ?? -90) }}
            title={`${l.from_name} hears ${l.to_name} at ${l.signal} dBm (${l.radio === "ng" ? "2.4 GHz" : "5 GHz"})`}
          />
        ))}
        <div className="density-axis muted small">
          {[-90, -80, -70, -60, -50, -40, -30].map((v) => (
            <span key={v}>{v}</span>
          ))}
        </div>
      </div>
    </div>
  );
}
