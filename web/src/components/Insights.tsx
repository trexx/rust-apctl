import { useState } from "react";
import { Link } from "react-router-dom";
import {
  useConnectivity,
  useDensity,
  useMulticast,
  useNeighbors,
  useRetries,
  useSiteActivity,
  useSiteTop,
} from "../api";
import type { TimeSpan } from "../api";
import { bitrate, bytes, duration, spanLabel } from "../format";
import { COLORS, Chart, RangePicker, ZoomContext, useTimeSpan } from "./Chart";
import { Loading } from "./common";

export function BandPicker({
  value,
  onChange,
  all = true,
}: {
  value: string;
  onChange: (b: string) => void;
  all?: boolean;
}) {
  const bands = [
    ...(all ? [["all", "All radios"]] : []),
    ["ng", "2.4 GHz"],
    ["na", "5 GHz"],
  ];
  return (
    <div className="segmented" role="group" aria-label="Band">
      {bands.map(([v, l]) => (
        <button
          key={v}
          className={value === v ? "active" : ""}
          onClick={() => onChange(v)}
        >
          {l}
        </button>
      ))}
    </div>
  );
}

/** Site-wide Wi-Fi activity and airtime, the first thing on the overview. */
export function SiteActivity() {
  const [view, setView] = useState<"activity" | "airtime">("activity");
  const [range, setRange] = useTimeSpan(86400);
  const [band, setBand] = useState("all");
  const a = useSiteActivity(range, band);
  return (
    <ZoomContext.Provider value={(from, to) => setRange({ from, to })}>
      <div className="panel">
        <div className="panel-head">
          <div className="segmented" role="group" aria-label="View">
            <button
              className={view === "activity" ? "active" : ""}
              onClick={() => setView("activity")}
            >
              Activity
            </button>
            <button
              className={view === "airtime" ? "active" : ""}
              onClick={() => setView("airtime")}
            >
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
                {
                  label: "Download",
                  values: a.data.activity.download_bps,
                  color: COLORS.blue,
                  fill: true,
                },
                {
                  label: "Upload",
                  values: a.data.activity.upload_bps,
                  color: COLORS.purple,
                },
                {
                  label: "Clients",
                  values: a.data.activity.clients,
                  color: COLORS.green,
                  right: true,
                  dashed: true,
                },
              ]}
            />
            <Chart
              title="TX retries and multicast"
              ts={a.data.activity.ts}
              height={120}
              min={0}
              format={(v) => `${v.toFixed(0)}%`}
              series={[
                {
                  label: "TX retries",
                  values: a.data.activity.tx_retry_pct,
                  color: COLORS.orange,
                },
                {
                  label: "Multicast + broadcast share",
                  values: a.data.activity.multicast_pct,
                  color: COLORS.teal,
                  dashed: true,
                },
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
              {
                label: "Total",
                values: a.data.airtime.total,
                color: COLORS.orange,
                fill: true,
              },
              {
                label: "Own traffic",
                values: a.data.airtime.own_traffic,
                color: COLORS.blue,
              },
              {
                label: "External interference",
                values: a.data.airtime.external_interference,
                color: COLORS.red,
              },
            ]}
          />
        )}
      </div>
    </ZoomContext.Provider>
  );
}

function TopList({
  title,
  items,
  link,
}: {
  title: string;
  items: {
    mac: string;
    name: string | null;
    sub?: string | null;
    total: number;
  }[];
  link: string;
}) {
  return (
    <div className="top-list">
      <div className="muted small">{title}</div>
      <div className="chips">
        {items.map((i) => (
          <Link
            key={i.mac}
            to={`/${link}/${i.mac}`}
            className="chip"
            title={i.sub ?? undefined}
          >
            <span className="chip-name">{i.name ?? i.mac}</span>
            <span className="muted small">{bytes(i.total)}</span>
          </Link>
        ))}
        {items.length === 0 && (
          <span className="muted small">No traffic in this range</span>
        )}
      </div>
    </div>
  );
}

/** "last 24 hours", or the fixed window. */
export function spanText(span: TimeSpan): string {
  return "from" in span
    ? spanLabel(span.from, span.to)
    : `last ${duration(span.last).replace(/^1d 0h$/, "24h")}`;
}

export function TopTalkers() {
  const [span] = useTimeSpan(86400);
  const t = useSiteTop(span);
  if (!t.data) return <Loading />;
  const total = (x: { download_bytes: number; upload_bytes: number }) =>
    x.download_bytes + x.upload_bytes;
  return (
    <div className="panel">
      <div className="panel-head">
        <b>Top traffic</b>
        <span className="muted small">{spanText(span)}</span>
      </div>
      <TopList
        title="Access points"
        link="devices"
        items={t.data.aps.map((a) => ({
          mac: a.mac,
          name: a.name,
          total: total(a),
        }))}
      />
      <TopList
        title="Clients"
        link="clients"
        items={t.data.clients
          .slice(0, 15)
          .map((c) => ({
            mac: c.mac,
            name: c.name,
            sub: c.vendor,
            total: total(c),
          }))}
      />
    </div>
  );
}

/** Lower edges of the retry buckets, worst first (as the official dashboard). */
const RETRY_EDGES = [25, 20, 15, 10, 5, 0];

export function RetryBuckets() {
  const [band, setBand] = useState("all");
  const [span] = useTimeSpan(86400);
  const r = useRetries(span);
  if (!r.data) return <Loading />;
  const radios = r.data.filter((x) => band === "all" || x.radio === band);
  return (
    <div className="panel">
      <div className="panel-head">
        <b>AP radio TX retries</b>
        <span className="muted small">{spanText(span)}</span>
        <span className="spacer" />
        <BandPicker value={band} onChange={setBand} />
      </div>
      <div className="buckets">
        {RETRY_EDGES.map((min, i) => {
          const upper = i === 0 ? Infinity : RETRY_EDGES[i - 1];
          const inBucket = radios.filter(
            (x) => x.tx_retry_pct >= min && x.tx_retry_pct < upper,
          );
          const tone = i === 0 ? "bad" : i === 1 ? "warn" : "good";
          const tip = inBucket
            .map(
              (x) =>
                `${x.name ?? x.mac} ${x.radio === "ng" ? "2.4 GHz" : "5 GHz"}: ${x.tx_retry_pct.toFixed(1)}%`,
            )
            .join("\n");
          return (
            <div key={min} className="bucket">
              <div
                className={`bucket-bar bucket-${tone} ${inBucket.length ? "" : "bucket-empty"}`}
                title={tip || undefined}
              >
                {inBucket.length || ""}
              </div>
            </div>
          );
        })}
      </div>
      <div className="bucket-edges muted small">
        {["35%+", "25%", "20%", "15%", "10%", "5%", "0%"].map((l) => (
          <span key={l}>{l}</span>
        ))}
      </div>
      <div className="muted small">
        Retries as a share of all transmissions (retries ÷ attempts + retries +
        dropped), per AP radio.
      </div>
    </div>
  );
}

const STAGES = [
  ["association_pct", "Assoc"],
  ["authentication_pct", "Auth"],
  ["dhcp_pct", "DHCP"],
  ["dns_pct", "DNS"],
] as const;

const pctTone = (p: number | null) =>
  p === null || p === 0 ? "" : p >= 80 ? "good" : p >= 60 ? "warn" : "bad";

export function Connectivity() {
  const [band, setBand] = useState("all");
  const [span] = useTimeSpan(86400);
  const c = useConnectivity(span);
  if (!c.data) return <Loading />;
  const d = c.data.bands[band];
  return (
    <div className="panel">
      <div className="panel-head">
        <b>Wi-Fi connectivity</b>
        <span className="muted small">{spanText(span)}</span>
        <span className="spacer" />
        <BandPicker value={band} onChange={setBand} />
      </div>
      {!d || d.attempts === 0 ? (
        <div className="muted small">
          No connection attempts recorded in this range. They come from the APs'
          connection-tracking reports.
        </div>
      ) : (
        <>
          <div className="stages">
            {STAGES.map(([k, label]) => (
              <div
                key={k}
                className={`stage-bar stage-${pctTone(d[k])}`}
                title={`${d[k] ?? 0}% of clients got past ${label}`}
              >
                {label}
              </div>
            ))}
            <div className="stage-success">
              Success{" "}
              <b className={`tone-${pctTone(d.success_pct)}`}>
                {d.success_pct ?? 0}%
              </b>
            </div>
          </div>
          <div className="small muted">
            {d.clients} client{d.clients === 1 ? "" : "s"}, {d.attempts} attempt
            {d.attempts === 1 ? "" : "s"}
            {d.failed_clients > 0 &&
              ` · ${d.failed_clients} never connected (stopped at ${Object.entries(
                d.failed_at,
              )
                .filter(([, n]) => n > 0)
                .map(([k, n]) => `${k} ${n}`)
                .join(", ")})`}
            {d.median_ms.dhcp !== null &&
              ` · typical: associate ${d.median_ms.association ?? "—"} ms, authenticate ${d.median_ms.authentication ?? "—"} ms, DHCP ${d.median_ms.dhcp} ms`}
          </div>
        </>
      )}
    </div>
  );
}

/** Deployment density: per AP, the average signal of its weaker half of clients. */
export function DeploymentDensity() {
  const [band, setBand] = useState("all");
  const [span] = useTimeSpan(86400);
  const d = useDensity(span);
  if (!d.data) return <Loading />;
  const pins = d.data.aps.flatMap((ap) => {
    const g = ap.bands.find((b) => b.band === band);
    return g && g.clients > 0 && g.signal_avg !== 0
      ? [{ ap, g, quiet: g.traffic_pct < 1 }]
      : [];
  });
  const counted = pins.filter((p) => !p.quiet);
  const verdict =
    counted.length === 0
      ? null
      : counted.some((p) => p.g.weakest_signal < -75)
        ? "AP deployment density may need improvement"
        : "AP density is good";
  const pos = (s: number) =>
    `${((Math.min(-30, Math.max(-90, s)) + 90) / 60) * 100}%`;
  // Pins in the same 3 dB step stack upwards.
  const stack = new Map<number, number>();
  return (
    <div className="panel">
      <div className="panel-head">
        {verdict ? (
          <b
            className={
              verdict.startsWith("AP density") ? "tone-good" : "tone-warn"
            }
          >
            {verdict}
          </b>
        ) : (
          <b>Deployment density</b>
        )}
        <span className="muted small">{spanText(span)}</span>
        <span className="spacer" />
        <BandPicker value={band} onChange={setBand} />
      </div>
      <div className="muted small">
        Signal of each AP's weaker half of clients, averaged. Below −75 dBm
        suggests clients are far from their AP.
      </div>
      <div className="density">
        <div className="density-scale" />
        {pins.map(({ ap, g, quiet }) => {
          const step = Math.round(g.weakest_signal / 3);
          const level = stack.get(step) ?? 0;
          stack.set(step, level + 1);
          return (
            <div
              key={ap.mac}
              className={`density-mark ${quiet ? "quiet" : g.weakest_signal < -80 ? "bad" : g.weakest_signal < -75 ? "warn" : ""}`}
              style={{ left: pos(g.weakest_signal), top: 8 - level * 14 }}
              title={`${ap.name ?? ap.mac}: weaker clients ${g.weakest_signal} dBm, all clients ${g.signal_avg} dBm, ${g.clients} clients on average, ${g.traffic_pct.toFixed(1)}% of traffic${g.tx_retry_pct !== null ? `, ${g.tx_retry_pct.toFixed(1)}% TX retries` : ""}${quiet ? " (too little traffic to count)" : ""}`}
            />
          );
        })}
        <div className="density-axis muted small">
          {[-90, -80, -70, -60, -50, -40, -30].map((v) => (
            <span key={v}>{v}</span>
          ))}
        </div>
      </div>
      {pins.length === 0 && (
        <div className="muted small">No clients in this range.</div>
      )}
    </div>
  );
}

const MCAST_COLORS: Record<string, string> = {
  mdns: COLORS.blue,
  ssdp: COLORS.purple,
  arp: COLORS.orange,
  igmp: COLORS.green,
  mld: "#7a9a3a",
  stream: COLORS.red,
  dhcp: COLORS.teal,
  dhcpv6: "#4a8fa0",
  ipv6_nd: "#b07ab0",
  other: "#8a8f98",
};

const MCAST_LABEL: Record<string, string> = {
  mdns: "mDNS",
  ssdp: "SSDP",
  arp: "ARP",
  igmp: "IGMP",
  mld: "MLD",
  stream: "Streams",
  dhcp: "DHCP",
  dhcpv6: "DHCPv6",
  ipv6_nd: "IPv6 ND",
  other: "Other",
};

const count = (n: number) =>
  new Intl.NumberFormat("en-GB", { notation: "compact" }).format(n);

/** Multicast and broadcast by traffic type, and the clients behind it. */
export function MulticastPanel({
  mac,
  span,
  title = "Multicast and broadcast",
}: {
  mac?: string;
  span: TimeSpan;
  title?: string;
}) {
  const [dir, setDir] = useState<"tx" | "rx">("tx");
  const m = useMulticast(span, mac);
  if (!m.data)
    return (
      <div className="panel">{m.error ? String(m.error) : <Loading />}</div>
    );
  const kinds = Object.entries(m.data.types)
    .filter(([, v]) => v.tx_pkts + v.rx_pkts > 0)
    .sort((a, b) => b[1][`${dir}_pkts`] - a[1][`${dir}_pkts`]);
  return (
    <div className="panel">
      <div className="panel-head">
        <b>{title}</b>
        <span className="muted small">{spanText(span)}</span>
        <span className="spacer" />
        <div className="segmented" role="group" aria-label="Direction">
          <button
            className={dir === "tx" ? "active" : ""}
            onClick={() => setDir("tx")}
          >
            To clients
          </button>
          <button
            className={dir === "rx" ? "active" : ""}
            onClick={() => setDir("rx")}
          >
            From clients
          </button>
        </div>
      </div>
      <Chart
        title={`Packets per second by type, ${dir === "tx" ? "delivered to clients" : "sent by clients"}`}
        ts={m.data.ts}
        height={160}
        min={0}
        format={(v) => `${v.toFixed(v < 10 ? 1 : 0)}/s`}
        series={kinds.map(([k, v]) => ({
          label: MCAST_LABEL[k] ?? k,
          values: v[`${dir}_pps`],
          color: MCAST_COLORS[k] ?? COLORS.teal,
        }))}
      />
      <div className="mcast-types small">
        {kinds.map(([k, v]) => (
          <span key={k}>
            <i
              className="swatch"
              style={{
                background: MCAST_COLORS[k] ?? COLORS.teal,
                borderColor: MCAST_COLORS[k] ?? COLORS.teal,
              }}
            />{" "}
            {MCAST_LABEL[k] ?? k} <b>{count(v[`${dir}_pkts`])}</b>
          </span>
        ))}
      </div>
      {m.data.clients.length > 0 && (
        <table className="table">
          <thead>
            <tr>
              <th>Client</th>
              <th>Sent</th>
              <th>Received</th>
              <th>Services</th>
              <th>Delivery</th>
            </tr>
          </thead>
          <tbody>
            {m.data.clients.slice(0, 10).map((c) => (
              <tr key={c.mac}>
                <td>
                  <Link to={`/clients/${c.mac}`}>{c.name ?? c.mac}</Link>
                  <div className="muted small">
                    {[c.vendor, !mac && c.ap].filter(Boolean).join(" · ")}
                  </div>
                </td>
                <td className="nowrap">{count(c.rx_pkts)} pkts</td>
                <td className="nowrap">{count(c.tx_pkts)} pkts</td>
                <td className="small">
                  {c.services.length
                    ? serviceNames(c.services).slice(0, 3).join(", ")
                    : "—"}
                </td>
                <td
                  className="small"
                  title={
                    c.delivery === "flooding"
                      ? "Joined groups are flooded to every client"
                      : c.delivery === "optimized"
                        ? "Only sent to clients that joined"
                        : undefined
                  }
                >
                  {c.delivery ?? "—"}
                  {c.memberships > 0 && (
                    <span className="muted"> · {c.memberships} groups</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

const SERVICES: [RegExp, string][] = [
  [/_airplay|_raop/, "AirPlay"],
  [/_googlecast|_googlezone/, "Chromecast"],
  [/_ipp|_printer|_pdl-datastream|_scanner|_uscan/, "Printers"],
  [/_spotify/, "Spotify Connect"],
  [/_homekit|_hap\./, "HomeKit"],
  [/_companion-link|_rdlink|_apple-mobdev|_sleep-proxy/, "Apple devices"],
  [/_androidtvremote|_amzn|_nvstream/, "TV remotes"],
  [/_smb|_afpovertcp|_nfs/, "File sharing"],
  [/_matter/, "Matter"],
  [/_hue|_homeconnect|_miio|_esphomelib/, "Smart home"],
];

/** Friendly names for the mDNS service types a client used. */
export function serviceNames(
  services: { name: string; pkts: number }[],
): string[] {
  const out = new Map<string, number>();
  for (const s of services) {
    const name =
      SERVICES.find(([re]) => re.test(s.name))?.[1] ??
      (s.name.startsWith("_services._dns-sd") ? null : "Others");
    if (name) out.set(name, (out.get(name) ?? 0) + s.pkts);
  }
  return [...out.entries()].sort((a, b) => b[1] - a[1]).map(([n]) => n);
}

/** Our APs' signal to each other: too strong means they crowd each other. */
/** How loudly our APs hear each other in their scans: too loud means they crowd each other. */
export function ApSpacing() {
  const n = useNeighbors(7 * 86400, "all");
  if (!n.data) return <Loading />;
  const links = n.data.own_links.filter((l) => l.signal !== null);
  const pos = (s: number) =>
    `${Math.min(100, Math.max(0, ((s + 90) / 60) * 100))}%`;
  const worst = links.reduce((m, l) => Math.max(m, l.signal ?? -100), -100);
  const verdict =
    links.length === 0
      ? "No AP-to-AP measurements yet"
      : worst > -55
        ? "APs may be too close"
        : worst > -65
          ? "AP density is fine"
          : "AP density is good";
  return (
    <div className="panel">
      <div className="panel-head">
        <b>{verdict}</b>
        <span className="muted small">
          how loudly your APs hear each other (from background scans)
        </span>
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
