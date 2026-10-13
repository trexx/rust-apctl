import { useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useChannelPlan, useNeighbors, useRadios } from "../api";
import type { Neighbor, RadioOverview } from "../api";
import { ago, bytes } from "../format";
import { ApSpacing, BandPicker } from "../components/Insights";
import { ThreatList } from "../components/Threats";
import { RoamingView } from "../components/RoamingView";
import { ErrorNote, Loading, Meter, Signal } from "../components/common";
import { ChannelAiPanel, PlanActions } from "../components/ChannelAi";

const BAND_NAME: Record<string, string> = { ng: "2.4 GHz", na: "5 GHz" };

/** Centre frequency (MHz) of a channel of the given width. */
function centre(
  channel: number,
  width: number | null,
  radio: string | null,
): number {
  if (radio === "ng" || channel <= 14)
    return channel === 14 ? 2484 : 2407 + 5 * channel;
  const w = width && width > 20 ? width : 20;
  const group = w / 5;
  const base = channel >= 149 ? 149 : 36;
  const start = Math.floor((channel - base) / group) * group + base;
  return 5000 + 5 * (start + (group - 4) / 2);
}

const AXIS = {
  ng: { from: 2400, to: 2485, ticks: [1, 3, 5, 7, 9, 11, 13] },
  na: { from: 5160, to: 5845, ticks: [36, 52, 64, 100, 116, 132, 149, 165] },
} as const;

interface Shape {
  key: string;
  label: string;
  freq: number;
  width: number;
  signal: number;
  own: boolean;
}

/** Channel occupancy: each network drawn as a trapezoid over the frequencies it uses, as tall as it is loud. */
function Spectrum({ band, shapes }: { band: "ng" | "na"; shapes: Shape[] }) {
  const [hover, setHover] = useState<string | null>(null);
  const ax = AXIS[band];
  const W = 900;
  const H = 220;
  const pad = { l: 36, r: 8, t: 8, b: 24 };
  const x = (f: number) =>
    pad.l + ((f - ax.from) / (ax.to - ax.from)) * (W - pad.l - pad.r);
  const y = (s: number) =>
    pad.t +
    ((-20 - Math.max(-100, Math.min(-20, s))) / 80) * (H - pad.t - pad.b);
  const floor = H - pad.b;
  // Quiet ones first, so the loud ones and our own APs are drawn on top.
  const sorted = [...shapes].sort(
    (a, b) => Number(a.own) - Number(b.own) || a.signal - b.signal,
  );
  return (
    <svg
      viewBox={`0 0 ${W} ${H}`}
      className="spectrum"
      role="img"
      aria-label={`${BAND_NAME[band]} channel occupancy`}
    >
      {[-30, -50, -70, -90].map((s) => (
        <g key={s}>
          <line
            x1={pad.l}
            x2={W - pad.r}
            y1={y(s)}
            y2={y(s)}
            className="spectrum-grid"
          />
          <text
            x={pad.l - 4}
            y={y(s) + 4}
            textAnchor="end"
            className="spectrum-label"
          >
            {s}
          </text>
        </g>
      ))}
      {ax.ticks.map((c) => (
        <text
          key={c}
          x={x(centre(c, 20, band))}
          y={H - 6}
          textAnchor="middle"
          className="spectrum-label"
        >
          {c}
        </text>
      ))}
      {sorted.map((s) => {
        const half = s.width / 2;
        const edge = Math.min(2, half / 4);
        const pts = [
          [x(s.freq - half), floor],
          [x(s.freq - half + edge), y(s.signal)],
          [x(s.freq + half - edge), y(s.signal)],
          [x(s.freq + half), floor],
        ]
          .map((p) => p.join(","))
          .join(" ");
        const active = hover === s.key;
        return (
          <polygon
            key={s.key}
            points={pts}
            className={`spectrum-shape ${s.own ? "own" : ""} ${active ? "active" : ""}`}
            onMouseEnter={() => setHover(s.key)}
            onMouseLeave={() => setHover(null)}
          >
            <title>{`${s.label}: ${s.signal} dBm, ${s.width} MHz`}</title>
          </polygon>
        );
      })}
    </svg>
  );
}

function ChannelPlan({
  band,
  radios,
}: {
  band: "ng" | "na";
  radios: RadioOverview[];
}) {
  const [dfs, setDfs] = useState(false);
  const plan = useChannelPlan(band, dfs);
  return (
    <div className="panel">
      <div className="panel-head">
        <b>Channel plan, {BAND_NAME[band]}</b>
        <span className="spacer" />
        {band === "na" && (
          <label className="small">
            <input
              type="checkbox"
              checked={dfs}
              onChange={(e) => setDfs(e.target.checked)}
            />{" "}
            Consider DFS channels
          </label>
        )}
      </div>
      <p className="muted small">
        Scores each channel your AP may use by how loudly it hears other
        networks and your other APs there (lower is better). APs only move when
        the plan as a whole is clearly better (by more than 10%), or when an AP
        is on a channel it may no longer use.
        {plan.data?.allowed &&
          ` Channels allowed: ${plan.data.allowed.join(", ")}.`}
      </p>
      <PlanActions band={band} plan={plan.data} />
      {plan.error && <ErrorNote error={plan.error} />}
      {!plan.data ? (
        <Loading />
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>AP</th>
                <th>Now</th>
                <th>Score</th>
                <th>Suggested</th>
                <th>Why</th>
              </tr>
            </thead>
            <tbody>
              {plan.data.plan.map((p) => {
                const r = radios.find(
                  (x) => x.mac === p.mac && x.radio === band,
                );
                return (
                  <tr key={p.mac}>
                    <td>
                      <Link to={`/devices/${p.mac}`}>{p.name ?? p.mac}</Link>
                      <div className="muted small">
                        {p.clients} clients
                        {p.pinned && " · kept as is"}
                      </div>
                    </td>
                    <td className="nowrap">
                      {p.current_channel ?? "—"}
                      <span className="muted small">
                        {" "}
                        / {r?.bw ?? p.width} MHz
                      </span>
                    </td>
                    <td>{p.current_score ?? "—"}</td>
                    <td className="nowrap">
                      {p.change && p.not_allowed ? (
                        <b className="suggest">
                          → {p.suggested_channel}{" "}
                          <span className="muted small">
                            (now on a channel it may not use)
                          </span>
                        </b>
                      ) : p.change ? (
                        <b className="suggest">
                          → {p.suggested_channel}{" "}
                          <span className="muted small">
                            (score {p.suggested_score})
                          </span>
                        </b>
                      ) : (
                        <span className="muted">keep</span>
                      )}
                    </td>
                    <td className="small">
                      {(p.current_reasons ?? []).length > 0 && (
                        <div>
                          Now hears {(p.current_reasons ?? []).join(", ")}
                        </div>
                      )}
                      {p.change && p.suggested_reasons.length > 0 && (
                        <div className="muted">
                          There: {p.suggested_reasons.join(", ")}
                        </div>
                      )}
                      {p.change && p.suggested_reasons.length === 0 && (
                        <div className="muted">
                          Nothing heard on {p.suggested_channel}
                        </div>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function RadioTable({ radios }: { radios: RadioOverview[] }) {
  return (
    <div className="panel">
      <div className="panel-head">
        <b>Radios</b>
        <span className="muted small">averages over the last 24 hours</span>
      </div>
      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th>AP</th>
              <th>Band</th>
              <th>Channel</th>
              <th>TX power</th>
              <th>Clients</th>
              <th>Utilisation</th>
              <th>Interference</th>
              <th>TX retries</th>
              <th>Noise</th>
              <th>Client signal</th>
              <th>Traffic</th>
            </tr>
          </thead>
          <tbody>
            {radios.map((r) => (
              <tr
                key={r.mac + r.radio}
                className={r.channel === null ? "dim" : ""}
              >
                <td>
                  <Link to={`/devices/${r.mac}`}>{r.name ?? r.mac}</Link>
                </td>
                <td className="nowrap">{BAND_NAME[r.radio] ?? r.radio}</td>
                {r.channel === null ? (
                  <td colSpan={2} className="muted small">
                    not in use (no SSIDs on this band)
                  </td>
                ) : (
                  <>
                    <td className="nowrap">
                      {r.channel}
                      <span className="muted small"> / {r.bw ?? "?"} MHz</span>
                    </td>
                    <td className="nowrap">
                      {r.tx_power ?? "—"} dBm
                      {r.eirp !== null && (
                        <span className="muted small"> ({r.eirp} EIRP)</span>
                      )}
                    </td>
                  </>
                )}
                <td>{r.clients}</td>
                <td>
                  <Meter value={r.avg_utilization} />
                </td>
                <td>
                  {r.avg_interference === null
                    ? "—"
                    : `${r.avg_interference.toFixed(0)}%`}
                </td>
                <td
                  className={
                    r.tx_retry_pct !== null && r.tx_retry_pct >= 15
                      ? "warn"
                      : ""
                  }
                >
                  {r.tx_retry_pct === null
                    ? "—"
                    : `${r.tx_retry_pct.toFixed(1)}%`}
                </td>
                <td className="nowrap">
                  {r.noise_floor === null ? "—" : `${r.noise_floor} dBm`}
                </td>
                <td>
                  <Signal dbm={r.avg_client_signal} />
                </td>
                <td className="nowrap">{bytes(r.usage_bytes)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function Channels() {
  const r = useRadios(86400);
  if (r.error) return <ErrorNote error={r.error} />;
  if (!r.data) return <Loading />;
  return (
    <>
      <RadioTable radios={r.data} />
      <ChannelAiPanel />
      <div className="grid2">
        <ChannelPlan band="na" radios={r.data} />
        <ChannelPlan band="ng" radios={r.data} />
      </div>
    </>
  );
}

function Environment() {
  const [band, setBand] = useState<"ng" | "na">("na");
  const [q, setQ] = useState("");
  const [showOwn, setShowOwn] = useState(false);
  const n = useNeighbors(7 * 86400, band);
  const r = useRadios(86400);

  const shapes = useMemo<Shape[]>(() => {
    const out: Shape[] = [];
    for (const nb of n.data?.neighbors ?? []) {
      if (nb.channel === null || nb.signal === null) continue;
      if (nb.is_unifi && nb.ap_name && !showOwn) continue;
      const w = nb.bw ?? 20;
      out.push({
        key: nb.bssid + nb.ap_mac,
        label: nb.essid || "hidden network",
        freq:
          nb.center_freq && nb.bw && nb.bw > 20
            ? nb.center_freq
            : centre(nb.channel, w, nb.radio),
        width: w,
        signal: nb.best_signal ?? nb.signal,
        own: false,
      });
    }
    for (const radio of r.data ?? []) {
      if (radio.radio !== band || radio.channel === null) continue;
      out.push({
        key: `own-${radio.mac}`,
        label: `${radio.name ?? radio.mac} (yours)`,
        freq: centre(radio.channel, radio.bw, radio.radio),
        width: radio.bw ?? 20,
        // Our APs are drawn at the level our clients hear them at.
        signal: radio.avg_client_signal ?? -50,
        own: true,
      });
    }
    return out;
  }, [n.data, r.data, band, showOwn]);

  const list = useMemo(() => {
    const term = q.trim().toLowerCase();
    return (n.data?.neighbors ?? [])
      .filter(
        (x) =>
          !term ||
          [x.essid, x.bssid, x.vendor, x.nearest_ap].some((v) =>
            v?.toLowerCase().includes(term),
          ),
      )
      .sort((a, b) => (b.best_signal ?? -200) - (a.best_signal ?? -200));
  }, [n.data, q]);

  // One row per network, merged across our APs that heard it.
  const unique = useMemo(() => {
    const m = new Map<string, Neighbor>();
    for (const x of list) if (!m.has(x.bssid)) m.set(x.bssid, x);
    return [...m.values()];
  }, [list]);

  return (
    <>
      <div className="panel">
        <div className="panel-head">
          <b>Channel occupancy</b>
          <BandPicker
            value={band}
            onChange={(b) => setBand(b as "ng" | "na")}
            all={false}
          />
          <span className="spacer" />
          <label className="small">
            <input
              type="checkbox"
              checked={showOwn}
              onChange={(e) => setShowOwn(e.target.checked)}
            />{" "}
            Include your APs as heard by each other
          </label>
        </div>
        {!n.data ? <Loading /> : <Spectrum band={band} shapes={shapes} />}
        <div className="legend small">
          <span className="swatch own" /> your APs <span className="swatch" />{" "}
          neighbouring networks (strongest signal seen in the last 7 days)
        </div>
        <p className="muted small">
          Neighbours come from the APs' background scans, which they run on
          their own every so often, and from Scan now on the Channels tab
          (active mode).
        </p>
      </div>

      <div className="panel">
        <div className="panel-head">
          <b>Neighbouring networks</b>
          <span className="muted small">{unique.length} seen</span>
          <span className="spacer" />
          <input
            className="search"
            placeholder="Filter by name, BSSID, vendor…"
            value={q}
            onChange={(e) => setQ(e.target.value)}
          />
        </div>
        {!n.data ? (
          <Loading />
        ) : unique.length === 0 ? (
          <div className="muted small">
            Nothing heard yet on {BAND_NAME[band]}.
          </div>
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Network</th>
                  <th>Channel</th>
                  <th>Signal</th>
                  <th>Security</th>
                  <th>Vendor</th>
                  <th>Heard best by</th>
                  <th>Last seen</th>
                </tr>
              </thead>
              <tbody>
                {unique.map((x) => (
                  <tr key={x.bssid}>
                    <td>
                      {x.essid || <span className="muted">hidden</span>}
                      {x.is_unifi && x.ap_name && (
                        <span className="tag">your AP {x.ap_name}</span>
                      )}
                      <div className="muted small mono">{x.bssid}</div>
                    </td>
                    <td className="nowrap">
                      {x.channel ?? "—"}
                      <span className="muted small"> / {x.bw ?? 20} MHz</span>
                    </td>
                    <td>
                      <Signal dbm={x.best_signal ?? x.signal} />
                    </td>
                    <td className="small">{x.security ?? "—"}</td>
                    <td className="small">{x.vendor ?? "—"}</td>
                    <td className="small">{x.nearest_ap ?? "—"}</td>
                    <td className="small nowrap">{ago(x.last_seen)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
      <div className="grid1">
        <ApSpacing />
      </div>
    </>
  );
}

const TABS = [
  ["channels", "Channels"],
  ["environment", "Environment"],
  ["roaming", "Roaming"],
  ["rogue", "Rogue networks"],
] as const;

export function Radios() {
  const [params, setParams] = useSearchParams();
  const tab = TABS.find(([k]) => k === params.get("tab"))?.[0] ?? "channels";
  return (
    <div className="page">
      <div className="page-head">
        <h1>Radios</h1>
        <div className="segmented" role="tablist">
          {TABS.map(([k, label]) => (
            <button
              key={k}
              role="tab"
              aria-selected={tab === k}
              className={tab === k ? "active" : ""}
              onClick={() => setParams(k === "channels" ? {} : { tab: k })}
            >
              {label}
            </button>
          ))}
        </div>
      </div>
      {tab === "channels" ? (
        <Channels />
      ) : tab === "environment" ? (
        <Environment />
      ) : tab === "roaming" ? (
        <RoamingView />
      ) : (
        <ThreatList />
      )}
    </div>
  );
}
