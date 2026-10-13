import { Link } from "react-router-dom";
import { useWlans } from "../api";
import type { Wlan } from "../api";
import { band, bitrate, bytes } from "../format";
import {
  COLORS,
  Chart,
  RangePicker,
  SpanContext,
  ZoomContext,
  useTimeSpan,
} from "../components/Chart";
import { ErrorNote, Loading, Signal } from "../components/common";
import { spanText } from "../components/Insights";

/** Experience bands as the official controller colours them: 90+ excellent, 70+ good. */
const uxTone = (v: number | null) =>
  v === null ? "" : v >= 90 ? "tone-good" : v >= 70 ? "tone-warn" : "tone-bad";

function Settings({ w }: { w: Wlan }) {
  const s = w.settings;
  // The settings say one thing, the APs broadcast another (e.g. WPA3 enabled but not advertised).
  const wpa3 = (x: string) => /wpa3/i.test(x);
  const open = (x: string) => /open|none/i.test(x);
  const differs =
    !!s &&
    !!w.security_on_air &&
    (wpa3(s.security) !== wpa3(w.security_on_air) ||
      open(s.security) !== open(w.security_on_air));
  return (
    <div className="chips-row small">
      {s ? (
        <>
          <span className="tag" title="From the imported controller settings">
            {s.security}
          </span>
          {s.network && <span className="tag">network {s.network}</span>}
          {s.vlan !== null && s.vlan !== undefined && (
            <span className="tag">VLAN {String(s.vlan)}</span>
          )}
          {s.hidden && <span className="tag">hidden</span>}
          {s.guest && <span className="tag">guest</span>}
          {s.fast_roaming && <span className="tag">fast roaming</span>}
          {s.bss_transition && <span className="tag">BSS transition</span>}
          {!s.enabled && <span className="tag tag-bad">disabled</span>}
        </>
      ) : (
        <span className="muted">Settings not imported</span>
      )}
      {w.security_on_air && (
        <span
          className={`tag ${differs ? "tag-warn" : ""}`}
          title="As your APs hear it broadcast"
        >
          on air: {w.security_on_air}
        </span>
      )}
    </div>
  );
}

function WlanPanel({ w }: { w: Wlan }) {
  return (
    <div className="panel">
      <div className="panel-head">
        <b>{w.essid}</b>
        <span className="muted small">
          {w.bands.map(band).join(" + ") || "not broadcast now"}
        </span>
        <span className="spacer" />
        <span className="small">
          on{" "}
          {w.broadcast.map((b, i) => (
            <span key={b.bssid}>
              {i > 0 && ", "}
              <Link to={`/devices/${b.ap}`}>{b.name ?? b.ap}</Link>
              <span className="muted">
                {" "}
                ({band(b.radio)} ch {b.channel})
              </span>
            </span>
          ))}
        </span>
      </div>
      <Settings w={w} />
      <div className="wlan-stats">
        <div>
          <div className="muted small">Clients</div>
          <b>{w.clients}</b>{" "}
          <span className="muted small">now · {w.peak_clients} peak</span>
        </div>
        <div>
          <div
            className="muted small"
            title="Average of its SSIDs' Wi-Fi experience scores, now"
          >
            Experience
          </div>
          <b className={uxTone(w.satisfaction)}>{w.satisfaction ?? "—"}</b>{" "}
          <span className="muted small">
            now · {w.satisfaction_avg ?? "—"} avg
          </span>
        </div>
        <div>
          <div className="muted small">Client signal</div>
          <Signal dbm={w.signal_avg} />
        </div>
        <div>
          <div className="muted small">Traffic</div>
          <b>↓ {bytes(w.download_bytes)}</b>{" "}
          <span className="muted small">↑ {bytes(w.upload_bytes)}</span>
        </div>
        <div>
          <div className="muted small">TX retries</div>
          <b
            className={
              w.tx_retry_pct !== null && w.tx_retry_pct >= 20 ? "tone-warn" : ""
            }
          >
            {w.tx_retry_pct === null ? "—" : `${w.tx_retry_pct.toFixed(1)}%`}
          </b>
        </div>
        <div>
          <div className="muted small">Multicast + broadcast</div>
          <b
            className={
              w.multicast_pct !== null && w.multicast_pct >= 30
                ? "tone-warn"
                : ""
            }
          >
            {w.multicast_pct === null ? "—" : `${w.multicast_pct.toFixed(1)}%`}
          </b>
          <span className="muted small"> of packets</span>
        </div>
      </div>
      <div className="grid2">
        <Chart
          title="Clients"
          ts={w.series.ts}
          height={120}
          min={0}
          format={(v) => `${Math.round(v)}`}
          series={[
            {
              label: "Clients",
              values: w.series.clients,
              color: COLORS.green,
              fill: true,
            },
          ]}
        />
        <Chart
          title="Traffic"
          ts={w.series.ts}
          height={120}
          format={(v) => bitrate(v / 8)}
          series={[
            {
              label: "To clients",
              values: w.series.download_bps,
              color: COLORS.blue,
              fill: true,
            },
            {
              label: "From clients",
              values: w.series.upload_bps,
              color: COLORS.purple,
            },
          ]}
        />
      </div>
    </div>
  );
}

export function Networks() {
  const [span, setSpan] = useTimeSpan(86400);
  const w = useWlans(span);
  return (
    <ZoomContext.Provider value={(from, to) => setSpan({ from, to })}>
      <SpanContext.Provider value={span}>
        <div className="page">
          <div className="page-head">
            <h1>Wi-Fi networks</h1>
            <span className="muted small">{spanText(span)}</span>
            <span className="spacer" />
            <RangePicker value={span} onChange={setSpan} />
          </div>
          {w.error && <ErrorNote error={w.error} />}
          {!w.data ? (
            <Loading />
          ) : w.data.wlans.length === 0 ? (
            <div className="muted">No networks seen yet.</div>
          ) : (
            <div className="stack">
              {w.data.wlans.map((x) => (
                <WlanPanel key={x.essid} w={x} />
              ))}
            </div>
          )}
        </div>
      </SpanContext.Provider>
    </ZoomContext.Provider>
  );
}
