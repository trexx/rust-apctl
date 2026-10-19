import { useState } from "react";
import { useSeries, useSiteActivity } from "../api";
import type {
  ListedClientView,
  RadioSample,
  TimeSpan,
  VapSample,
} from "../api";
import { COLORS, Chart } from "./Chart";
import { QueryState, Signal, THead } from "./common";
import {
  SIGNAL,
  band,
  bytes,
  compact,
  multicastTone,
  pct,
  pct1,
  rate,
} from "../format";
import type { Tone } from "../format";

const share = (part: number, whole: number) =>
  pct1(whole > 0 ? (100 * part) / whole : null);

/** A value with its unit, or "—" when there is none. */
const unit = (v: number | null, u: string) => (v === null ? "—" : `${v} ${u}`);

/** The keys of `T` whose values are numbers (or null). */
type NumericKey<T> = {
  [K in keyof T]: T[K] extends number | null ? K : never;
}[keyof T];

/** Lower edges of the signal buckets, strongest first, with the colour of `signalClass`. */
const SIGNAL_BUCKETS: [number, string, Tone][] = [
  [SIGNAL.excellent, "Excellent", "good"],
  [SIGNAL.good, "Good", "good"],
  [SIGNAL.fair, "Fair", "warn"],
  [-Infinity, "Poor", "bad"],
];

/** How many of the radio's clients are in each signal band; those without a signal reading are left out. */
function SignalDistribution({ clients }: { clients: ListedClientView[] }) {
  const signals = clients.flatMap((c) => c.sample.signal ?? []);
  const counts = SIGNAL_BUCKETS.map(([min], i) => {
    const max = i === 0 ? Infinity : SIGNAL_BUCKETS[i - 1]![0];
    return signals.filter((s) => s >= min && s < max).length;
  });
  const total = signals.length;
  return (
    <div className="dist">
      <div className="dist-bar">
        {counts.map((n, i) =>
          n ? (
            <span
              key={i}
              className={`fill-${SIGNAL_BUCKETS[i]![2]}`}
              style={{ flex: n }}
              title={`${SIGNAL_BUCKETS[i]![1]}: ${n}`}
            />
          ) : null,
        )}
        {total === 0 && <span className="dist-empty" style={{ flex: 1 }} />}
      </div>
      <div className="dist-legend small muted">
        {SIGNAL_BUCKETS.map(([min, label], i) => (
          <span key={label}>
            {label} {i < 3 ? `≥ ${min}` : `< ${SIGNAL.fair}`}:{" "}
            <b>{counts[i]}</b>
          </span>
        ))}
      </div>
    </div>
  );
}

export function RadioPanel({
  mac,
  radio,
  vaps,
  clients,
  range,
}: {
  mac: string;
  radio: RadioSample;
  vaps: VapSample[];
  clients: ListedClientView[];
  range: TimeSpan;
}) {
  const s = useSeries("radio", `${mac},${radio.radio}`, range);
  // The radio's own retry counters stay at zero on this firmware, so totals come from its SSIDs.
  const sum = (k: NumericKey<VapSample>) =>
    vaps.reduce((a, v) => a + (v[k] ?? 0), 0);
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
            ? `channel ${radio.channel} · ${unit(radio.bw, "MHz")}`
            : "no SSIDs on this radio"}{" "}
          · noise {unit(radio.noise_floor, "dBm")}
        </span>
      </div>
      <dl className="kv">
        <dt>TX power</dt>
        <dd>
          {unit(radio.tx_power, "dBm")}
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
          {compact(txPkts)} packets · {bytes(sum("tx_bytes"))}
        </dd>
        <dt>RX</dt>
        <dd>
          {compact(sum("rx_packets"))} packets · {bytes(sum("rx_bytes"))}
        </dd>
        <dt>TX retries</dt>
        <dd>{share(retries, retries + attempts + sum("wifi_tx_dropped"))}</dd>
        <dt>TX dropped</dt>
        <dd>{share(dropped, txPkts + dropped)}</dd>
        <dt>Multicast / broadcast</dt>
        <dd>
          <span
            className={`tone-${multicastTone(mcastShare)}`}
            title="Share of all packets on this radio"
          >
            {pct1(mcastShare)} of packets
          </span>
          <span className="muted">
            {" "}
            · to clients {compact(sum("tx_mcast") + sum("tx_bcast"))}, from
            clients {compact(sum("rx_mcast") + sum("rx_bcast"))}
          </span>
        </dd>
        <dt>Clients ({clients.length})</dt>
        <dd>
          <SignalDistribution clients={clients} />
        </dd>
      </dl>
      <div className="muted small">Counters are since the AP last started.</div>
      <QueryState q={s}>
        {(data) => (
          <Chart
            title="Airtime (channel utilisation)"
            ts={data.ts}
            format={pct}
            min={0}
            max={100}
            series={[
              {
                label: "Total",
                values: data.fields.cu_total,
                color: COLORS.blue,
                fill: true,
              },
              {
                label: "Own RX",
                values: data.fields.cu_self_rx,
                color: COLORS.green,
              },
              {
                label: "Own TX",
                values: data.fields.cu_self_tx,
                color: COLORS.purple,
              },
              {
                label: "Interference",
                values: data.fields.cu_interf,
                color: COLORS.red,
              },
            ]}
          />
        )}
      </QueryState>
    </div>
  );
}

/** Client activity, network performance and multicast for one radio, from its SSIDs' counters. */
export function RadioActivity({
  mac,
  radio,
  range,
}: {
  mac: string;
  radio: string;
  range: TimeSpan;
}) {
  const a = useSiteActivity(range, radio, mac);
  return (
    <QueryState q={a} panel>
      {({ activity: x }) => (
        <div className="panel">
          <div className="panel-head">
            <b>{band(radio)} activity</b>
          </div>
          <Chart
            title="Client activity"
            ts={x.ts}
            format={rate}
            formatRight={(v) => `${Math.round(v)}`}
            series={[
              {
                label: "To clients",
                values: x.download_bps,
                color: COLORS.blue,
                fill: true,
              },
              {
                label: "From clients",
                values: x.upload_bps,
                color: COLORS.purple,
              },
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
              {
                label: "TX retries",
                values: x.tx_retry_pct,
                color: COLORS.orange,
              },
              {
                label: "TX dropped",
                values: x.tx_dropped_pct,
                color: COLORS.red,
              },
            ]}
          />
          <Chart
            title="Packets and multicast"
            ts={x.ts}
            height={130}
            format={(v) => `${v.toFixed(v < 10 ? 1 : 0)}/s`}
            formatRight={pct}
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
      )}
    </QueryState>
  );
}

/** The AP's SSIDs (one row per radio), each with its traffic chart on demand. */
export function VapTable({
  vaps,
  range,
}: {
  vaps: VapSample[];
  range: TimeSpan;
}) {
  const [open, setOpen] = useState<string | null>(null);
  return (
    <div className="panel">
      <table className="table">
        <THead
          columns={[
            "SSID",
            "Band",
            "Clients",
            "Avg signal",
            "Satisfaction",
            "BSSID",
          ]}
        />
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
      {/* The whole row toggles; the button (its click bubbles up) is for the keyboard. */}
      <tr className="clickable" onClick={toggle}>
        <td>
          <button className="plain" aria-expanded={open}>
            {open ? "▾" : "▸"} {vap.essid}
          </button>
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
  return (
    <QueryState q={s}>
      {(data) => (
        <Chart
          title="SSID traffic on this radio"
          ts={data.ts}
          format={rate}
          series={[
            {
              label: "To clients",
              values: data.fields.tx_bytes,
              scale: 8,
              color: COLORS.blue,
              fill: true,
            },
            {
              label: "From clients",
              values: data.fields.rx_bytes,
              scale: 8,
              color: COLORS.purple,
            },
          ]}
        />
      )}
    </QueryState>
  );
}
