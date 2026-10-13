import { useState } from "react";
import { Link } from "react-router-dom";
import { useConnections } from "../api";
import type { ConnAttempt, Roam, TimeSpan, Timings } from "../api";
import { band, clock } from "../format";
import { ErrorNote, Loading, Signal } from "./common";

const STAGE_NAME = [
  "",
  "association",
  "authentication",
  "DHCP",
  "DNS",
  "first traffic",
  "",
];

const ms = (v: number) =>
  v < 1000
    ? `${Math.round(v)} ms`
    : v < 60000
      ? `${(v / 1000).toFixed(1)} s`
      : `${(v / 60000).toFixed(1)} min`;

/** How long each step of joining took: association, authentication, DHCP, DNS. */
export function TimingBar({ t }: { t: Timings }) {
  const parts: [string, number | null, string][] = [
    ["Associate", t.association, "seg-assoc"],
    ["Authenticate", t.authentication, "seg-auth"],
    ["DHCP", t.dhcp, "seg-dhcp"],
    ["DNS", t.dns, "seg-dns"],
  ];
  const known = parts.filter((p) => p[1] !== null && p[1] > 0) as [
    string,
    number,
    string,
  ][];
  if (known.length === 0) return <span className="muted small">—</span>;
  const sum = known.reduce((a, p) => a + p[1], 0);
  return (
    <span
      className="timing"
      title={
        known.map(([l, v]) => `${l} ${ms(v)}`).join(", ") +
        (t.total ? `; total ${ms(t.total)}` : "")
      }
    >
      <span className="timing-bar">
        {known.map(([l, v, c]) => (
          <span
            key={l}
            className={c}
            style={{ flex: Math.max(v / sum, 0.06) }}
          />
        ))}
      </span>
      <span className="small muted">{ms(t.total ?? sum)}</span>
    </span>
  );
}

function Result({ a }: { a: ConnAttempt }) {
  if (a.success && a.roam)
    return <span className="tag tag-info">Roamed in</span>;
  if (a.success && a.fixed_up)
    return (
      <span className="tag tag-good" title="Failed at first, then recovered">
        Connected (recovered)
      </span>
    );
  if (a.success) return <span className="tag tag-good">Connected</span>;
  return (
    <span className="tag tag-bad" title={`Got stuck at ${STAGE_NAME[a.stage]}`}>
      Failed: {a.failure}
    </span>
  );
}

const where = (
  radio: string | null,
  channel: number | null,
  bw: number | null,
) =>
  [
    band(radio),
    channel !== null ? `ch ${channel}` : null,
    bw ? `${bw} MHz` : null,
  ]
    .filter((x) => x && x !== "—")
    .join(" ");

type Item =
  | { kind: "attempt"; ts: number; a: ConnAttempt }
  | { kind: "roam"; ts: number; r: Roam };

/** One client's connection attempts and roams, newest first. */
export function ConnectionLog({
  client,
  span,
}: {
  client: string;
  span: TimeSpan;
}) {
  const c = useConnections(span, { client });
  if (c.error) return <ErrorNote error={c.error} />;
  if (!c.data) return <Loading />;
  const ap = (m: string) => c.data!.ap_names[m] ?? m;
  // A roam also shows up as the attempt on the new AP; keep just the roam.
  const roams = c.data.roams;
  const isRoamJoin = (a: ConnAttempt) =>
    a.roam &&
    roams.some((r) => r.to.ap === a.ap && Math.abs(r.ts - a.ts) <= 15);
  const items: Item[] = [
    ...c.data.attempts
      .filter((a) => !isRoamJoin(a))
      .map((a) => ({ kind: "attempt" as const, ts: a.ts, a })),
    ...c.data.roams.map((r) => ({ kind: "roam" as const, ts: r.ts, r })),
  ].sort((x, y) => y.ts - x.ts);
  if (items.length === 0)
    return (
      <div className="muted small">
        No connection attempts or roams in this range. They come from the APs'
        connection-tracking reports.
      </div>
    );
  return (
    <table className="table conn-log">
      <thead>
        <tr>
          <th>Time</th>
          <th>Result</th>
          <th>Access point</th>
          <th>Network</th>
          <th>Signal</th>
          <th>Time to connect</th>
        </tr>
      </thead>
      <tbody>
        {items.slice(0, 100).map((it, i) =>
          it.kind === "attempt" ? (
            <tr key={`a${i}`}>
              <td className="nowrap small">{clock(it.ts)}</td>
              <td>
                <Result a={it.a} />
                {it.a.reason && (
                  <div className="muted small">AP reason: {it.a.reason}</div>
                )}
              </td>
              <td>
                <Link to={`/devices/${it.a.ap}`}>{ap(it.a.ap)}</Link>
              </td>
              <td className="small">
                {it.a.essid ?? "—"}
                <div className="muted">
                  {where(it.a.radio, it.a.channel, it.a.bw)}
                </div>
              </td>
              <td>
                <Signal dbm={it.a.rssi} />
              </td>
              <td>
                <TimingBar t={it.a.timings} />
              </td>
            </tr>
          ) : (
            <tr key={`r${i}`}>
              <td className="nowrap small">{clock(it.ts)}</td>
              <td>
                <span
                  className={`tag ${it.r.success ? "tag-info" : "tag-bad"}`}
                >
                  {it.r.success
                    ? "Roamed"
                    : `Roam failed${it.r.gap_s ? `, off for ${it.r.gap_s}s` : ""}`}
                </span>
                <div className="muted small">
                  {[
                    it.r.fast && "fast roaming (802.11r)",
                    it.r.min_rssi && "pushed by minimum RSSI",
                    it.r.assistant && "roaming assistant",
                  ]
                    .filter(Boolean)
                    .join(" · ")}
                </div>
              </td>
              <td className="small">
                <Link to={`/devices/${it.r.from.ap}`}>{ap(it.r.from.ap)}</Link>{" "}
                → <Link to={`/devices/${it.r.to.ap}`}>{ap(it.r.to.ap)}</Link>
              </td>
              <td className="small">
                {it.r.to.essid ?? "—"}
                <div className="muted">
                  {band(it.r.from.radio)} →{" "}
                  {where(it.r.to.radio, it.r.to.channel, it.r.to.bw)}
                </div>
              </td>
              <td className="nowrap">
                <Signal dbm={it.r.from.rssi} /> → <Signal dbm={it.r.to.rssi} />
              </td>
              <td />
            </tr>
          ),
        )}
      </tbody>
    </table>
  );
}

/** Connection attempts across the site, newest first. */
export function AttemptList({ span }: { span: TimeSpan }) {
  const [failed, setFailed] = useState(false);
  const c = useConnections(span, { failed });
  return (
    <div className="panel">
      <div className="panel-head">
        <b>Connection attempts</b>
        <span className="muted small">
          from the APs' connection-tracking reports
        </span>
        <span className="spacer" />
        <div className="segmented" role="group" aria-label="Which attempts">
          <button
            className={!failed ? "active" : ""}
            onClick={() => setFailed(false)}
          >
            All
          </button>
          <button
            className={failed ? "active" : ""}
            onClick={() => setFailed(true)}
          >
            Failed only
          </button>
        </div>
      </div>
      {c.error && <ErrorNote error={c.error} />}
      {!c.data ? (
        <Loading />
      ) : c.data.attempts.length === 0 ? (
        <div className="muted small">
          {failed
            ? "No failed attempts in this range."
            : "No attempts in this range."}
        </div>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Client</th>
                <th>Result</th>
                <th>Access point</th>
                <th>Network</th>
                <th>Signal</th>
                <th>Time to connect</th>
              </tr>
            </thead>
            <tbody>
              {c.data.attempts.slice(0, 200).map((a, i) => (
                <tr key={i}>
                  <td className="nowrap small">{clock(a.ts)}</td>
                  <td>
                    <Link to={`/clients/${a.client}`}>
                      {c.data!.client_names[a.client] ?? a.client}
                    </Link>
                  </td>
                  <td>
                    <Result a={a} />
                  </td>
                  <td>
                    <Link to={`/devices/${a.ap}`}>
                      {c.data!.ap_names[a.ap] ?? a.ap}
                    </Link>
                  </td>
                  <td className="small">
                    {a.essid ?? "—"}
                    <div className="muted">
                      {where(a.radio, a.channel, a.bw)}
                    </div>
                  </td>
                  <td>
                    <Signal dbm={a.rssi} />
                  </td>
                  <td>
                    <TimingBar t={a.timings} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
