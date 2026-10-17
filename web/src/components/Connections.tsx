import { useState } from "react";
import { Link } from "react-router-dom";
import { useConnections } from "../api";
import type { ConnAttempt, Connections, Roam, TimeSpan, Timings } from "../api";
import { band, clock } from "../format";
import { QueryState, Segmented, Signal } from "./common";
import { stableKeys } from "./keys";

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
function TimingBar({ t }: { t: Timings }) {
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

/**
 * One connection attempt as a table row: time, (with `client`, the client's
 * name), result, AP, network, signal and time to connect.
 */
function AttemptRow({
  a,
  apName,
  client,
}: {
  a: ConnAttempt;
  apName: (mac: string) => string;
  client?: string;
}) {
  return (
    <tr>
      <td className="nowrap small">{clock(a.ts)}</td>
      {client !== undefined && (
        <td>
          <Link to={`/clients/${a.client}`}>{client}</Link>
        </td>
      )}
      <td>
        <Result a={a} />
        {a.reason && <div className="muted small">AP reason: {a.reason}</div>}
      </td>
      <td>
        <Link to={`/devices/${a.ap}`}>{apName(a.ap)}</Link>
      </td>
      <td className="small">
        {a.essid ?? "—"}
        <div className="muted">{where(a.radio, a.channel, a.bw)}</div>
      </td>
      <td>
        <Signal dbm={a.rssi} />
      </td>
      <td>
        <TimingBar t={a.timings} />
      </td>
    </tr>
  );
}

/**
 * One roam as a table row, in the same columns as `AttemptRow` (`timing`
 * leaves the time-to-connect column empty).
 */
export function RoamRow({
  r,
  apName,
  client,
  timing,
}: {
  r: Roam;
  apName: (mac: string) => string;
  client?: string;
  timing?: boolean;
}) {
  return (
    <tr>
      <td className="nowrap small">{clock(r.ts)}</td>
      {client !== undefined && (
        <td>
          <Link to={`/clients/${r.client}`}>{client}</Link>
        </td>
      )}
      <td>
        <span className={`tag ${r.success ? "tag-info" : "tag-bad"}`}>
          {r.success
            ? "Roamed"
            : `Roam failed${r.gap_s ? `, off for ${r.gap_s}s` : ""}`}
        </span>
        <div className="muted small">
          {[
            r.fast && "fast roaming (802.11r)",
            r.min_rssi && "pushed by minimum RSSI",
            r.assistant && "roaming assistant",
          ]
            .filter(Boolean)
            .join(" · ")}
        </div>
      </td>
      <td className="small">
        <Link to={`/devices/${r.from.ap}`}>{apName(r.from.ap)}</Link> →{" "}
        <Link to={`/devices/${r.to.ap}`}>{apName(r.to.ap)}</Link>
      </td>
      <td className="small">
        {r.to.essid ?? "—"}
        <div className="muted">
          {band(r.from.radio)} → {where(r.to.radio, r.to.channel, r.to.bw)}
        </div>
      </td>
      <td className="nowrap">
        <Signal dbm={r.from.rssi} /> → <Signal dbm={r.to.rssi} />
      </td>
      {timing && <td />}
    </tr>
  );
}

/**
 * The head of a table of `AttemptRow`s and `RoamRow`s: `client` adds the
 * client column; `roamsOnly` (roams, no attempts) names the AP column
 * "From → to" and leaves out time to connect.
 */
export function ConnHead({
  client,
  roamsOnly,
}: {
  client?: boolean;
  roamsOnly?: boolean;
}) {
  return (
    <thead>
      <tr>
        <th>Time</th>
        {client && <th>Client</th>}
        <th>Result</th>
        <th>{roamsOnly ? "From → to" : "Access point"}</th>
        <th>Network</th>
        <th>Signal</th>
        {!roamsOnly && <th>Time to connect</th>}
      </tr>
    </thead>
  );
}

/** A roam's row key. */
export const roamId = (r: Roam) =>
  `r-${r.ts}-${r.client}-${r.from.ap}-${r.to.ap}`;

type Item =
  | { kind: "attempt"; ts: number; a: ConnAttempt; key: string }
  | { kind: "roam"; ts: number; r: Roam; key: string };

const attemptId = (a: ConnAttempt) => `a-${a.ts}-${a.client}-${a.ap}`;

/** Rows a client's log shows (attempts and roams merged, newest first). */
const LOG_ROWS = 100;
/** Rows the site's attempt list shows. */
const ATTEMPT_ROWS = 200;

/** One client's connection attempts and roams, newest first. */
export function ConnectionLog({
  client,
  span,
}: {
  client: string;
  span: TimeSpan;
}) {
  const c = useConnections(span, { client, limit: LOG_ROWS });
  return (
    <QueryState q={c}>{(data) => <ConnectionTable data={data} />}</QueryState>
  );
}

function ConnectionTable({ data }: { data: Connections }) {
  const ap = (m: string) => data.ap_names[m] ?? m;
  // A roam also shows up as the attempt on the new AP; keep just the roam.
  const roamsTo = new Map<string, number[]>();
  for (const r of data.roams) {
    const times = roamsTo.get(r.to.ap);
    if (times) times.push(r.ts);
    else roamsTo.set(r.to.ap, [r.ts]);
  }
  const isRoamJoin = (a: ConnAttempt) =>
    a.roam && !!roamsTo.get(a.ap)?.some((ts) => Math.abs(ts - a.ts) <= 15);
  const attempts = data.attempts.filter((a) => !isRoamJoin(a));
  const attemptKeys = stableKeys(attempts, attemptId);
  const roamKeys = stableKeys(data.roams, roamId);
  const items: Item[] = [
    ...attempts.map((a, i) => ({
      kind: "attempt" as const,
      ts: a.ts,
      a,
      key: attemptKeys[i]!,
    })),
    ...data.roams.map((r, i) => ({
      kind: "roam" as const,
      ts: r.ts,
      r,
      key: roamKeys[i]!,
    })),
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
      <ConnHead />
      <tbody>
        {items
          .slice(0, LOG_ROWS)
          .map((it) =>
            it.kind === "attempt" ? (
              <AttemptRow key={it.key} a={it.a} apName={ap} />
            ) : (
              <RoamRow key={it.key} r={it.r} apName={ap} timing />
            ),
          )}
      </tbody>
    </table>
  );
}

const WHICH = [
  [false, "All"],
  [true, "Failed only"],
] as const;

/** Connection attempts across the site, newest first. */
export function AttemptList({ span }: { span: TimeSpan }) {
  const [failed, setFailed] = useState(false);
  const c = useConnections(span, { failed, limit: ATTEMPT_ROWS, roams: false });
  return (
    <div className="panel">
      <div className="panel-head">
        <b>Connection attempts</b>
        <span className="muted small">
          from the APs' connection-tracking reports
        </span>
        <span className="spacer" />
        <Segmented
          label="Which attempts"
          options={WHICH}
          value={failed}
          onChange={setFailed}
        />
      </div>
      <QueryState q={c}>
        {(data) =>
          data.attempts.length === 0 ? (
            <div className="muted small">
              {failed
                ? "No failed attempts in this range."
                : "No attempts in this range."}
            </div>
          ) : (
            <AttemptTable data={data} />
          )
        }
      </QueryState>
    </div>
  );
}

function AttemptTable({ data }: { data: Connections }) {
  const keys = stableKeys(data.attempts, attemptId);
  return (
    <div className="table-wrap">
      <table className="table">
        <ConnHead client />
        <tbody>
          {data.attempts.map((a, i) => (
            <AttemptRow
              key={keys[i]}
              a={a}
              apName={(m) => data.ap_names[m] ?? m}
              client={data.client_names[a.client] ?? a.client}
            />
          ))}
        </tbody>
      </table>
    </div>
  );
}
