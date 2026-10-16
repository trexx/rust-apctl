import { useState } from "react";
import { Link } from "react-router-dom";
import { useConnections } from "../api";
import type { ConnAttempt, Roam, TimeSpan, Timings } from "../api";
import { band, clock } from "../format";
import { QueryState, Signal } from "./common";

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
  | { kind: "attempt"; ts: number; a: ConnAttempt; key: string }
  | { kind: "roam"; ts: number; r: Roam; key: string };

/** Keys from what identifies each row, numbered when two rows share one. */
function stableKeys<T>(rows: T[], id: (row: T) => string): string[] {
  const seen = new Map<string, number>();
  return rows.map((row) => {
    const k = id(row);
    const n = seen.get(k) ?? 0;
    seen.set(k, n + 1);
    return n ? `${k}#${n}` : k;
  });
}

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

function ConnectionTable({
  data,
}: {
  data: NonNullable<ReturnType<typeof useConnections>["data"]>;
}) {
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
  const roamKeys = stableKeys(
    data.roams,
    (r) => `r-${r.ts}-${r.client}-${r.from.ap}-${r.to.ap}`,
  );
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
        {items.slice(0, LOG_ROWS).map((it) =>
          it.kind === "attempt" ? (
            <tr key={it.key}>
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
            <tr key={it.key}>
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
  const c = useConnections(span, { failed, limit: ATTEMPT_ROWS });
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

function AttemptTable({
  data,
}: {
  data: NonNullable<ReturnType<typeof useConnections>["data"]>;
}) {
  const keys = stableKeys(data.attempts, attemptId);
  return (
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
          {data.attempts.map((a, i) => (
            <tr key={keys[i]}>
              <td className="nowrap small">{clock(a.ts)}</td>
              <td>
                <Link to={`/clients/${a.client}`}>
                  {data.client_names[a.client] ?? a.client}
                </Link>
              </td>
              <td>
                <Result a={a} />
              </td>
              <td>
                <Link to={`/devices/${a.ap}`}>
                  {data.ap_names[a.ap] ?? a.ap}
                </Link>
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
          ))}
        </tbody>
      </table>
    </div>
  );
}
