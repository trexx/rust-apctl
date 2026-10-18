import { Link } from "react-router";
import { useRoaming } from "../api";
import type { Roaming } from "../api";
import { pct, roamTone, spanText, useNow } from "../format";
import { RangePicker, useTimeSpan } from "./Chart";
import { ConnHead, RoamRow, roamId } from "./Connections";
import { QueryState, Signal, Stat, THead } from "./common";
import { stableKeys } from "./keys";

export function RoamingView() {
  const [span, setSpan] = useTimeSpan(2 * 86400);
  const r = useRoaming(span);
  return (
    <>
      <div className="panel">
        <div className="panel-head">
          <b>Roaming</b>
          <span className="muted small">
            {spanText(span)} · from the APs' connection-tracking reports
          </span>
          <span className="spacer" />
          <RangePicker value={span} onChange={setSpan} />
        </div>
        <QueryState q={r}>{(data) => <Summary data={data} />}</QueryState>
      </div>
      {r.data && r.data.roams.length > 0 && <Details data={r.data} />}
    </>
  );
}

function Summary({ data }: { data: Roaming }) {
  const { roams: n, successes: ok, fast } = data.total;
  if (n === 0)
    return (
      <div className="muted small">
        No roams in this range. Clients roam when they move between APs on the
        same network.
      </div>
    );
  const weaker = data.clients.reduce((a, c) => a + c.to_weaker, 0);
  const back = data.clients.reduce((a, c) => a + c.quick_returns, 0);
  return (
    <div className="stats">
      <Stat
        label="Roams"
        value={n}
        sub={`${data.clients.length} client${data.clients.length === 1 ? "" : "s"}`}
      />
      <Stat
        label="Successful"
        value={
          <span className={`tone-${roamTone((100 * ok) / n)}`}>
            {pct((100 * ok) / n)}
          </span>
        }
        sub={`${n - ok} failed`}
      />
      <Stat
        label="Fast roaming (802.11r)"
        value={pct((100 * fast) / n)}
        sub={`${fast} of ${n}`}
      />
      <Stat
        label="Questionable roams"
        value={weaker + back}
        sub={`${weaker} to a weaker AP, ${back} straight back (apctl's own measure)`}
      />
    </div>
  );
}

function Details({ data }: { data: Roaming }) {
  const ap = (m: string) => data.ap_names[m] ?? m;
  const client = (m: string) => data.client_names[m] ?? m;
  const keys = stableKeys(data.roams, roamId);
  const now = useNow();
  return (
    <>
      <div className="grid2 align-top">
        <div className="panel">
          <div className="panel-head">
            <b>Between access points</b>
          </div>
          <table className="table">
            <THead
              columns={["APs", "Roams", "Success", "Fast", "Top clients"]}
            />
            <tbody>
              {data.pairs.map((p) => (
                <tr key={p.ap_1 + p.ap_2}>
                  <td className="small">
                    <Link to={`/devices/${p.ap_1}`}>{ap(p.ap_1)}</Link> ⇄{" "}
                    <Link to={`/devices/${p.ap_2}`}>{ap(p.ap_2)}</Link>
                    <div className="muted">
                      → {p.forward.attempts} · ← {p.backward.attempts}
                      {p.forward.min_rssi + p.backward.min_rssi > 0 &&
                        ` · ${p.forward.min_rssi + p.backward.min_rssi} by minimum RSSI`}
                      {p.forward.assistant + p.backward.assistant > 0 &&
                        ` · ${p.forward.assistant + p.backward.assistant} by roaming assistant`}
                    </div>
                  </td>
                  <td>{p.attempts}</td>
                  <td className={`tone-${roamTone(p.success_pct)}`}>
                    {p.success_pct}%
                  </td>
                  <td>{p.forward.fast + p.backward.fast}</td>
                  <td className="small">
                    {p.top_clients.slice(0, 3).map((c, i) => (
                      <span key={c.mac}>
                        {i > 0 && ", "}
                        <Link to={`/clients/${c.mac}`}>{client(c.mac)}</Link> (
                        {c.roams})
                      </span>
                    ))}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="panel">
          <div className="panel-head">
            <b>Clients that roam most</b>
          </div>
          <table className="table">
            <THead
              columns={[
                "Client",
                "Roams",
                ["Leaves at", "Average signal when leaving an AP"],
                ["Questionable", "apctl's own measures"],
              ]}
            />
            <tbody>
              {data.clients.slice(0, 10).map((c) => (
                <tr key={c.mac}>
                  <td>
                    <Link to={`/clients/${c.mac}`}>{client(c.mac)}</Link>
                  </td>
                  <td>
                    {c.roams}
                    {c.failed > 0 && (
                      <span className="tone-bad"> ({c.failed} failed)</span>
                    )}
                  </td>
                  <td>
                    <Signal dbm={c.avg_leave_rssi} />
                  </td>
                  <td className="small">
                    {c.to_weaker > 0 && (
                      <div className="tone-warn">
                        {c.to_weaker}× to a weaker AP
                      </div>
                    )}
                    {c.quick_returns > 0 && (
                      <div className="tone-warn">
                        {c.quick_returns}× straight back
                      </div>
                    )}
                    {c.to_weaker + c.quick_returns === 0 && (
                      <span className="muted">—</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="muted small">
            "To a weaker AP": joined an AP it heard more than 3 dB worse than
            the one it left. "Straight back": returned to the AP it had just
            left within 2 minutes. Frequent ones suggest APs overlap too much or
            transmit power is uneven.
          </p>
        </div>
      </div>
      <div className="panel">
        <div className="panel-head">
          <b>Recent roams</b>
        </div>
        <div className="table-wrap">
          <table className="table">
            <ConnHead client roamsOnly />
            <tbody>
              {data.roams.map((x, i) => (
                <RoamRow
                  key={keys[i]}
                  r={x}
                  apNames={data.ap_names}
                  client={client(x.client)}
                  now={now}
                />
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </>
  );
}
