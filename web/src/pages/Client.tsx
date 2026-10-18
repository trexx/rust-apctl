import { useState } from "react";
import { Link, useParams } from "react-router";
import {
  HttpError,
  displayName,
  keys,
  setAlias,
  useCanEdit,
  useClient,
  useDeviceNames,
  useEvents,
  useSeries,
} from "../api";
import {
  COLORS,
  Chart,
  RangePicker,
  SpanContext,
  ZoomContext,
  useTimeSpan,
} from "../components/Chart";
import {
  Dot,
  ErrorNote,
  EventList,
  QueryState,
  Signal,
  Stat,
  useRunner,
} from "../components/common";
import {
  ago,
  bandChannel,
  bytes,
  compact,
  duration,
  phy,
  rate,
  useNow,
} from "../format";
import { mcastLabel, serviceNames } from "../components/insights/Multicast";
import { ConnectionLog } from "../components/Connections";
import { ClientActions } from "../components/Actions";
import type { GroupMember, Multicast } from "../api";

/** Keyed by MAC: nothing typed or shown for one client carries over to the next. */
export function Client() {
  const mac = useParams().mac ?? "";
  return <ClientPage key={mac} mac={mac} />;
}

function ClientPage({ mac }: { mac: string }) {
  const [range, setRange] = useTimeSpan(6 * 3600);
  const client = useClient(mac);
  const names = useDeviceNames();
  const now = useNow();
  const c = client.data;
  const s = c?.sample;
  const events = useEvents({ client: mac, limit: 100 });
  const series = useSeries("client", mac, range);

  // The client list and this client's view come from the same live view, so
  // a client the server doesn't know (404) is in neither: only its MAC and
  // stored history show.
  const name = c ? displayName(c) : mac;
  // Every event in the timeline is this client's (a MAC alone shows as one).
  const cnames = name !== mac ? { [mac]: name } : {};
  // What was fetched stays up when a refetch fails.
  const unknown =
    !c && client.error instanceof HttpError && client.error.status === 404;

  return (
    <ZoomContext.Provider value={(from, to) => setRange({ from, to })}>
      <SpanContext.Provider value={range}>
        <div className="page">
          <div className="page-head">
            <AliasHeader
              mac={mac}
              connected={c?.connected}
              alias={c?.alias ?? null}
              note={c?.note ?? null}
              hostname={c?.sample.hostname ?? null}
            />
            <span className="spacer" />
            <RangePicker value={range} onChange={setRange} />
          </div>
          <ClientActions
            mac={mac}
            name={name}
            connected={c?.connected ?? false}
            blocked={c?.blocked ?? false}
            lockedTo={c?.locked_to ?? null}
            aps={names}
            usergroupId={c?.usergroup_id ?? null}
          />
          {c?.blocked && (
            <div className="banner">
              Blocked: no AP lets this device join any SSID.
            </div>
          )}
          {c?.locked_to && (
            <div className="banner">
              Locked to {names[c.locked_to] ?? c.locked_to}: the other APs
              refuse it.
            </div>
          )}
          {unknown ? (
            <div className="banner">
              Not seen since the controller started; showing stored history
              only.
            </div>
          ) : (
            !c && client.error && <ErrorNote error={client.error} />
          )}

          {s && c && (
            <div className="stats">
              <Stat
                label="Connected to"
                value={
                  c.connected ? (
                    <Link to={`/devices/${s.ap_mac}`}>
                      {names[s.ap_mac] ?? s.ap_mac}
                    </Link>
                  ) : (
                    "Disconnected"
                  )
                }
                sub={
                  c.connected
                    ? `${s.essid ?? "—"} · ${bandChannel(s.radio, s.channel)}`
                    : `last seen ${ago(c.last_seen, now)}`
                }
              />
              <Stat
                label="Signal"
                value={<Signal dbm={s.signal} />}
                sub={`noise ${s.noise ?? "—"} dBm`}
              />
              <Stat
                label="Rate (down/up)"
                value={`${phy(s.tx_rate)} / ${phy(s.rx_rate)}`}
                sub={
                  s.wifi_gen
                    ? `802.11${s.wifi_gen}, ${s.nss ?? "?"} streams`
                    : ""
                }
              />
              <Stat
                label="Session"
                value={duration(s.uptime)}
                sub={`${bytes(s.tx_bytes)} down · ${bytes(s.rx_bytes)} up · satisfaction ${s.satisfaction ?? "—"}`}
              />
            </div>
          )}

          <QueryState q={series}>
            {({ ts, fields: f }) => (
              <div className="grid2">
                <div className="panel">
                  <Chart
                    title="Signal and noise"
                    ts={ts}
                    format={(v) => `${Math.round(v)} dBm`}
                    min={-100}
                    max={-20}
                    series={[
                      {
                        label: "Signal",
                        values: f.signal,
                        color: COLORS.blue,
                        fill: true,
                      },
                      { label: "Noise", values: f.noise, color: COLORS.red },
                    ]}
                  />
                  <Chart
                    title="PHY rate"
                    ts={ts}
                    format={(v) => `${Math.round(v)} Mbps`}
                    series={[
                      {
                        label: "Down (AP→client)",
                        values: f.tx_rate,
                        scale: 1 / 1000,
                        color: COLORS.green,
                      },
                      {
                        label: "Up (client→AP)",
                        values: f.rx_rate,
                        scale: 1 / 1000,
                        color: COLORS.purple,
                      },
                    ]}
                  />
                </div>
                <div className="panel">
                  <Chart
                    title="Throughput"
                    ts={ts}
                    format={rate}
                    series={[
                      {
                        label: "Down",
                        values: f.tx_bytes,
                        scale: 8,
                        color: COLORS.blue,
                        fill: true,
                      },
                      {
                        label: "Up",
                        values: f.rx_bytes,
                        scale: 8,
                        color: COLORS.purple,
                      },
                    ]}
                  />
                  <Chart
                    title="Retries and latency"
                    ts={ts}
                    format={(v) => v.toFixed(v < 10 ? 1 : 0)}
                    series={[
                      {
                        label: "TX retries/s",
                        values: f.tx_retries,
                        color: COLORS.orange,
                      },
                      {
                        label: "Latency (ms)",
                        values: f.latency_avg,
                        color: COLORS.teal,
                      },
                    ]}
                  />
                </div>
              </div>
            )}
          </QueryState>

          {c?.sample.multicast && (
            <ClientMulticast m={c.sample.multicast} peers={c.peers} />
          )}

          <h2>Connection log</h2>
          <div className="panel">
            <ConnectionLog client={mac} span={range} />
          </div>

          <h2>Timeline</h2>
          <div className="panel">
            <QueryState q={events}>
              {(data) => (
                <EventList events={data} names={names} clientNames={cnames} />
              )}
            </QueryState>
          </div>
        </div>
      </SpanContext.Provider>
    </ZoomContext.Provider>
  );
}

/** The client's name with an inline editor for its alias and note. */
function AliasHeader(p: {
  mac: string;
  connected?: boolean;
  alias: string | null;
  note: string | null;
  hostname: string | null;
}) {
  const canEdit = useCanEdit();
  const [editing, setEditing] = useState(false);
  const [alias, setAliasText] = useState("");
  const [note, setNote] = useState("");
  // The engine applies the change asynchronously; the live socket also refreshes.
  const { busy, msg, setMsg, run } = useRunner(
    [keys.client(p.mac), keys.clients()],
    300,
  );
  const start = () => {
    setAliasText(p.alias ?? "");
    setNote(p.note ?? "");
    setMsg(null);
    setEditing(true);
  };

  if (editing) {
    return (
      <form
        className="alias-form"
        onSubmit={(e) => {
          e.preventDefault();
          void run(async () => {
            await setAlias(p.mac, alias, note);
            setEditing(false);
          });
        }}
      >
        <input
          autoFocus
          className="search"
          maxLength={64}
          placeholder={p.hostname ?? "Name for this device"}
          value={alias}
          onChange={(e) => setAliasText(e.target.value)}
          aria-label="Alias"
        />
        <input
          className="search"
          maxLength={500}
          placeholder="Note (optional)"
          value={note}
          onChange={(e) => setNote(e.target.value)}
          aria-label="Note"
        />
        <button type="submit" className="btn primary" disabled={busy}>
          Save
        </button>
        <button type="button" className="btn" onClick={() => setEditing(false)}>
          Cancel
        </button>
        {msg && !msg.ok && <span className="error small">{msg.text}</span>}
        <span className="muted small">
          Leave both empty to remove the alias.
        </span>
      </form>
    );
  }
  return (
    <div className="alias-head">
      <h1>
        {p.connected !== undefined && <Dot ok={p.connected} />}{" "}
        {p.alias || p.hostname || p.mac}
        {canEdit && (
          <button
            className="btn small"
            onClick={start}
            title="Give this device a name you recognise"
          >
            {p.alias ? "Rename" : "Add name"}
          </button>
        )}
      </h1>
      <div className="muted small">
        {p.alias && p.hostname ? <>{p.hostname} · </> : null}
        <span className="mono">{p.mac}</span>
        {p.note ? <> · {p.note}</> : null}
      </div>
    </div>
  );
}

/** What this client sends and receives as multicast/broadcast, from the AP's latest report. */
function ClientMulticast({
  m,
  peers,
}: {
  m: Multicast;
  /** The other connected clients in each group (the server's). */
  peers: Record<string, GroupMember[]>;
}) {
  const types = Object.entries(m.types)
    .filter(([, c]) => c.tx_pkts + c.rx_pkts > 0)
    .sort(
      (a, b) => b[1].rx_pkts + b[1].tx_pkts - (a[1].rx_pkts + a[1].tx_pkts),
    );
  // Other connected clients that joined the same groups.
  const others = (group: string) => (peers[group] ?? []).map((c) => c.name);
  const services = serviceNames(m.services);
  return (
    <>
      <h2>Multicast</h2>
      <div className="grid2">
        <div className="panel">
          <div className="panel-head">
            <b>By type</b>
            <span className="muted small">packets since it connected</span>
          </div>
          {types.length === 0 ? (
            <div className="muted small">None.</div>
          ) : (
            <table className="table">
              <thead>
                <tr>
                  <th>Type</th>
                  <th>Sent</th>
                  <th>Received</th>
                </tr>
              </thead>
              <tbody>
                {types.map(([k, c]) => (
                  <tr key={k}>
                    <td>{mcastLabel(k, true)}</td>
                    <td>{compact(c.rx_pkts)}</td>
                    <td>{compact(c.tx_pkts)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {services.length > 0 && (
            <p className="small">
              <span className="muted">Services it uses or announces: </span>
              {services.join(", ")}
            </p>
          )}
        </div>
        <div className="panel">
          <div className="panel-head">
            <b>Groups joined</b>
            <span className="muted small">
              {m.memberships.length === 0
                ? "none"
                : m.groups.length
                  ? "delivered only to members"
                  : "flooded to everyone"}
            </span>
          </div>
          {m.memberships.length === 0 ? (
            <div className="muted small">
              This client hasn't joined any multicast groups.
            </div>
          ) : (
            <table className="table">
              <thead>
                <tr>
                  <th>Group</th>
                  <th>Also joined by</th>
                </tr>
              </thead>
              <tbody>
                {m.memberships.map((g) => {
                  const p = others(g);
                  return (
                    <tr key={g}>
                      <td className="mono">{g}</td>
                      <td className="small">
                        {p.length
                          ? p.slice(0, 4).join(", ") +
                            (p.length > 4 ? ` and ${p.length - 4} more` : "")
                          : "—"}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </>
  );
}
