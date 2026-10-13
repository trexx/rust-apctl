import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import {
  setAlias,
  useClients,
  useClient,
  useDevices,
  useEvents,
  useMe,
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
  Loading,
  Signal,
  Stat,
  clientNames,
  deviceNames,
} from "../components/common";
import { ago, band, bitrate, bytes, duration, phy } from "../format";
import { serviceNames } from "../components/Insights";
import type { ClientView, Multicast } from "../api";

export function Client() {
  const { mac = "" } = useParams();
  const [range, setRange] = useTimeSpan(6 * 3600);
  const client = useClient(mac);
  const devices = useDevices();
  const names = deviceNames(devices.data);
  const clients = useClients();
  const cnames = clientNames(clients.data);
  // Clients not seen in this run still have their stored name and alias in the list.
  const listed = clients.data?.find((x) => x.sample.mac === mac);
  const events = useEvents({ client: mac, limit: 100 });
  const series = useSeries("client", mac, range);

  const c = client.data;
  const s = c?.sample;
  const f = series.data?.fields;
  const ts = series.data?.ts ?? [];
  const bits = (a: (number | null)[] | undefined) =>
    (a ?? []).map((v) => (v === null ? null : v * 8));
  const mbps = (a: (number | null)[] | undefined) =>
    (a ?? []).map((v) => (v === null ? null : v / 1000));

  return (
    <ZoomContext.Provider value={(from, to) => setRange({ from, to })}>
      <SpanContext.Provider value={range}>
        <div className="page">
          <div className="page-head">
            <AliasHeader
              mac={mac}
              connected={c?.connected}
              alias={c?.alias ?? listed?.alias ?? null}
              note={c?.note ?? listed?.note ?? null}
              hostname={s?.hostname ?? listed?.sample.hostname ?? null}
            />
            <span className="spacer" />
            <RangePicker value={range} onChange={setRange} />
          </div>
          {client.error && (
            <div className="banner">
              Not seen since the controller started; showing stored history
              only.
            </div>
          )}

          {s && c && (
            <div className="stats">
              <Stat
                label="Connected to"
                value={
                  c.connected ? (
                    <Link to={`/devices/${s.ap_mac}`}>
                      {names.get(s.ap_mac) ?? s.ap_mac}
                    </Link>
                  ) : (
                    "Disconnected"
                  )
                }
                sub={
                  c.connected
                    ? `${s.essid} · ${band(s.radio)} ch ${s.channel}`
                    : `last seen ${ago(c.last_seen)}`
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

          {!series.data ? (
            series.error ? (
              <ErrorNote error={series.error} />
            ) : (
              <Loading />
            )
          ) : (
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
                      values: f!.signal,
                      color: COLORS.blue,
                      fill: true,
                    },
                    { label: "Noise", values: f!.noise, color: COLORS.red },
                  ]}
                />
                <Chart
                  title="PHY rate"
                  ts={ts}
                  format={(v) => `${Math.round(v)} Mbps`}
                  series={[
                    {
                      label: "Down (AP→client)",
                      values: mbps(f!.tx_rate),
                      color: COLORS.green,
                    },
                    {
                      label: "Up (client→AP)",
                      values: mbps(f!.rx_rate),
                      color: COLORS.purple,
                    },
                  ]}
                />
              </div>
              <div className="panel">
                <Chart
                  title="Throughput"
                  ts={ts}
                  format={(v) => bitrate(v / 8)}
                  series={[
                    {
                      label: "Down",
                      values: bits(f!.tx_bytes),
                      color: COLORS.blue,
                      fill: true,
                    },
                    {
                      label: "Up",
                      values: bits(f!.rx_bytes),
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
                      values: f!.tx_retries,
                      color: COLORS.orange,
                    },
                    {
                      label: "Latency (ms)",
                      values: f!.latency_avg,
                      color: COLORS.teal,
                    },
                  ]}
                />
              </div>
            </div>
          )}

          {s?.multicast && (
            <ClientMulticast
              mac={mac}
              m={s.multicast}
              all={clients.data ?? []}
            />
          )}

          <h2>Timeline</h2>
          <div className="panel">
            {events.data ? (
              <EventList
                events={events.data}
                names={names}
                clientNames={cnames}
              />
            ) : (
              <Loading />
            )}
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
  const qc = useQueryClient();
  const readOnly = useMe().data?.read_only ?? false;
  const [editing, setEditing] = useState(false);
  const [alias, setAliasText] = useState("");
  const [note, setNote] = useState("");
  const save = useMutation({
    mutationFn: (v: { alias: string; note: string }) =>
      setAlias(p.mac, v.alias, v.note),
    onSuccess: () => {
      setEditing(false);
      // The engine applies the change asynchronously; the live socket also refreshes.
      window.setTimeout(
        () => void qc.invalidateQueries({ queryKey: ["client", p.mac] }),
        300,
      );
      window.setTimeout(
        () => void qc.invalidateQueries({ queryKey: ["clients"] }),
        300,
      );
    },
  });
  const start = () => {
    setAliasText(p.alias ?? "");
    setNote(p.note ?? "");
    save.reset();
    setEditing(true);
  };

  if (editing) {
    return (
      <form
        className="alias-form"
        onSubmit={(e) => {
          e.preventDefault();
          save.mutate({ alias, note });
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
        <button type="submit" className="btn primary" disabled={save.isPending}>
          Save
        </button>
        <button type="button" className="btn" onClick={() => setEditing(false)}>
          Cancel
        </button>
        {save.error && (
          <span className="error small">{save.error.message}</span>
        )}
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
        {!readOnly && (
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

const TYPE_LABEL: Record<string, string> = {
  mdns: "mDNS (device discovery)",
  ssdp: "SSDP / UPnP",
  arp: "ARP",
  igmp: "IGMP (group joins)",
  mld: "MLD (IPv6 group joins)",
  stream: "Streams (video, audio)",
  dhcp: "DHCP",
  dhcpv6: "DHCPv6",
  ipv6_nd: "IPv6 neighbour discovery",
  other: "Other",
};

const n = (x: number) =>
  new Intl.NumberFormat("en-GB", { notation: "compact" }).format(x);

/** What this client sends and receives as multicast/broadcast, from the AP's latest report. */
function ClientMulticast({
  mac,
  m,
  all,
}: {
  mac: string;
  m: Multicast;
  all: ClientView[];
}) {
  const types = Object.entries(m.types)
    .filter(([, c]) => c.tx_pkts + c.rx_pkts > 0)
    .sort(
      (a, b) => b[1].rx_pkts + b[1].tx_pkts - (a[1].rx_pkts + a[1].tx_pkts),
    );
  // Other clients that joined the same groups.
  const peers = (group: string) =>
    all
      .filter(
        (c) =>
          c.sample.mac !== mac &&
          c.sample.multicast?.memberships.includes(group),
      )
      .map((c) => c.alias || c.sample.hostname || c.sample.mac);
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
                    <td>{TYPE_LABEL[k] ?? k}</td>
                    <td>{n(c.rx_pkts)}</td>
                    <td>{n(c.tx_pkts)}</td>
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
                  const p = peers(g);
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
