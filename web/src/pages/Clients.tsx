import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { AttemptList } from "../components/Connections";
import { RangePicker, SpanContext, useTimeSpan } from "../components/Chart";
import { displayName, useClients } from "../api";
import type { ClientView } from "../api";
import {
  ErrorNote,
  Loading,
  Signal,
  Segmented,
  useUrlTab,
} from "../components/common";
import { ago, band, duration, phy } from "../format";

type SortKey =
  "name" | "ap" | "essid" | "signal" | "rate" | "uptime" | "last_seen";

const name = displayName;

function value(c: ClientView, key: SortKey): string | number {
  switch (key) {
    case "name":
      return name(c).toLowerCase();
    case "ap":
      return (c.ap_name ?? "").toLowerCase();
    case "essid":
      return (c.sample.essid ?? "").toLowerCase();
    case "signal":
      return c.sample.signal ?? -999;
    case "rate":
      return c.sample.tx_rate ?? 0;
    case "uptime":
      return c.connected ? (c.sample.uptime ?? 0) : -1;
    case "last_seen":
      return c.last_seen ?? 0;
  }
}

const TABS = [
  ["clients", "Clients"],
  ["attempts", "Connection attempts"],
] as const;

export function Clients() {
  const [tab, setTab] = useUrlTab(TABS);
  const tabs = <Segmented tabs options={TABS} value={tab} onChange={setTab} />;
  return tab === "attempts" ? (
    <Attempts tabs={tabs} />
  ) : (
    <ClientList tabs={tabs} />
  );
}

function Attempts({ tabs }: { tabs: React.ReactNode }) {
  const [span, setSpan] = useTimeSpan(86400);
  return (
    <SpanContext.Provider value={span}>
      <div className="page">
        <div className="page-head">
          <h1>Clients</h1>
          {tabs}
          <span className="spacer" />
          <RangePicker value={span} onChange={setSpan} />
        </div>
        <AttemptList span={span} />
      </div>
    </SpanContext.Provider>
  );
}

function ClientList({ tabs }: { tabs: React.ReactNode }) {
  const clients = useClients();
  const [filter, setFilter] = useState("");
  const [showGone, setShowGone] = useState(false);
  const [sort, setSort] = useState<{ key: SortKey; desc: boolean }>({
    key: "signal",
    desc: true,
  });

  const rows = useMemo(() => {
    const f = filter.trim().toLowerCase();
    return (clients.data ?? [])
      .filter((c) => showGone || c.connected)
      .filter(
        (c) =>
          !f ||
          [
            c.alias,
            c.note,
            c.sample.hostname,
            c.sample.mac,
            c.sample.ip,
            c.sample.essid,
            c.ap_name,
          ].some((v) => v?.toLowerCase().includes(f)),
      )
      .sort((a, b) => {
        const [x, y] = [value(a, sort.key), value(b, sort.key)];
        const cmp = x < y ? -1 : x > y ? 1 : 0;
        return sort.desc ? -cmp : cmp;
      });
  }, [clients.data, filter, showGone, sort]);

  if (clients.isLoading) return <Loading />;
  if (clients.error) return <ErrorNote error={clients.error} />;

  const th = (key: SortKey, label: string) => (
    <th
      className="sortable"
      onClick={() =>
        setSort((s) => ({
          key,
          desc: s.key === key ? !s.desc : key !== "name",
        }))
      }
      aria-sort={
        sort.key === key ? (sort.desc ? "descending" : "ascending") : "none"
      }
    >
      {label} {sort.key === key ? (sort.desc ? "↓" : "↑") : ""}
    </th>
  );

  return (
    <div className="page">
      <div className="page-head">
        <h1>Clients</h1>
        {tabs}
        <span className="muted">{rows.length} shown</span>
        <span className="spacer" />
        <label className="check">
          <input
            type="checkbox"
            checked={showGone}
            onChange={(e) => setShowGone(e.target.checked)}
          />{" "}
          include disconnected
        </label>
        <input
          className="search"
          placeholder="Filter by name, note, MAC, IP, SSID or AP"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
        />
      </div>
      <div className="panel">
        <table className="table">
          <thead>
            <tr>
              {th("name", "Client")}
              <th>IP</th>
              {th("ap", "AP")}
              {th("essid", "SSID")}
              <th>Band</th>
              {th("signal", "Signal")}
              {th("rate", "Rate (down/up)")}
              <th>Wi-Fi</th>
              {th("uptime", "Connected")}
              {th("last_seen", "Last seen")}
            </tr>
          </thead>
          <tbody>
            {rows.map((c) => (
              <tr key={c.sample.mac} className={c.connected ? "" : "dim"}>
                <td>
                  <Link
                    to={`/clients/${c.sample.mac}`}
                    title={c.note ?? undefined}
                  >
                    {name(c)}
                  </Link>
                  <div className="small muted">
                    {c.alias && c.sample.hostname
                      ? `${c.sample.hostname} · `
                      : ""}
                    {(c.alias || c.sample.hostname) && (
                      <span className="mono">{c.sample.mac}</span>
                    )}
                  </div>
                </td>
                <td className="mono">{c.sample.ip ?? "—"}</td>
                <td>
                  {c.sample.ap_mac ? (
                    <Link to={`/devices/${c.sample.ap_mac}`}>
                      {c.ap_name ?? c.sample.ap_mac}
                    </Link>
                  ) : (
                    "—"
                  )}
                </td>
                <td>{c.sample.essid ?? "—"}</td>
                <td>
                  {band(c.sample.radio)}
                  {c.sample.channel ? ` ch ${c.sample.channel}` : ""}
                </td>
                <td>{c.connected ? <Signal dbm={c.sample.signal} /> : "—"}</td>
                <td>
                  {c.connected
                    ? `${phy(c.sample.tx_rate)} / ${phy(c.sample.rx_rate)}`
                    : "—"}
                </td>
                <td>
                  {c.sample.wifi_gen
                    ? `802.11${c.sample.wifi_gen}${c.sample.nss ? ` ${c.sample.nss}×${c.sample.nss}` : ""}`
                    : "—"}
                </td>
                <td>{c.connected ? duration(c.sample.uptime) : "—"}</td>
                <td>{c.connected ? "now" : ago(c.last_seen)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
