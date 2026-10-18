import { memo, useDeferredValue, useState } from "react";
import { Link } from "react-router";
import { AttemptList } from "../components/Connections";
import { RangePicker, SpanContext, useTimeSpan } from "../components/Chart";
import { displayName, useClients } from "../api";
import type { ClientView } from "../api";
import {
  ErrorNote,
  Loading,
  Segmented,
  Signal,
  Toggle,
  useUrlTab,
} from "../components/common";
import { ago, bandChannel, duration, phy, useNow } from "../format";

type SortKey =
  | "name"
  | "ap"
  | "essid"
  | "signal"
  | "rate"
  | "uptime"
  | "last_seen";

function value(c: ClientView, key: SortKey): string | number {
  switch (key) {
    case "name":
      return displayName(c).toLowerCase();
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

type Sort = { key: SortKey; desc: boolean };

/** A sortable column's header. */
function SortHeader({
  k,
  label,
  sort,
  onSort,
}: {
  k: SortKey;
  label: string;
  sort: Sort;
  onSort: () => void;
}) {
  const on = sort.key === k;
  return (
    <th aria-sort={on ? (sort.desc ? "descending" : "ascending") : "none"}>
      <button className="plain sortable" onClick={onSort}>
        {label} {on ? (sort.desc ? "↓" : "↑") : ""}
      </button>
    </th>
  );
}

function ClientList({ tabs }: { tabs: React.ReactNode }) {
  const clients = useClients();
  const [filter, setFilter] = useState("");
  const [showGone, setShowGone] = useState(false);
  const [sort, setSort] = useState<Sort>({
    key: "signal",
    desc: true,
  });

  // Typing stays responsive however many clients there are: the list
  // follows the filter when React has time.
  const f = useDeferredValue(filter).trim().toLowerCase();
  // What "last seen" counts from: a minute's ticks.
  const now = useNow();
  const rows = (clients.data ?? [])
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
    // Each client's key worked out once, not in every comparison.
    .map((c) => [value(c, sort.key), c] as const)
    .sort(([x], [y]) => {
      const cmp = x < y ? -1 : x > y ? 1 : 0;
      return sort.desc ? -cmp : cmp;
    })
    .map(([, c]) => c);

  // What was fetched stays up when a refetch fails.
  if (!clients.data)
    return clients.error ? <ErrorNote error={clients.error} /> : <Loading />;

  const th = (key: SortKey, label: string) => (
    <SortHeader
      k={key}
      label={label}
      sort={sort}
      onSort={() =>
        setSort((s) => ({
          key,
          desc: s.key === key ? !s.desc : key !== "name",
        }))
      }
    />
  );

  return (
    <div className="page">
      <div className="page-head">
        <h1>Clients</h1>
        {tabs}
        <span className="muted">{rows.length} shown</span>
        <span className="spacer" />
        <Toggle
          value={showGone}
          onChange={setShowGone}
          label="include disconnected"
        />
        <input
          className="search"
          aria-label="Filter clients"
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
              // Only a disconnected row shows how long ago it was seen, so a
              // connected one needn't re-render as time passes.
              <ClientRow key={c.sample.mac} c={c} now={c.connected ? 0 : now} />
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/**
 * One client. A refetch keeps an unchanged client's object (React Query's
 * structural sharing), so only the changed rows re-render, and the
 * disconnected ones once a minute for their "last seen".
 */
const ClientRow = memo(function ClientRow({
  c,
  now,
}: {
  c: ClientView;
  /** What "last seen" counts from (`useNow()`); unused while connected. */
  now: number;
}) {
  return (
    <tr className={c.connected ? "" : "dim"}>
      <td>
        <Link to={`/clients/${c.sample.mac}`} title={c.note ?? undefined}>
          {displayName(c)}
        </Link>
        <div className="small muted">
          {c.alias && c.sample.hostname ? `${c.sample.hostname} · ` : ""}
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
      <td>{bandChannel(c.sample.radio, c.sample.channel)}</td>
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
      <td>{c.connected ? "now" : ago(c.last_seen, now)}</td>
    </tr>
  );
});
