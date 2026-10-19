import { useState } from "react";
import { Link } from "react-router";
import { useMulticast } from "../../api";
import type { SiteMulticast, TimeSpan } from "../../api";
import { compact, spanText } from "../../format";
import { COLORS, Chart } from "../Chart";
import { QueryState, Segmented, THead } from "../common";
import { SpanContext } from "../span";

const DIRECTIONS = [
  ["tx", "To clients"],
  ["rx", "From clients"],
] as const;

// The types beyond the six chart colours take the page's extra --c-* ones,
// which also have a dark-mode shade.
const MCAST_COLORS: Record<string, string> = {
  mdns: COLORS.blue,
  ssdp: COLORS.purple,
  arp: COLORS.orange,
  igmp: COLORS.green,
  mld: "var(--c-olive)",
  stream: COLORS.red,
  dhcp: COLORS.teal,
  dhcpv6: "var(--c-steel)",
  ipv6_nd: "var(--c-pink)",
  other: "var(--c-grey)",
};

/** Multicast traffic types: a short name for charts and a longer one for tables. */
const MCAST_TYPES: Record<string, [short: string, long: string]> = {
  mdns: ["mDNS", "mDNS (device discovery)"],
  ssdp: ["SSDP", "SSDP / UPnP"],
  arp: ["ARP", "ARP"],
  igmp: ["IGMP", "IGMP (group joins)"],
  mld: ["MLD", "MLD (IPv6 group joins)"],
  stream: ["Streams", "Streams (video, audio)"],
  dhcp: ["DHCP", "DHCP"],
  dhcpv6: ["DHCPv6", "DHCPv6"],
  ipv6_nd: ["IPv6 ND", "IPv6 neighbour discovery"],
  other: ["Other", "Other"],
};

const TYPE_ORDER = Object.keys(MCAST_TYPES);

/** A multicast traffic type's name, short or long. */
export const mcastLabel = (type: string, long = false) =>
  MCAST_TYPES[type]?.[long ? 1 : 0] ?? type;

/** Multicast and broadcast by traffic type, and the clients behind it. */
export function MulticastPanel({
  mac,
  span,
  title,
}: {
  mac?: string;
  span: TimeSpan;
  title?: string;
}) {
  const [dir, setDir] = useState<"tx" | "rx">("tx");
  const m = useMulticast(span, mac);
  return (
    <QueryState q={m} panel>
      {(data) => (
        <MulticastView
          data={data}
          mac={mac}
          span={span}
          title={title ?? "Multicast and broadcast"}
          dir={dir}
          setDir={setDir}
        />
      )}
    </QueryState>
  );
}

function MulticastView({
  data,
  mac,
  span,
  title,
  dir,
  setDir,
}: {
  data: SiteMulticast;
  mac?: string;
  span: TimeSpan;
  title: string;
  dir: "tx" | "rx";
  setDir: (d: "tx" | "rx") => void;
}) {
  // The chart's series keep a fixed order (MCAST_TYPES', then any unknown
  // type by name), so a change in the ranking pushes new data instead of
  // rebuilding the chart; only the legend below is ranked by count.
  const order = (k: string) => {
    const i = TYPE_ORDER.indexOf(k);
    return i < 0 ? TYPE_ORDER.length : i;
  };
  const kinds = Object.entries(data.types)
    .filter(([, v]) => v.tx_pkts + v.rx_pkts > 0)
    .sort(([a], [b]) => order(a) - order(b) || a.localeCompare(b));
  const ranked = [...kinds].sort(
    (a, b) => b[1][`${dir}_pkts`] - a[1][`${dir}_pkts`],
  );
  return (
    <div className="panel">
      <div className="panel-head">
        <b>{title}</b>
        <span className="muted small">{spanText(span)}</span>
        <span className="spacer" />
        <Segmented
          label="Direction"
          options={DIRECTIONS}
          value={dir}
          onChange={setDir}
        />
      </div>
      <div className="mcast-stack">
        <div>
          <SpanContext.Provider value={span}>
            <Chart
              title={`Packets per second by type, ${dir === "tx" ? "delivered to clients" : "sent by clients"}`}
              ts={data.ts}
              height={160}
              min={0}
              format={(v) => `${v.toFixed(v < 10 ? 1 : 0)}/s`}
              series={kinds.map(([k, v]) => ({
                label: mcastLabel(k),
                values: v[`${dir}_pps`],
                color: MCAST_COLORS[k] ?? COLORS.teal,
              }))}
            />
          </SpanContext.Provider>
          <div className="mcast-types small">
            {ranked.map(([k, v]) => (
              <span key={k}>
                <i
                  className="swatch"
                  style={{
                    background: MCAST_COLORS[k] ?? COLORS.teal,
                    borderColor: MCAST_COLORS[k] ?? COLORS.teal,
                  }}
                />{" "}
                {mcastLabel(k)} <b>{compact(v[`${dir}_pkts`])}</b>
              </span>
            ))}
          </div>
        </div>
        {data.clients.length > 0 && (
          <table className="table mcast-clients">
            <THead
              columns={[
                "Client",
                ["Sent", "Multicast and broadcast packets the client sent"],
                [
                  "Received",
                  "Multicast and broadcast packets its network delivered while it was connected",
                ],
                "Services",
                "Delivery",
              ]}
            />
            <tbody>
              {data.clients.slice(0, 8).map((c) => (
                <tr key={c.mac}>
                  <td>
                    <Link to={`/clients/${c.mac}`}>{c.name ?? c.mac}</Link>
                    <div className="muted small">
                      {[c.vendor, !mac && c.ap].filter(Boolean).join(" · ")}
                    </div>
                  </td>
                  <td className="nowrap">{compact(c.rx_pkts)} pkts</td>
                  <td className="nowrap">{compact(c.tx_pkts)} pkts</td>
                  <td className="small">
                    {c.services.length
                      ? serviceNames(c.services).slice(0, 3).join(", ")
                      : "—"}
                  </td>
                  <td
                    className="small"
                    title={
                      c.delivery === "flooding"
                        ? "Joined groups are flooded to every client"
                        : c.delivery === "optimized"
                          ? "Only sent to clients that joined"
                          : undefined
                    }
                  >
                    {c.delivery ?? "—"}
                    {c.memberships > 0 && (
                      <span className="muted"> · {c.memberships} groups</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

const SERVICES: [RegExp, string][] = [
  [/_airplay|_raop/, "AirPlay"],
  [/_googlecast|_googlezone/, "Chromecast"],
  [/_ipp|_printer|_pdl-datastream|_scanner|_uscan/, "Printers"],
  [/_spotify/, "Spotify Connect"],
  [/_homekit|_hap\./, "HomeKit"],
  [/_companion-link|_rdlink|_apple-mobdev|_sleep-proxy/, "Apple devices"],
  [/_androidtvremote|_amzn|_nvstream/, "TV remotes"],
  [/_smb|_afpovertcp|_nfs/, "File sharing"],
  [/_matter/, "Matter"],
  [/_hue|_homeconnect|_miio|_esphomelib/, "Smart home"],
];

/** Friendly names for the mDNS service types a client used. */
export function serviceNames(
  services: { name: string; pkts: number }[],
): string[] {
  const out = new Map<string, number>();
  for (const s of services) {
    const name =
      SERVICES.find(([re]) => re.test(s.name))?.[1] ??
      (s.name.startsWith("_services._dns-sd") ? null : "Others");
    if (name) out.set(name, (out.get(name) ?? 0) + s.pkts);
  }
  return [...out.entries()].sort((a, b) => b[1] - a[1]).map(([n]) => n);
}
