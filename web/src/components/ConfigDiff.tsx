import type { ReactNode } from "react";
import type { ConfigPushed } from "../api";

/** What each top-level section of an AP's config is about. */
const AREA: Record<string, string> = {
  aaa: "Wi-Fi security",
  wireless: "Wi-Fi network",
  radio: "Radio",
  macacl: "MAC filter",
  netconf: "Network interface",
  bridge: "Bridge",
  vlan: "VLAN",
  mdns_sd: "mDNS",
  users: "Users",
  ntpclient: "Time servers",
  ledbar: "LED",
  led: "LED",
  mesh: "Mesh",
  sshd: "SSH",
  resolv: "DNS servers",
  dhcpc: "DHCP client",
  switch: "Switch ports",
  pathmon: "Path monitoring",
  unifi: "Controller",
  system: "System",
  locale: "System",
  mark: "Traffic marking",
  cron: "Scheduled tasks",
  ebtables: "Firewall (ebtables)",
  syslog: "Remote logging",
  stamgr: "Client steering",
  bandsteering: "Band steering",
  mgmt: "Management",
  snmp: "SNMP",
  qos: "QoS",
};

interface Change {
  op: "+" | "-" | "~";
  key: string;
  before?: string;
  after?: string;
}

function parseDiff(diff: string): Change[] {
  const out: Change[] = [];
  for (const line of diff.split("\n")) {
    const m = line.match(/^([~+-]) (.*)$/);
    if (!m) continue;
    const op = m[1]!;
    const rest = m[2]!;
    if (op === "~") {
      const i = rest.indexOf(": ");
      const [before, after] = rest.slice(i + 2).split(" -> ");
      out.push({ op: "~", key: rest.slice(0, i), before, after });
    } else {
      const i = rest.indexOf("=");
      out.push({
        op: op as "+" | "-",
        key: i < 0 ? rest : rest.slice(0, i),
        [op === "+" ? "after" : "before"]: i < 0 ? "" : rest.slice(i + 1),
      });
    }
  }
  return out;
}

/** Group changes by area and numbered section ("Wi-Fi security — Home WiFi (5 GHz)"). */
export function group(
  changes: Change[],
  labels: Record<string, string>,
): [string, (Change & { field: string })[]][] {
  const groups = new Map<string, (Change & { field: string })[]>();
  for (const c of changes) {
    const parts = c.key.split(".");
    const [top = "", second = ""] = parts;
    const area = AREA[top] ?? top;
    const numbered = parts.length > 2 && /^\d+$/.test(second);
    const section = numbered ? `${top}.${second}` : top;
    const title = numbered
      ? `${area} — ${labels[section] ?? `#${second}`}`
      : area;
    const field = parts.slice(numbered ? 2 : 1).join(".") || top;
    groups.set(title, [...(groups.get(title) ?? []), { ...c, field }]);
  }
  return [...groups.entries()];
}

/** The settings changes in a config push (or a preview of one), grouped by section. */
export function summarise(d: ConfigPushed): {
  changes: Change[];
  groups: ReturnType<typeof group>;
} {
  const diffs = [d.system_cfg?.diff, d.mgmt_cfg?.diff].filter(
    (x): x is string => typeof x === "string" && !!x,
  );
  // The version stamp changes with every push; it says nothing about the settings.
  const changes = diffs
    .flatMap(parseDiff)
    .filter((c) => c.key !== "cfgversion");
  return { changes, groups: group(changes, d.labels ?? {}) };
}

export function ChangeGroups({
  groups,
}: {
  groups: ReturnType<typeof group>;
}): ReactNode {
  return (
    <div className="cfg-groups">
      {groups.map(([title, list]) => (
        <div key={title} className="cfg-group">
          <div className="cfg-group-title">{title}</div>
          <table className="table cfg-table">
            <tbody>
              {list.map((c, i) => (
                <tr key={i}>
                  <td className="mono small">{c.field}</td>
                  <td className="small">
                    {c.op === "~" ? (
                      <>
                        <span className="cfg-old">{c.before}</span> →{" "}
                        <span className="cfg-new">{c.after}</span>
                      </>
                    ) : c.op === "+" ? (
                      <>
                        <span className="muted">added</span>{" "}
                        <span className="cfg-new">{c.after}</span>
                      </>
                    ) : (
                      <>
                        <span className="muted">removed</span>{" "}
                        <span className="cfg-old">{c.before}</span>
                      </>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ))}
    </div>
  );
}
