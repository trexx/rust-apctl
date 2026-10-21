import type { ReactNode } from "react";
import type { CfgChange, CfgKeyChange, ConfigPushed } from "../api";

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

/** The changes a diff's text lists, for pushes recorded before the server sent them structured. */
function parseDiff(diff: string): CfgKeyChange[] {
  const out: CfgKeyChange[] = [];
  for (const line of diff.split("\n")) {
    const m = line.match(/^([~+-]) (.*)$/);
    if (!m) continue;
    const op = m[1]!;
    const rest = m[2]!;
    if (op === "~") {
      const i = rest.indexOf(": ");
      // "old -> new", where a value can hold " -> " itself: split at the
      // middle one, which is right when both values hold it equally often
      // (an edit to such a value), and keep all the text either way.
      const parts = rest.slice(i + 2).split(" -> ");
      const mid = Math.max(1, Math.floor(parts.length / 2));
      out.push({
        op: "~",
        key: rest.slice(0, i),
        old: parts.slice(0, mid).join(" -> "),
        new: parts.slice(mid).join(" -> "),
      });
    } else {
      const i = rest.indexOf("=");
      out.push({
        op: op as "+" | "-",
        key: i < 0 ? rest : rest.slice(0, i),
        [op === "+" ? "new" : "old"]: i < 0 ? "" : rest.slice(i + 1),
      });
    }
  }
  return out;
}

/** Group changes by area and numbered section ("Wi-Fi security — Home WiFi (5 GHz)"). */
function group(
  changes: CfgKeyChange[],
  labels: Record<string, string>,
): [string, (CfgKeyChange & { field: string })[]][] {
  const groups = new Map<string, (CfgKeyChange & { field: string })[]>();
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
    const list = groups.get(title);
    if (list) list.push({ ...c, field });
    else groups.set(title, [{ ...c, field }]);
  }
  return [...groups.entries()];
}

/** The settings changes in a config push (or a preview of one), grouped by section. */
export function summarise(d: ConfigPushed): {
  changes: CfgKeyChange[];
  groups: ReturnType<typeof group>;
} {
  const listed = (c: CfgChange | undefined) =>
    c?.changes ?? (c?.diff ? parseDiff(c.diff) : []);
  // The version stamp changes with every push; it says nothing about the settings.
  const changes = [...listed(d.system_cfg), ...listed(d.mgmt_cfg)].filter(
    (c) => c.key !== "cfgversion",
  );
  return { changes, groups: group(changes, d.labels ?? {}) };
}

/** A config push's summary line: the sections it changed and how many settings in each. */
export function pushText(
  d: ConfigPushed,
  { changes, groups }: ReturnType<typeof summarise>,
): string {
  const { system_cfg: s, mgmt_cfg: m } = d;
  if (s?.baseline) return `first config seen (${s.lines} lines)`;
  if (changes.length > 0)
    return groups.map(([t, l]) => `${t} (${l.length})`).join(", ");
  // A management-only push with nothing to compare with.
  return m?.baseline
    ? `first management config seen (${m.lines} lines)`
    : "no setting changed (re-sent)";
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
                        <span className="cfg-old">{c.old}</span> →{" "}
                        <span className="cfg-new">{c.new}</span>
                      </>
                    ) : c.op === "+" ? (
                      <>
                        <span className="muted">added</span>{" "}
                        <span className="cfg-new">{c.new}</span>
                      </>
                    ) : (
                      <>
                        <span className="muted">removed</span>{" "}
                        <span className="cfg-old">{c.old}</span>
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
