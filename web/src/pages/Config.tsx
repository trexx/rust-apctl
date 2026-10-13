import { useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useDevices, useEvents } from "../api";
import type { AppEvent } from "../api";
import { DryRunPage } from "./DryRun";
import { FirmwarePanel } from "../components/Firmware";
import { Loading, deviceNames } from "../components/common";
import { clock } from "../format";

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
    const [, op, rest] = m;
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
function group(
  changes: Change[],
  labels: Record<string, string>,
): [string, (Change & { field: string })[]][] {
  const groups = new Map<string, (Change & { field: string })[]>();
  for (const c of changes) {
    const parts = c.key.split(".");
    const area = AREA[parts[0]] ?? parts[0];
    const numbered = parts.length > 2 && /^\d+$/.test(parts[1]);
    const section = numbered ? `${parts[0]}.${parts[1]}` : parts[0];
    const title = numbered
      ? `${area} — ${labels[section] ?? `#${parts[1]}`}`
      : area;
    const field = parts.slice(numbered ? 2 : 1).join(".") || parts[0];
    groups.set(title, [...(groups.get(title) ?? []), { ...c, field }]);
  }
  return [...groups.entries()];
}

function Push({ e, ap }: { e: AppEvent; ap: React.ReactNode }) {
  const [open, setOpen] = useState(false);
  const d = (e.data ?? {}) as Record<string, any>;
  const s = d.system_cfg ?? {};
  const m = d.mgmt_cfg ?? {};
  const labels: Record<string, string> = d.labels ?? {};
  const diffs = [s.diff, m.diff].filter(
    (x) => typeof x === "string" && x,
  ) as string[];
  // The version stamp changes with every push; it says nothing about the settings.
  const changes = diffs
    .flatMap(parseDiff)
    .filter((c) => c.key !== "cfgversion");
  const groups = group(changes, labels);
  const summary = s.baseline
    ? `first config seen (${s.lines} lines)`
    : changes.length === 0
      ? "no setting changed (re-sent)"
      : groups.map(([t, l]) => `${t} (${l.length})`).join(", ");
  return (
    <div className="cfg-entry">
      <div className="cfg-head">
        <span className="muted small nowrap">{clock(e.ts)}</span>
        <b>Config sent</b>
        <span>to {ap}</span>
        <span className="muted small cfg-summary">{summary}</span>
        <span className="spacer" />
        {groups.length > 0 && (
          <button className="btn small" onClick={() => setOpen((o) => !o)}>
            {open ? "Hide" : "Show"} {changes.length} change
            {changes.length === 1 ? "" : "s"}
          </button>
        )}
      </div>
      {open && (
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
      )}
    </div>
  );
}

function History() {
  const [device, setDevice] = useState("");
  const devices = useDevices();
  const names = deviceNames(devices.data);
  const ev = useEvents({
    kind: "config_pushed,config_applied,settings_imported,radio_changed",
    device: device || undefined,
    limit: 300,
  });
  const ap = (mac: string | null) =>
    mac ? <Link to={`/devices/${mac}`}>{names.get(mac) ?? mac}</Link> : null;
  return (
    <div className="panel">
      <div className="panel-head">
        <b>Configuration history</b>
        <span className="muted small">
          every config sent to an AP, with what changed; secrets are never
          stored
        </span>
        <span className="spacer" />
        <select
          value={device}
          onChange={(e) => setDevice(e.target.value)}
          aria-label="Access point"
        >
          <option value="">All APs</option>
          {(devices.data ?? []).map((d) => (
            <option key={d.mac} value={d.mac}>
              {d.name ?? d.mac}
            </option>
          ))}
        </select>
      </div>
      {!ev.data ? (
        <Loading />
      ) : ev.data.length === 0 ? (
        <div className="muted small">Nothing recorded yet.</div>
      ) : (
        <div>
          {ev.data.map((e, i) => {
            const d = (e.data ?? {}) as Record<string, any>;
            if (e.kind === "config_pushed")
              return <Push key={i} e={e} ap={ap(e.device_mac)} />;
            const text =
              e.kind === "config_applied"
                ? d.seconds_after_push !== undefined &&
                  d.seconds_after_push !== null
                  ? `applied it ${d.seconds_after_push}s later`
                  : "applied it"
                : e.kind === "radio_changed"
                  ? `${d.radio === "ng" ? "2.4 GHz" : d.radio === "na" ? "5 GHz" : d.radio}: channel ${d.from?.channel} → ${d.to?.channel}, ${d.from?.bw} → ${d.to?.bw} MHz, ${d.from?.tx_power} → ${d.to?.tx_power} dBm`
                  : `settings imported: ${(d.wlans ?? []).length} SSIDs, ${(d.networks ?? []).length} networks`;
            const title =
              e.kind === "config_applied"
                ? "Applied"
                : e.kind === "radio_changed"
                  ? "Radio changed"
                  : "Settings imported";
            return (
              <div key={i} className="cfg-entry">
                <div className="cfg-head">
                  <span className="muted small nowrap">{clock(e.ts)}</span>
                  <b className="muted">{title}</b>
                  {e.device_mac && <span>{ap(e.device_mac)}</span>}
                  <span className="muted small">{text}</span>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

export function Config() {
  const [params, setParams] = useSearchParams();
  const tab =
    params.get("tab") === "dryrun"
      ? "dryrun"
      : params.get("tab") === "firmware"
        ? "firmware"
        : "history";
  return (
    <div className="page">
      <div className="page-head">
        <h1>Config</h1>
        <div className="segmented" role="tablist">
          <button
            role="tab"
            aria-selected={tab === "history"}
            className={tab === "history" ? "active" : ""}
            onClick={() => setParams({})}
          >
            History
          </button>
          <button
            role="tab"
            aria-selected={tab === "dryrun"}
            className={tab === "dryrun" ? "active" : ""}
            onClick={() => setParams({ tab: "dryrun" })}
          >
            Dry run
          </button>
          <button
            role="tab"
            aria-selected={tab === "firmware"}
            className={tab === "firmware" ? "active" : ""}
            onClick={() => setParams({ tab: "firmware" })}
          >
            Firmware
          </button>
        </div>
      </div>
      {tab === "history" ? (
        <History />
      ) : tab === "firmware" ? (
        <FirmwarePanel />
      ) : (
        <DryRunPage embedded />
      )}
    </div>
  );
}
