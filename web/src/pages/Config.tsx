import { useMemo, useState } from "react";
import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import { eventData, useDeviceNames, useEvents } from "../api";
import type { AppEvent } from "../api";
import { DryRunPage } from "./DryRun";
import { FirmwarePanel } from "../components/Firmware";
import {
  ApSelect,
  QueryState,
  Segmented,
  useUrlTab,
} from "../components/common";
import { band, clock } from "../format";
import { ChangeGroups, summarise } from "../components/ConfigDiff";

function Push({ e, ap }: { e: AppEvent; ap: ReactNode }) {
  const [open, setOpen] = useState(false);
  const d = eventData<"config_pushed">(e);
  const s = d.system_cfg ?? {};
  const { changes, groups } = useMemo(
    () => summarise(eventData<"config_pushed">(e)),
    [e],
  );
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
      {open && <ChangeGroups groups={groups} />}
    </div>
  );
}

/** One line for the other configuration events: its title and what happened. */
function describe(e: AppEvent): [string, string] {
  switch (e.kind) {
    case "config_applied": {
      const d = eventData<"config_applied">(e);
      return [
        "Applied",
        d.seconds_after_push !== undefined && d.seconds_after_push !== null
          ? `applied it ${d.seconds_after_push}s later`
          : "applied it",
      ];
    }
    case "radio_changed": {
      const d = eventData<"radio_changed">(e);
      return [
        "Radio changed",
        `${band(d.radio)}: channel ${d.from?.channel} → ${d.to?.channel}, ${d.from?.bw} → ${d.to?.bw} MHz, ${d.from?.tx_power} → ${d.to?.tx_power} dBm`,
      ];
    }
    case "settings_changed":
      return [
        "Settings changed",
        String(eventData<"settings_changed">(e).what ?? ""),
      ];
    default: {
      const d = eventData<"settings_imported">(e);
      return [
        "Settings imported",
        `settings imported: ${(d.wlans ?? []).length} SSIDs, ${(d.networks ?? []).length} networks`,
      ];
    }
  }
}

function History() {
  const [device, setDevice] = useState("");
  const names = useDeviceNames();
  const ev = useEvents({
    kind: "config_pushed,config_applied,settings_imported,settings_changed,radio_changed",
    device: device || undefined,
    limit: 300,
  });
  const ap = (mac: string | null) =>
    mac ? <Link to={`/devices/${mac}`}>{names[mac] ?? mac}</Link> : null;
  return (
    <div className="panel">
      <div className="panel-head">
        <b>Configuration history</b>
        <span className="muted small">
          every config sent to an AP, with what changed; secrets are never
          stored
        </span>
        <span className="spacer" />
        <ApSelect value={device} onChange={setDevice} />
      </div>
      <QueryState q={ev}>
        {(events) =>
          events.length === 0 ? (
            <div className="muted small">Nothing recorded yet.</div>
          ) : (
            <div>
              {events.map((e) => {
                if (e.kind === "config_pushed")
                  return <Push key={e.id} e={e} ap={ap(e.device_mac)} />;
                const [title, text] = describe(e);
                return (
                  <div key={e.id} className="cfg-entry">
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
          )
        }
      </QueryState>
    </div>
  );
}

const TABS = [
  ["history", "History"],
  ["dryrun", "Dry run"],
  ["firmware", "Firmware"],
] as const;

export function Config() {
  const [tab, setTab] = useUrlTab(TABS);
  return (
    <div className="page">
      <div className="page-head">
        <h1>Config</h1>
        <Segmented tabs options={TABS} value={tab} onChange={setTab} />
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
