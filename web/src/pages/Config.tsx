import { useState } from "react";
import type { ReactNode } from "react";
import { Link, useSearchParams } from "react-router";
import { eventData, useDeviceNames, useEvents } from "../api";
import type { AppEvent } from "../api";
import { DryRun } from "./DryRun";
import { FirmwarePanel } from "../components/Firmware";
import {
  ApSelect,
  QueryState,
  Segmented,
  eventText,
  useSetParams,
  useUrlTab,
} from "../components/common";
import { clock, useNow } from "../format";
import { ChangeGroups, summarise } from "../components/ConfigDiff";

function Push({ e, ap, now }: { e: AppEvent; ap: ReactNode; now: number }) {
  const [open, setOpen] = useState(false);
  const d = eventData<"config_pushed">(e);
  const s = d.system_cfg ?? {};
  const { changes, groups } = summarise(d);
  const summary = s.baseline
    ? `first config seen (${s.lines} lines)`
    : changes.length === 0
      ? "no setting changed (re-sent)"
      : groups.map(([t, l]) => `${t} (${l.length})`).join(", ");
  return (
    <div className="cfg-entry">
      <div className="cfg-head">
        <span className="muted small nowrap">{clock(e.ts, now)}</span>
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

function History() {
  // The AP lives in the URL (`?device=`), as on the Events and Logs pages.
  const [params] = useSearchParams();
  const device = params.get("device") ?? "";
  const setUrl = useSetParams();
  const setDevice = (mac: string) => setUrl({ device: mac }, { replace: true });
  const names = useDeviceNames();
  const now = useNow();
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
          // The previous AP's history is dimmed while this one's loads.
          events.length === 0 ? (
            <div className="muted small">Nothing recorded yet.</div>
          ) : (
            <div className={ev.isPlaceholderData ? "dim" : undefined}>
              {events.map((e) => {
                if (e.kind === "config_pushed")
                  return (
                    <Push key={e.id} e={e} ap={ap(e.device_mac)} now={now} />
                  );
                const { label, detail } = eventText(e, names);
                return (
                  <div key={e.id} className="cfg-entry">
                    <div className="cfg-head">
                      <span className="muted small nowrap">
                        {clock(e.ts, now)}
                      </span>
                      <b className="muted">{label}</b>
                      {e.device_mac && <span>{ap(e.device_mac)}</span>}
                      <span className="muted small">{detail}</span>
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
        <DryRun />
      )}
    </div>
  );
}
