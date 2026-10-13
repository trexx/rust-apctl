import { useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useDevices, useEvents } from "../api";
import type { AppEvent } from "../api";
import { DryRunPage } from "./DryRun";
import { FirmwarePanel } from "../components/Firmware";
import { Loading, deviceNames } from "../components/common";
import { clock } from "../format";
import { ChangeGroups, summarise } from "../components/ConfigDiff";

function Push({ e, ap }: { e: AppEvent; ap: React.ReactNode }) {
  const [open, setOpen] = useState(false);
  const d = (e.data ?? {}) as Record<string, any>;
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

function History() {
  const [device, setDevice] = useState("");
  const devices = useDevices();
  const names = deviceNames(devices.data);
  const ev = useEvents({
    kind: "config_pushed,config_applied,settings_imported,settings_changed,radio_changed",
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
                  : e.kind === "settings_changed"
                    ? String(d.what ?? "")
                    : `settings imported: ${(d.wlans ?? []).length} SSIDs, ${(d.networks ?? []).length} networks`;
            const title =
              e.kind === "config_applied"
                ? "Applied"
                : e.kind === "radio_changed"
                  ? "Radio changed"
                  : e.kind === "settings_changed"
                    ? "Settings changed"
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
