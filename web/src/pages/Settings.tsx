import { importState, keys, useCanEdit, useSettingsState } from "../api";
import { Outcome, QueryState, useRunner } from "../components/common";
import { NotificationSettings } from "../components/Alerts";
import { BackupSection } from "../components/Backups";
import { FileButton } from "../components/FileButton";
import { SiteSettingsPanel } from "../components/SettingsEditor";
import { ago, clock, useNow } from "../format";

export function Settings() {
  return (
    <div className="page">
      <div className="page-head">
        <h1>Settings</h1>
      </div>
      <h2>Notifications</h2>
      <NotificationSettings />

      <h2>Backups</h2>
      <BackupSection />

      <h2>Site settings</h2>
      <SiteSettingsPanel />

      <h2>Controller settings</h2>
      <ControllerSettings />
    </div>
  );
}

/** The imported controller settings and the import: only this panel waits
 *  for them or shows their error, and an import stays possible. */
function ControllerSettings() {
  const state = useSettingsState();
  const canEdit = useCanEdit();
  const now = useNow();
  const { busy, msg, run } = useRunner([keys.settingsState()], 500);

  const onFile = (file: File) => {
    void run(async () => {
      await importState(JSON.parse(await file.text()));
      return `Imported ${file.name}.`;
    });
  };

  return (
    <div className="panel">
      <QueryState q={state}>
        {({ summary: s, imported_at }) =>
          s ? (
            <div className="kv kv-wide">
              <span>Imported</span>
              <span>
                {clock(imported_at!, now)} ({ago(imported_at, now)})
              </span>
              <span>SSIDs</span>
              <span>{s.wlans.join(", ") || "none"}</span>
              <span>Networks</span>
              <span>{s.networks.join(", ") || "none"}</span>
              <span>AP groups</span>
              <span>{s.ap_groups.join(", ") || "none"}</span>
              <span>Devices</span>
              <span>{s.devices}</span>
              <span>Known clients</span>
              <span>{s.clients}</span>
            </div>
          ) : (
            <p className="muted">
              No settings imported yet. The dry run needs them to know what
              apctl should push.
            </p>
          )
        }
      </QueryState>
      {canEdit && (
        <div className="import">
          <p className="muted small">
            Import a snapshot of the existing controller's settings, made with{" "}
            <code>informdump import</code>. It replaces the current settings and
            contains Wi-Fi passwords, so keep the file private.
          </p>
          <FileButton
            accept="application/json,.json"
            disabled={busy}
            onFile={onFile}
          >
            {busy ? "Importing…" : "Choose snapshot file…"}
          </FileButton>
          <Outcome msg={msg} />
        </div>
      )}
    </div>
  );
}
