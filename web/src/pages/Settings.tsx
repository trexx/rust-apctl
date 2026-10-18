import { importState, keys, useCanEdit, useSettingsState } from "../api";
import { ErrorNote, Loading, Outcome, useRunner } from "../components/common";
import { NotificationSettings } from "../components/Alerts";
import { BackupSection } from "../components/Backups";
import { FileButton } from "../components/FileButton";
import { SiteSettingsPanel } from "../components/SettingsEditor";
import { ago, clock, useNow } from "../format";

export function Settings() {
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

  // What was fetched stays up when a refetch fails.
  if (!state.data)
    return state.error ? <ErrorNote error={state.error} /> : <Loading />;
  const s = state.data.summary;
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
      <div className="panel">
        {s ? (
          <div className="kv kv-wide">
            <span>Imported</span>
            <span>
              {clock(state.data.imported_at!, now)} (
              {ago(state.data.imported_at, now)})
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
            No settings imported yet. The dry run needs them to know what apctl
            should push.
          </p>
        )}
        {canEdit && (
          <div className="import">
            <p className="muted small">
              Import a snapshot of the existing controller's settings, made with{" "}
              <code>informdump import</code>. It replaces the current settings
              and contains Wi-Fi passwords, so keep the file private.
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
    </div>
  );
}
