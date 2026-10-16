import { importState, keys, useCanEdit, useSettingsState } from "../api";
import { ErrorNote, Loading, Outcome, useRunner } from "../components/common";
import { NotificationSettings } from "../components/Alerts";
import { BackupSection } from "../components/Backups";
import { SiteSettingsPanel } from "../components/SettingsEditor";
import { ago, clock } from "../format";

export function Settings() {
  const state = useSettingsState();
  const canEdit = useCanEdit();
  const { busy, msg, run } = useRunner([keys.settingsState()], 500);

  const onFile = (file: File | undefined) => {
    if (!file) return;
    void run(async () => {
      await importState(JSON.parse(await file.text()));
      return `Imported ${file.name}.`;
    });
  };

  if (state.isLoading) return <Loading />;
  if (state.error) return <ErrorNote error={state.error} />;
  const s = state.data?.summary;
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
              {clock(state.data!.imported_at!)} ({ago(state.data!.imported_at)})
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
            <label className="btn">
              {busy ? "Importing…" : "Choose snapshot file…"}
              <input
                type="file"
                accept="application/json,.json"
                hidden
                disabled={busy}
                onChange={(e) => {
                  const file = e.target.files?.[0];
                  // Lets the same file be chosen again, e.g. after a failed import.
                  e.target.value = "";
                  onFile(file);
                }}
              />
            </label>
            <Outcome msg={msg} />
          </div>
        )}
      </div>
    </div>
  );
}
