import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { importState, useMe, useSettingsState } from "../api";
import { ErrorNote, Loading } from "../components/common";
import { NotificationSettings } from "../components/Alerts";
import { BackupSection } from "../components/Backups";
import { SiteSettingsPanel } from "../components/SettingsEditor";
import { ago, clock } from "../format";

export function Settings() {
  const qc = useQueryClient();
  const state = useSettingsState();
  const readOnly = useMe().data?.read_only ?? false;
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(
    null,
  );
  const [busy, setBusy] = useState(false);

  const onFile = async (file: File | undefined) => {
    if (!file) return;
    setBusy(true);
    setMessage(null);
    try {
      const snapshot = JSON.parse(await file.text());
      await importState(snapshot);
      setMessage({ ok: true, text: `Imported ${file.name}.` });
      window.setTimeout(
        () => void qc.invalidateQueries({ queryKey: ["settings-state"] }),
        500,
      );
    } catch (e) {
      setMessage({
        ok: false,
        text: e instanceof Error ? e.message : String(e),
      });
    } finally {
      setBusy(false);
    }
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
        {!readOnly && (
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
                onChange={(e) => void onFile(e.target.files?.[0])}
              />
            </label>
            {message && (
              <div className={message.ok ? "ok small" : "error small"}>
                {message.text}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
