import { useEffect, useState } from "react";
import {
  createBackup,
  deleteBackup,
  keys,
  restoreBackup,
  saveBackupSettings,
  uploadBackup,
  useBackups,
  useCanEdit,
} from "../api";
import type { BackupManifest, BackupMeta, BackupSettings } from "../api";
import { ago, bytes, dateTime as when, hhmm, useNow } from "../format";
import { Outcome, QueryNote, THead, Toggle, useRunner } from "./common";
import { FileButton } from "./FileButton";
import { NumberInput, TimeInput } from "./settings/form";

const HISTORY: [number, string][] = [
  [0, "Settings only"],
  [7, "Settings + 7 days"],
  [30, "Settings + 30 days"],
  [90, "Settings + 90 days"],
  [365, "Settings + 365 days"],
  [-1, "Everything"],
];
const historyLabel = (d: number) =>
  HISTORY.find((h) => h[0] === d)?.[1] ?? `Settings + ${d} days`;
const WEEKDAYS = [
  "Monday",
  "Tuesday",
  "Wednesday",
  "Thursday",
  "Friday",
  "Saturday",
  "Sunday",
];
const KIND: Record<BackupMeta["kind"], string> = {
  auto: "Automatic",
  manual: "Manual",
  "pre-restore": "Before a restore",
};

/** Minutes after midnight UTC <-> "HH:MM" in this browser's time zone. */
const offsetMin = () => -new Date().getTimezoneOffset();
const toLocal = (utcMin: number) =>
  hhmm((((utcMin + offsetMin()) % 1440) + 1440) % 1440);
const fromLocal = (text: string) => {
  const [h = 0, m = 0] = text.split(":").map(Number);
  return (((h * 60 + m - offsetMin()) % 1440) + 1440) % 1440;
};

/**
 * Which apctl process answers: when it started, "signed out" when it no
 * longer knows this session (as after a restore), null when none answers
 * (nor with its status: a proxy's page while it restarts is no answer).
 */
const whoAnswers = () =>
  fetch("/api/status", { cache: "no-store" })
    .then(async (r): Promise<string | null> => {
      if (r.status === 401) return "signed out";
      return r.ok ? String((await r.json()).started) : null;
    })
    .catch(() => null);

/**
 * Waits for apctl to come back after a restore, then reloads the page: once
 * another process answers than the one that took the restore (`before`), or
 * any process after none did. The old one answers for a few seconds more,
 * while it stores what is queued. Returns whether it gave up waiting.
 */
function useRestartWatch(restart: { before: string | null } | null) {
  const [gaveUp, setGaveUp] = useState(false);
  useEffect(() => {
    if (!restart) return;
    let stop = false;
    const started = Date.now();
    const poll = async () => {
      let down = false;
      while (!stop && Date.now() - started < 5 * 60_000) {
        await new Promise((r) => setTimeout(r, 1000));
        const now = await whoAnswers();
        if (now === null) down = true;
        else if (down || (restart.before !== null && now !== restart.before)) {
          window.location.reload();
          return;
        }
      }
      if (!stop) setGaveUp(true);
    };
    void poll();
    return () => {
      stop = true;
    };
  }, [restart]);
  return gaveUp;
}

function Schedule({
  initial,
  readOnly,
  nextRun,
}: {
  initial: BackupSettings;
  readOnly: boolean;
  nextRun: number | null;
}) {
  const [s, setS] = useState(initial);
  const [base, setBase] = useState(initial);
  // Saved settings (from here or elsewhere) replace the form's; the outcome
  // line ("Saved.") stays.
  if (JSON.stringify(initial) !== JSON.stringify(base)) {
    setBase(initial);
    setS(initial);
  }
  const { msg, run } = useRunner([keys.backups()]);
  const dirty = JSON.stringify(s) !== JSON.stringify(initial);
  const save = () => void run(() => saveBackupSettings(s), "Saved.");
  return (
    <div className="backup-form">
      <Toggle
        value={s.enabled}
        disabled={readOnly}
        onChange={(enabled) => setS({ ...s, enabled })}
        label="Automatic backups"
      />
      <div className="backup-row">
        <select
          aria-label="How often"
          value={s.frequency}
          disabled={readOnly || !s.enabled}
          onChange={(e) =>
            setS({
              ...s,
              frequency: e.target.value as BackupSettings["frequency"],
            })
          }
        >
          <option value="daily">Daily</option>
          <option value="weekly">Weekly</option>
          <option value="monthly">Monthly</option>
        </select>
        {s.frequency === "weekly" && (
          <select
            aria-label="Day of the week"
            value={s.weekday}
            disabled={readOnly || !s.enabled}
            onChange={(e) => setS({ ...s, weekday: Number(e.target.value) })}
          >
            {WEEKDAYS.map((d, i) => (
              <option key={d} value={i}>
                on {d}
              </option>
            ))}
          </select>
        )}
        {s.frequency === "monthly" && (
          <select
            aria-label="Day of the month"
            value={s.monthday}
            disabled={readOnly || !s.enabled}
            onChange={(e) => setS({ ...s, monthday: Number(e.target.value) })}
          >
            {Array.from({ length: 28 }, (_, i) => i + 1).map((d) => (
              <option key={d} value={d}>
                on day {d}
              </option>
            ))}
          </select>
        )}
        <label className="small">
          at{" "}
          <TimeInput
            value={toLocal(s.minute_utc)}
            disabled={readOnly || !s.enabled}
            onChange={(t) => setS({ ...s, minute_utc: fromLocal(t) })}
          />
        </label>
        <span className="muted small">({hhmm(s.minute_utc)} UTC)</span>
      </div>
      <div className="backup-row">
        <label className="small">
          Keep the newest{" "}
          <NumberInput
            value={s.keep}
            fallback={s.keep}
            min={1}
            max={100}
            disabled={readOnly || !s.enabled}
            onChange={(keep) => setS({ ...s, keep })}
          />
        </label>
        <label className="small">
          containing{" "}
          <select
            value={s.days}
            disabled={readOnly || !s.enabled}
            onChange={(e) => setS({ ...s, days: Number(e.target.value) })}
          >
            {HISTORY.map(([d, l]) => (
              <option key={d} value={d}>
                {l.toLowerCase()}
              </option>
            ))}
          </select>
        </label>
        {!readOnly && (
          <button
            className="btn small primary"
            disabled={!dirty}
            onClick={save}
          >
            Save
          </button>
        )}
        <Outcome msg={msg} inline />
      </div>
      {initial.enabled && nextRun && (
        <div className="muted small">
          Next automatic backup: {when(nextRun)}
        </div>
      )}
    </div>
  );
}

function ConfirmRestore({
  what,
  busy,
  onConfirm,
  onCancel,
}: {
  what: React.ReactNode;
  busy: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  return (
    <div className="banner banner-medium restore-confirm">
      <div>
        <b>Restore {what}?</b> apctl saves its current state as a backup first,
        then restarts with the restored data; it is back within a minute. A
        settings-only backup keeps the current statistics and logs. You will
        need to sign in again.
      </div>
      <div className="backup-row">
        <button
          className="btn small primary"
          disabled={busy}
          onClick={onConfirm}
        >
          {busy ? "Restoring…" : "Restore and restart"}
        </button>
        <button className="btn small" onClick={onCancel}>
          Cancel
        </button>
      </div>
    </div>
  );
}

export function BackupSection() {
  const b = useBackups();
  const readOnly = !useCanEdit();
  const now = useNow();
  const [days, setDays] = useState(0);
  // Only failures are reported; success shows in the list.
  const { busy, msg, run } = useRunner([keys.backups()], 300);
  const [confirm, setConfirm] = useState<{
    name?: string;
    staged?: string;
    label: string;
  } | null>(null);
  const [uploaded, setUploaded] = useState<{
    staged: string;
    manifest: BackupManifest;
    file: string;
  } | null>(null);
  const [restarting, setRestarting] = useState<{
    before: string | null;
  } | null>(null);
  const gaveUp = useRestartWatch(restarting);

  // apctl's API is down while it restarts, so these come before the fetch error.
  if (restarting && gaveUp)
    return (
      <div className="panel">
        <b>apctl has not come back after 5 minutes.</b> Check that it is running
        and its log; if the restore failed, apctl started with the data it had
        before. Reload this page once it answers again.
      </div>
    );
  if (restarting)
    return (
      <div className="panel">
        <b>Restoring…</b> apctl is restarting with the restored data. This page
        reloads when it is back.
      </div>
    );
  if (!b.data) return <QueryNote q={b} />;
  const d = b.data;
  return (
    <div className="panel" id="backups">
      <div className="panel-head">
        <b>Backups</b>
        {d.encrypted ? (
          <span
            className="tag tag-good"
            title="AES-256-GCM with the key from --backup-key"
          >
            encrypted
          </span>
        ) : (
          <span
            className="tag tag-warn"
            title="Start apctl with --backup-key to encrypt backups"
          >
            not encrypted
          </span>
        )}
        <span className="muted small">
          stored on apctl's volume; download one to keep a copy elsewhere
        </span>
      </div>
      {!d.encrypted && (
        <p className="small tone-warn">
          No backup key is configured, so backups (which include AP keys and
          your Wi-Fi settings) are written unencrypted. Provide one with
          --backup-key.
        </p>
      )}
      {d.restore_pending && (
        <div className="banner">
          A restore is waiting to be applied at the next start.
        </div>
      )}
      {d.restore_failed && (
        <div className="banner banner-high">
          The last restore could not be applied, so apctl started with its
          current data: {d.restore_failed}
        </div>
      )}

      <Schedule initial={d.settings} readOnly={readOnly} nextRun={d.next_run} />

      {!readOnly && (
        <div className="backup-row backup-actions">
          <select
            value={days}
            onChange={(e) => setDays(Number(e.target.value))}
            aria-label="What to include"
          >
            {HISTORY.map(([v, l]) => (
              <option key={v} value={v}>
                {l}
              </option>
            ))}
          </select>
          <button
            className="btn small primary"
            disabled={busy}
            onClick={() => run(() => createBackup(days))}
          >
            {busy ? "Working…" : "Back up now"}
          </button>
          <FileButton
            className="btn small"
            accept=".apb"
            disabled={busy}
            onFile={(f) =>
              void run(async () =>
                setUploaded({ ...(await uploadBackup(f)), file: f.name }),
              )
            }
          >
            Restore from a file…
          </FileButton>
        </div>
      )}
      <Outcome msg={msg} />
      {uploaded && !confirm && (
        <div className="banner">
          <b>{uploaded.file}</b> checks out: made{" "}
          {when(uploaded.manifest.created)} by apctl {uploaded.manifest.version}
          , {historyLabel(uploaded.manifest.days).toLowerCase()},{" "}
          {Object.keys(uploaded.manifest.files).join(", ")}.{" "}
          <button
            className="btn small primary"
            onClick={() =>
              setConfirm({
                staged: uploaded.staged,
                label: `the uploaded ${uploaded.file}`,
              })
            }
          >
            Restore it…
          </button>{" "}
          <button className="btn small" onClick={() => setUploaded(null)}>
            Cancel
          </button>
        </div>
      )}
      {confirm && (
        <ConfirmRestore
          what={confirm.label}
          busy={busy}
          onCancel={() => setConfirm(null)}
          onConfirm={() =>
            void run(async () => {
              const before = await whoAnswers();
              await restoreBackup({
                name: confirm.name,
                staged: confirm.staged,
              });
              setRestarting({ before });
            })
          }
        />
      )}

      {d.backups.length === 0 ? (
        <div className="muted small">No backups yet.</div>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <THead
              columns={["Made", "Kind", "Contains", "apctl", "Size", ""]}
            />
            <tbody>
              {d.backups.map((x) => (
                <tr key={x.name}>
                  <td className="nowrap">
                    {when(x.created)}{" "}
                    <span className="muted small">({ago(x.created, now)})</span>
                  </td>
                  <td>
                    {KIND[x.kind]}
                    {!x.encrypted && (
                      <span className="tag tag-warn">unencrypted</span>
                    )}
                  </td>
                  <td className="small">{historyLabel(x.days)}</td>
                  <td className="small">{x.version}</td>
                  <td className="small nowrap">{bytes(x.size)}</td>
                  <td className="nowrap">
                    <a
                      className="btn small"
                      href={`/api/backups/file/${encodeURIComponent(x.name)}`}
                      download
                    >
                      Download
                    </a>{" "}
                    {!readOnly && (
                      <>
                        <button
                          className="btn small"
                          onClick={() =>
                            setConfirm({
                              name: x.name,
                              label: `the backup from ${when(x.created)}`,
                            })
                          }
                        >
                          Restore…
                        </button>{" "}
                        <button
                          className="btn small"
                          onClick={() =>
                            window.confirm(
                              `Delete the backup from ${when(x.created)}?`,
                            ) && void run(() => deleteBackup(x.name))
                          }
                        >
                          Delete
                        </button>
                      </>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
