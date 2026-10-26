import { useEffect, useState } from "react";
import type { ReactNode } from "react";
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
import {
  ago,
  bytes,
  dateTime as when,
  hhmm,
  minutesOf,
  useNow,
} from "../format";
import { Outcome, QueryNote, THead, Toggle, useRunner } from "./common";
import { FileButton } from "./FileButton";
import { NumberInput, Select, TimeInput } from "./settings/form";
import type { Option } from "./settings/form";

const HISTORY: [number, string][] = [
  [0, "Settings only"],
  [7, "Settings + 7 days"],
  [30, "Settings + 30 days"],
  [90, "Settings + 90 days"],
  [365, "Settings + 365 days"],
  [-1, "Everything"],
];
/**
 * What a backup holds: its history (`days`), but an "everything" one without
 * the statistics database (the copy a settings-only restore saves first) says
 * so. `files` is empty for backups listed before the server named them.
 */
const historyLabel = (d: number, files: string[]) =>
  d === -1 && files.length > 0 && !files.includes("metrics.db")
    ? "Settings and events (no statistics or logs)"
    : (HISTORY.find((h) => h[0] === d)?.[1] ?? `Settings + ${d} days`);
const WEEKDAYS = [
  "Monday",
  "Tuesday",
  "Wednesday",
  "Thursday",
  "Friday",
  "Saturday",
  "Sunday",
];
const FREQUENCIES: Option<BackupSettings["frequency"]>[] = [
  ["daily", "Daily"],
  ["weekly", "Weekly"],
  ["monthly", "Monthly"],
];
const ON_WEEKDAY = WEEKDAYS.map((d, i) => [i, `on ${d}`] as const);
const ON_MONTHDAY = Array.from(
  { length: 28 },
  (_, i) => [i + 1, `on day ${i + 1}`] as const,
);
const KIND: Record<BackupMeta["kind"], string> = {
  auto: "Automatic",
  manual: "Manual",
  "pre-restore": "Before a restore",
};

/**
 * apctl keeps the schedule in UTC: the time in minutes after midnight, and the
 * weekly backup's day (Monday = 0) and the monthly one's date as UTC days. The
 * form shows the time and the weekday in this browser's time zone, at today's
 * offset: where the local and the UTC date differ at that time (01:00 local at
 * UTC+2 is 23:00 UTC the day before), the weekday moves with it. A date can't
 * move the same way (day 1 would become the last day of the month before), so
 * the monthly date stays a UTC one and is shown as such.
 */
const offsetMin = () => -new Date().getTimezoneOffset();
const mod = (n: number, m: number) => ((n % m) + m) % m;
/** `minute` moved by `by` minutes: the minute of its day, and how many days it moved. */
const shift = (minute: number, by: number) => ({
  minute: mod(minute + by, 1440),
  days: Math.floor((minute + by) / 1440),
});
const toLocal = (s: BackupSettings) => {
  const t = shift(s.minute_utc, offsetMin());
  return { time: hhmm(t.minute), weekday: mod(s.weekday + t.days, 7) };
};
const fromLocal = (time: string, weekday: number) => {
  const t = shift(minutesOf(time), -offsetMin());
  return { minute_utc: t.minute, weekday: mod(weekday + t.days, 7) };
};
/** The schedule as apctl keeps it, in UTC. */
const utcText = (s: BackupSettings) =>
  s.frequency === "weekly"
    ? `${WEEKDAYS[s.weekday]} ${hhmm(s.minute_utc)} UTC`
    : s.frequency === "monthly"
      ? `day ${s.monthday}, ${hhmm(s.minute_utc)} UTC`
      : `${hhmm(s.minute_utc)} UTC`;

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
  const local = toLocal(s);
  return (
    <div className="backup-form">
      <Toggle
        value={s.enabled}
        disabled={readOnly}
        onChange={(enabled) => setS({ ...s, enabled })}
        label="Automatic backups"
      />
      <div className="backup-row">
        <Select
          aria-label="How often"
          value={s.frequency}
          options={FREQUENCIES}
          disabled={readOnly || !s.enabled}
          onChange={(frequency) => setS({ ...s, frequency })}
        />
        {s.frequency === "weekly" && (
          <Select
            aria-label="Day of the week"
            value={local.weekday}
            options={ON_WEEKDAY}
            disabled={readOnly || !s.enabled}
            onChange={(w) => setS({ ...s, ...fromLocal(local.time, w) })}
          />
        )}
        {s.frequency === "monthly" && (
          <Select
            aria-label="Day of the month (UTC)"
            value={s.monthday}
            options={ON_MONTHDAY}
            disabled={readOnly || !s.enabled}
            onChange={(monthday) => setS({ ...s, monthday })}
          />
        )}
        <label className="small">
          at{" "}
          <TimeInput
            value={local.time}
            disabled={readOnly || !s.enabled}
            onChange={(t) => setS({ ...s, ...fromLocal(t, local.weekday) })}
          />
        </label>
        <span
          className="muted small"
          title="apctl keeps the schedule in UTC, so its local time moves by an hour when daylight saving time starts or ends."
        >
          ({utcText(s)})
        </span>
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
          <Select
            value={s.days}
            options={HISTORY.map(([d, l]) => [d, l.toLowerCase()] as const)}
            disabled={readOnly || !s.enabled}
            onChange={(days) => setS({ ...s, days })}
          />
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
  what: ReactNode;
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
  if (!b.data) return <QueryNote q={b} panel />;
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
          stored on apctl's volume
          {readOnly ? "" : "; download one to keep a copy elsewhere"}
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

      {d.settings_error && (
        <div className="banner banner-high">{d.settings_error}</div>
      )}
      <Schedule initial={d.settings} readOnly={readOnly} nextRun={d.next_run} />

      {!readOnly && (
        <div className="backup-row backup-actions">
          <Select
            aria-label="What to include"
            value={days}
            options={HISTORY}
            onChange={setDays}
          />
          <button
            className="btn small primary"
            disabled={busy}
            onClick={() => void run(() => createBackup(days))}
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
          ,{" "}
          {historyLabel(
            uploaded.manifest.days,
            Object.keys(uploaded.manifest.files),
          ).toLowerCase()}
          , {Object.keys(uploaded.manifest.files).join(", ")}.{" "}
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
              columns={[
                "Made",
                "Kind",
                "Contains",
                "apctl",
                "Size",
                ...(readOnly ? [] : [""]),
              ]}
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
                  <td className="small">{historyLabel(x.days, x.files)}</td>
                  <td className="small">{x.version}</td>
                  <td className="small nowrap">{bytes(x.size)}</td>
                  {/* Read-only mode withholds the files: they hold AP keys and Wi-Fi passwords. */}
                  {!readOnly && (
                    <td className="nowrap">
                      <a
                        className="btn small"
                        href={`/api/backups/file/${encodeURIComponent(x.name)}`}
                        download
                      >
                        Download
                      </a>{" "}
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
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
