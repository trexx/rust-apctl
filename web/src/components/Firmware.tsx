import { useState } from "react";
import { Link } from "react-router-dom";
import {
  cancelFirmware,
  checkFirmware,
  keys,
  upgradeFirmware,
  upgradeFirmwareUrl,
  useCanEdit,
  useFirmware,
} from "../api";
import type { FirmwareInfo } from "../api";
import { ago, bytes, clock } from "../format";
import { ErrorNote, Loading, Outcome, useRunner } from "./common";

const STATUS: Record<FirmwareInfo["aps"][number]["status"], [string, string]> =
  {
    update_available: ["Update available", "tag-warn"],
    up_to_date: ["Up to date", "tag-good"],
    ahead: ["Ahead of release", "tag-info"],
    unknown: ["Unknown", ""],
  };

const STEP: Record<string, string> = {
  queued: "waiting for its next report",
  sent: "told to update",
  downloading: "downloading",
  writing: "writing to flash",
};

export function FirmwarePanel() {
  const f = useFirmware();
  const readOnly = !useCanEdit();
  const [urlFor, setUrlFor] = useState<string | null>(null);
  const [url, setUrl] = useState("");
  // The engine updates the job list a moment after each request.
  const { busy, msg, run } = useRunner([keys.firmware()], 1200);
  if (f.error) return <ErrorNote error={f.error} />;
  if (!f.data) return <Loading />;
  const d = f.data;
  const canAct = d.active && !readOnly;
  const updatable = d.aps.filter(
    (a) => a.status === "update_available" && a.online,
  );
  const job = d.jobs.current;
  return (
    <div className="stack">
      <div className="panel">
        <div className="panel-head">
          <b>Firmware</b>
          <span className="muted small">
            {d.channel} channel ·{" "}
            {d.checked ? `checked ${ago(d.checked)}` : "not checked yet"}
          </span>
          <span className="spacer" />
          {!readOnly && (
            <button
              className="btn small"
              disabled={busy}
              onClick={() =>
                run(
                  async () =>
                    `The feed lists ${(await checkFirmware()).platforms} platforms.`,
                )
              }
            >
              Check now
            </button>
          )}
          {canAct && updatable.length > 1 && (
            <button
              className="btn small primary"
              disabled={busy}
              onClick={() =>
                window.confirm(
                  `Update ${updatable.length} APs, one at a time? Each restarts and drops its clients for a few minutes.`,
                ) &&
                void run(
                  async () =>
                    `${(await upgradeFirmware(updatable.map((a) => a.mac))).queued} queued.`,
                )
              }
            >
              Update all ({updatable.length})
            </button>
          )}
        </div>
        {d.error && (
          <div className="small error">The last check failed: {d.error}</div>
        )}
        {!d.active && (
          <p className="small muted">
            apctl is in shadow mode, so it never talks to the APs: it shows what
            is available, and follows updates your current controller performs.
            Updating from apctl works after the cutover.
          </p>
        )}
        <Outcome msg={msg} />
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Access point</th>
                <th>Running</th>
                <th>Latest release</th>
                <th>Status</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {d.aps.map((a) => (
                <tr key={a.mac}>
                  <td>
                    <Link to={`/devices/${a.mac}`}>{a.name ?? a.mac}</Link>
                    <div className="muted small">{a.model}</div>
                  </td>
                  <td className="mono small">{a.version ?? "—"}</td>
                  <td className="small">
                    {a.release ? (
                      <>
                        <span className="mono">{a.release.version}</span>
                        <div className="muted">
                          {a.release.created?.slice(0, 10)}
                          {a.release.size ? ` · ${bytes(a.release.size)}` : ""}
                        </div>
                      </>
                    ) : (
                      <span className="muted">
                        {a.platform ? `nothing listed for ${a.platform}` : "—"}
                      </span>
                    )}
                  </td>
                  <td>
                    <span className={`tag ${STATUS[a.status][1]}`}>
                      {STATUS[a.status][0]}
                    </span>
                    {a.status === "ahead" && (
                      <div className="muted small">
                        running a newer (early-access) build
                      </div>
                    )}
                  </td>
                  <td className="nowrap">
                    {canAct && a.status === "update_available" && a.online && (
                      <button
                        className="btn small primary"
                        disabled={busy || !!job}
                        onClick={() => {
                          if (
                            window.confirm(
                              `Update ${a.name ?? a.mac} from ${a.version} to ${a.release?.version}? It restarts and drops its clients for a few minutes.`,
                            )
                          )
                            void run(
                              async () =>
                                `${(await upgradeFirmware([a.mac])).queued ? "Queued" : "Not queued"}.`,
                            );
                        }}
                      >
                        Update
                      </button>
                    )}{" "}
                    {canAct && a.online && (
                      <button
                        className="btn small"
                        onClick={() =>
                          setUrlFor(urlFor === a.mac ? null : a.mac)
                        }
                      >
                        From URL…
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {urlFor && (
          <form
            className="banner backup-row"
            onSubmit={(e) => {
              e.preventDefault();
              const ap = d.aps.find((a) => a.mac === urlFor);
              if (
                !window.confirm(
                  `Install the firmware at ${url} on ${ap?.name ?? urlFor}? apctl cannot check custom firmware; the AP verifies it before writing.`,
                )
              )
                return;
              void run(async () => {
                await upgradeFirmwareUrl(urlFor, url);
                setUrlFor(null);
                setUrl("");
                return "Queued.";
              });
            }}
          >
            <span className="small">
              Firmware file for {d.aps.find((a) => a.mac === urlFor)?.name}:
            </span>
            <input
              className="search"
              required
              placeholder="https://…/firmware.bin"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
            />
            <button className="btn small primary" type="submit" disabled={busy}>
              Install
            </button>
            <button
              className="btn small"
              type="button"
              onClick={() => setUrlFor(null)}
            >
              Cancel
            </button>
          </form>
        )}
      </div>

      {(job || d.jobs.queue.length > 0 || d.jobs.stopped) && (
        <div className="panel">
          <div className="panel-head">
            <b>Updates in progress</b>
            <span className="muted small">one AP at a time</span>
            <span className="spacer" />
            {!readOnly && d.jobs.queue.length > 0 && (
              <button
                className="btn small"
                onClick={() =>
                  run(
                    async () =>
                      `${(await cancelFirmware()).cancelled} cancelled.`,
                  )
                }
              >
                Cancel waiting
              </button>
            )}
          </div>
          {d.jobs.stopped && (
            <div className="small error">
              Stopped: {d.jobs.stopped}.{" "}
              {canAct && (
                <button
                  className="btn small"
                  onClick={() =>
                    run(
                      async () =>
                        `${(await upgradeFirmware([])).queued} queued; resuming.`,
                    )
                  }
                >
                  Resume
                </button>
              )}
            </div>
          )}
          {job && (
            <div className="small">
              <b>{job.name ?? job.mac}</b>: {job.from} → {job.target},{" "}
              {STEP[job.state] ?? job.state}
              {job.sent_at && ` since ${clock(job.sent_at)}`}
              {job.expires && (
                <span className="muted">
                  {" "}
                  · gives up at {clock(job.expires)}
                </span>
              )}
            </div>
          )}
          {d.jobs.queue.map((q) => (
            <div key={q.mac} className="small muted">
              Next: {q.name ?? q.mac} → {q.target}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
