import { Link } from "react-router";
import { useDeviceNames, useDryRun } from "../api";
import type { FieldComparison } from "../api";
import { ErrorNote, Loading } from "../components/common";
import { clock, useNow } from "../format";

const STATUS: Record<string, string> = {
  match: "Identical",
  equivalent: "Equivalent",
  differs: "Differs",
  error: "Generator error",
  no_settings: "Import settings first",
  no_config_seen: "No config seen yet",
};

function FieldResult({ label, c }: { label: string; c: FieldComparison }) {
  const verdict = c.identical
    ? "identical"
    : c.equivalent
      ? "equivalent: only the order of unordered lists differs (the current controller doesn't keep it stable)"
      : c.same_content
        ? "same lines, different order"
        : `${c.added} extra, ${c.removed} missing, ${c.changed} different`;
  const ok = c.identical || c.equivalent;
  return (
    <div className="dr-field">
      <span className={ok ? "ok" : "error"}>{ok ? "✓" : "✗"}</span>{" "}
      <b>{label}</b>{" "}
      <span className="muted">
        {verdict} · ours {c.expected_lines} lines, actual {c.actual_lines}
      </span>
      {!c.identical && c.diff && (
        <details>
          <summary>diff (actual → ours)</summary>
          <pre className="diff">{c.diff}</pre>
        </details>
      )}
    </div>
  );
}

/** The Config page's Dry run tab. */
export function DryRun() {
  const dr = useDryRun();
  const names = useDeviceNames();
  const now = useNow();
  if (dr.isLoading) return <Loading />;
  if (dr.error || !dr.data) return <ErrorNote error={dr.error ?? "no data"} />;
  const d = dr.data;
  const total = d.history.length;
  const matched = d.history.filter((h) => h.matches).length;
  return (
    <>
      <div className="page-head">
        <span className="muted">
          what apctl would push, compared with what the current controller
          pushes. Nothing is sent to APs.
        </span>
      </div>
      {d.devices.some((x) => x.settings_stale) && (
        <div className="banner">
          The current controller has pushed new config since the settings were
          imported, so differences below may just be those changes.{" "}
          <Link to="/settings">Re-import the settings</Link> to compare against
          what is configured now.
        </div>
      )}
      <h2>Now</h2>
      <div className="cards">
        {d.devices.map((x) => (
          <div key={x.mac} className="card">
            <div className="card-head">
              <span
                className={`dot ${x.status === "match" || x.status === "equivalent" ? "dot-ok" : x.status === "differs" || x.status === "error" ? "dot-bad" : "dot-warn"}`}
              />
              <span className="card-title">{x.name ?? x.mac}</span>
              <span className="muted">{STATUS[x.status] ?? x.status}</span>
            </div>
            {x.comparison && (
              <>
                <FieldResult label="mgmt_cfg" c={x.comparison.mgmt_cfg} />
                <FieldResult label="system_cfg" c={x.comparison.system_cfg} />
                {x.against_redacted && (
                  <div className="muted small">
                    Compared with a stored copy where passwords are masked.
                  </div>
                )}
              </>
            )}
            {x.error && <div className="error small">{x.error}</div>}
            {x.settings_stale && (
              <div className="muted small">
                Settings changed on the current controller since the import.
              </div>
            )}
          </div>
        ))}
      </div>
      <h2>
        At each config push{" "}
        <span className="muted small">
          {total ? `${matched} of ${total} identical` : ""}
        </span>
      </h2>
      <div className="panel">
        {total === 0 ? (
          <div className="muted pad">
            No config pushes compared yet. They happen when the current
            controller changes an AP's config.
          </div>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Time</th>
                <th>AP</th>
                <th>Result</th>
                <th>system_cfg</th>
              </tr>
            </thead>
            <tbody>
              {d.history.map((h, i) => (
                <tr key={`${h.ts}-${i}`}>
                  <td>{clock(h.ts, now)}</td>
                  <td>{names[h.mac] ?? h.mac}</td>
                  <td className={h.matches ? "ok" : "error"}>
                    {h.matches
                      ? h.comparison?.system_cfg?.identical === false
                        ? "equivalent"
                        : "identical"
                      : "differs"}
                  </td>
                  <td className="muted">
                    {h.comparison?.error ??
                      (h.comparison?.system_cfg
                        ? `${h.comparison.system_cfg.added} extra, ${h.comparison.system_cfg.removed} missing, ${h.comparison.system_cfg.changed} different`
                        : "")}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </>
  );
}
