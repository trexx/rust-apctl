import { Link } from "react-router";
import { useDeviceNames, useDryRun } from "../api";
import type {
  DryRun as DryRunData,
  FieldComparison,
  StoredComparison,
} from "../api";
import { Dot, QueryNote, THead } from "../components/common";
import { clock, useNow } from "../format";
import type { Tone } from "../format";

type Status = DryRunData["devices"][number]["status"];
type Compared = DryRunData["history"][number];

const STATUS: Record<Status, string> = {
  match: "Identical",
  equivalent: "Equivalent",
  differs: "Differs",
  error: "Generator error",
  no_settings: "Import settings first",
  no_config_seen: "No config seen yet",
};

/** A status's dot: the same config is good, a difference or an error bad, nothing to compare yet a warning. */
const TONE: Record<Status, Tone> = {
  match: "good",
  equivalent: "good",
  differs: "bad",
  error: "bad",
  no_settings: "warn",
  no_config_seen: "warn",
};

/** How one config compares, in words; `long` explains an equivalent one. */
const verdict = (c: StoredComparison, long = false) =>
  c.identical
    ? "identical"
    : c.equivalent
      ? long
        ? "equivalent: only the order of unordered lists differs (the current controller doesn't keep it stable)"
        : "equivalent"
      : c.same_content
        ? "same lines, different order"
        : `${c.added} extra, ${c.removed} missing, ${c.changed} different`;

function FieldResult({ label, c }: { label: string; c: FieldComparison }) {
  const ok = c.identical || c.equivalent;
  return (
    <div className="dr-field">
      <span className={ok ? "tone-good" : "error"}>{ok ? "✓" : "✗"}</span>{" "}
      <b>{label}</b>{" "}
      <span className="muted">
        {verdict(c, true)} · ours {c.expected_lines} lines, actual{" "}
        {c.actual_lines}
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
  if (!dr.data) return <QueryNote q={dr} />;
  const d = dr.data;
  // A match with a config that isn't identical differs only in the order of unordered lists.
  const equivalent = (h: Compared) =>
    h.matches &&
    (h.comparison?.system_cfg?.identical === false ||
      h.comparison?.mgmt_cfg?.identical === false);
  /** Each config that isn't identical, and how it compares. */
  const difference = (h: Compared) =>
    h.comparison?.error ??
    (["mgmt_cfg", "system_cfg"] as const)
      .flatMap((f) => {
        const c = h.comparison?.[f];
        return c && !c.identical ? [`${f}: ${verdict(c)}`] : [];
      })
      .join("; ");
  // The split is over the listed (newest) comparisons, the totals over all of them.
  const listed = d.history.length;
  const reordered = d.history.filter(equivalent).length;
  const identical = d.history.filter((h) => h.matches).length - reordered;
  const split = reordered
    ? ` (${listed < d.history_total ? `of the last ${listed}: ` : ""}${identical} identical, ${reordered} equivalent)`
    : "";
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
              <Dot tone={TONE[x.status] ?? "warn"} />
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
          {d.history_total
            ? `${d.history_matches} of ${d.history_total} match${split}`
            : ""}
        </span>
      </h2>
      <div className="panel">
        {listed === 0 ? (
          <div className="muted pad">
            No config pushes compared yet. They happen when the current
            controller changes an AP's config.
          </div>
        ) : (
          <table className="table">
            <THead columns={["Time", "AP", "Result", "Difference"]} />
            <tbody>
              {d.history.map((h) => (
                <tr key={h.id}>
                  <td>{clock(h.ts, now)}</td>
                  <td>{names[h.mac] ?? h.mac}</td>
                  <td className={h.matches ? "tone-good" : "error"}>
                    {equivalent(h)
                      ? "equivalent"
                      : h.matches
                        ? "identical"
                        : h.comparison?.error
                          ? "error"
                          : "differs"}
                  </td>
                  <td className="muted">{difference(h)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </>
  );
}
