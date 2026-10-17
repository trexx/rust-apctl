import { useState } from "react";
import { Link } from "react-router";
import { ackThreat, keys, useCanEdit, useThreats } from "../api";
import type { ThreatFinding } from "../api";
import { ago, band, duration, useNow } from "../format";
import { ErrorNote, Loading, Signal, useRunner } from "./common";

const KIND_LABEL: Record<ThreatFinding["kind"], string> = {
  spoofed_bssid: "Cloned AP address",
  impersonation: "Copy of your network",
  lookalike: "Look-alike name",
  bridged: "Network run by a client",
  new_nearby: "New strong network",
};

const SEVERITY_LABEL = { high: "High", medium: "Medium", low: "Low" };

function Finding({ f, readOnly }: { f: ThreatFinding; readOnly: boolean }) {
  const [noting, setNoting] = useState(false);
  const [note, setNote] = useState("");
  // The engine writes asynchronously: refresh once it has.
  const { busy, msg, run } = useRunner([keys.threats()], 1500);
  const now = useNow();
  const ack = (on: boolean, why?: string) =>
    void run(async () => {
      await ackThreat(f.kind, f.bssid, on, why);
      setNoting(false);
    });
  return (
    <div className={`threat threat-${f.acknowledged ? "acked" : f.severity}`}>
      <div className="threat-head">
        <span className={`sev sev-${f.severity}`}>
          {SEVERITY_LABEL[f.severity]}
        </span>
        <b>{KIND_LABEL[f.kind]}</b>
        <span>
          {f.essid ? (
            `"${f.essid}"`
          ) : (
            <span className="muted">hidden network</span>
          )}
        </span>
        <span className="spacer" />
        <Signal dbm={f.best_signal} />
      </div>
      <p className="threat-detail">{f.detail}</p>
      <div className="threat-meta small muted">
        <span className="mono">{f.bssid}</span>
        {f.vendor && <span>{f.vendor}</span>}
        {f.channel !== null && (
          <span>
            {band(f.radio)} channel {f.channel}
          </span>
        )}
        {f.security && <span>{f.security}</span>}
        <span>
          heard by{" "}
          {f.heard_by.map((h, i) => (
            <span key={h.mac}>
              {i > 0 && ", "}
              <Link to={`/devices/${h.mac}`}>{h.name ?? h.mac}</Link>
              {h.signal !== null && ` (${h.signal} dBm)`}
            </span>
          ))}
        </span>
        <span>
          first seen {ago(f.first_seen, now)}, last {ago(f.last_seen, now)}
        </span>
        {f.kind === "bridged" && f.target && (
          <Link to={`/clients/${f.target}`}>view client</Link>
        )}
      </div>
      {f.acknowledged ? (
        <div className="threat-ack small">
          Dismissed {ago(f.acknowledged.ts, now)}
          {f.acknowledged.note && <>: “{f.acknowledged.note}”</>}
          {!readOnly && (
            <button
              className="btn small"
              disabled={busy}
              onClick={() => ack(false)}
            >
              Undo
            </button>
          )}
        </div>
      ) : (
        !readOnly &&
        (noting ? (
          <form
            className="threat-ack"
            onSubmit={(e) => {
              e.preventDefault();
              ack(true, note);
            }}
          >
            <input
              className="search"
              autoFocus
              maxLength={200}
              placeholder="Why it's fine, e.g. “the neighbours' printer” (optional)"
              value={note}
              onChange={(e) => setNote(e.target.value)}
            />
            <button className="btn small primary" type="submit" disabled={busy}>
              Dismiss
            </button>
            <button
              className="btn small"
              type="button"
              onClick={() => setNoting(false)}
            >
              Cancel
            </button>
          </form>
        ) : (
          <div className="threat-ack">
            <button className="btn small" onClick={() => setNoting(true)}>
              It's known, dismiss…
            </button>
          </div>
        ))
      )}
      {msg && !msg.ok && <ErrorNote error={msg.text} />}
    </div>
  );
}

export function ThreatList() {
  const t = useThreats();
  const readOnly = !useCanEdit();
  const [showAcked, setShowAcked] = useState(false);
  if (t.error) return <ErrorNote error={t.error} />;
  if (!t.data) return <Loading />;
  const open = t.data.findings.filter((f) => !f.acknowledged);
  const acked = t.data.findings.filter((f) => f.acknowledged);
  // As of the last fetch (it refreshes every minute).
  const watched = t.dataUpdatedAt / 1000 - t.data.watching_since;
  return (
    <>
      <div className="panel">
        <div className="panel-head">
          <b>
            {open.length === 0
              ? "No suspicious networks"
              : `${open.length} suspicious network${open.length > 1 ? "s" : ""}`}
          </b>
          <span className="muted small">
            from your APs' background scans over the last 7 days · watching for{" "}
            {duration(watched)}
          </span>
        </div>
        <p className="muted small">
          Flags networks that copy your network names or your APs' addresses,
          names made to look like yours, networks run by your own Wi-Fi clients
          (hotspots, extenders, device setup networks) and, after two days of
          watching, strong networks that are new. Dismiss the ones you know; a
          dismissed network is reported again if it does something different
          later.
        </p>
        {open.length === 0 && (
          <div className="muted small">Nothing to look at right now.</div>
        )}
      </div>
      {open.map((f) => (
        <Finding key={f.kind + f.bssid} f={f} readOnly={readOnly} />
      ))}
      {acked.length > 0 && (
        <div className="panel">
          <button className="btn small" onClick={() => setShowAcked((v) => !v)}>
            {showAcked ? "Hide" : "Show"} {acked.length} dismissed
          </button>
        </div>
      )}
      {showAcked &&
        acked.map((f) => (
          <Finding key={f.kind + f.bssid} f={f} readOnly={readOnly} />
        ))}
    </>
  );
}

/** A warning on the overview while anything serious is unacknowledged. */
export function ThreatBanner() {
  const t = useThreats();
  const open = (t.data?.findings ?? []).filter(
    (f) => !f.acknowledged && f.severity !== "low",
  );
  const worst = open[0];
  if (!worst) return null;
  return (
    <div className={`banner banner-${worst.severity}`}>
      <b>
        {open.length === 1
          ? "A suspicious network"
          : `${open.length} suspicious networks`}
      </b>{" "}
      nearby: {KIND_LABEL[worst.kind].toLowerCase()}
      {worst.essid ? ` "${worst.essid}"` : ""}
      {open.length > 1 ? " and more" : ""}.{" "}
      <Link to="/radios?tab=rogue">Review</Link>
    </div>
  );
}
