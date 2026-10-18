import { useState } from "react";
import { adoptAp, adoptOverSsh, keys, useAdoption, useCanEdit } from "../api";
import { ago, useNow } from "../format";
import { Outcome, TextField, useRunner } from "./common";

/** APs waiting for adoption, and adopting one by IP over SSH (active mode). */
export function AdoptionPanel() {
  const canEdit = useCanEdit();
  // Read-only users never see the panel, so don't fetch (or poll) for them.
  const a = useAdoption(canEdit);
  const now = useNow();
  const [form, setForm] = useState(false);
  const [ip, setIp] = useState("");
  const [user, setUser] = useState("");
  const [pass, setPass] = useState("");
  // Event lists refetch when the adoption's events arrive.
  const { busy, msg, run } = useRunner([keys.adoption(), keys.devices()]);
  if (!a.data || !a.data.active || !canEdit) return null;
  const d = a.data;
  const nothing = d.pending.length === 0 && d.adopting.length === 0;
  return (
    <div className="panel">
      <div className="panel-head">
        <b>Adopt APs</b>
        <span className="muted small">
          {nothing
            ? "no AP is waiting"
            : `${d.pending.length} waiting${d.adopting.length ? `, ${d.adopting.length} adopting` : ""}`}
        </span>
        <span className="spacer" />
        <button className="btn small" onClick={() => setForm((f) => !f)}>
          Adopt by IP
        </button>
      </div>
      {d.pending.length > 0 && (
        <div className="table-wrap">
          <table className="table">
            <tbody>
              {d.pending.map((p) => (
                <tr key={p.mac}>
                  <td>
                    <b>{p.hostname ?? p.model_display ?? p.model ?? p.mac}</b>
                    <div className="muted small mono">{p.mac}</div>
                  </td>
                  <td className="small">
                    {[p.model, p.version, p.ip].filter(Boolean).join(" · ")}
                    <div className="muted">
                      {p.known
                        ? "was yours, then reset: adopt it again"
                        : `waiting since ${ago(p.first_seen, now)}`}
                    </div>
                  </td>
                  <td className="nowrap">
                    <button
                      className="btn small primary"
                      disabled={busy}
                      onClick={() =>
                        void run(async () => {
                          await adoptAp(p.mac);
                          return "Adopting: it gets its own key with its next report, then its configuration.";
                        })
                      }
                    >
                      Adopt
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {d.adopting.map((x) => (
        <div key={x.mac} className="small muted">
          Adopting <span className="mono">{x.mac}</span> (since {ago(x.since, now)})…
        </div>
      ))}
      {form && (
        <div className="settings-form">
          <p className="muted small">
            For an AP that reports to another controller (or nowhere): apctl
            logs in over SSH and points it here
            {d.ssh.inform_url ? ` (${d.ssh.inform_url})` : ""}. Leave the login
            empty to try your site's device login, then the factory one
            (ubnt/ubnt).
          </p>
          <div className="form-row">
            <div className="form-label">IP address</div>
            <div className="form-control">
              <TextField
                value={ip}
                placeholder="192.168.1.20"
                aria-label="IP address"
                onChange={setIp}
              />
            </div>
          </div>
          <div className="form-row">
            <div className="form-label">SSH login</div>
            <div className="form-control">
              <TextField
                value={user}
                placeholder="username"
                autoComplete="off"
                aria-label="SSH user name"
                onChange={setUser}
              />
              <TextField
                type="password"
                value={pass}
                placeholder="password"
                autoComplete="new-password"
                aria-label="SSH password"
                onChange={setPass}
              />
            </div>
          </div>
          <div className="actions-row">
            <button
              className="btn primary"
              disabled={busy || !ip.trim() || !d.ssh.possible}
              onClick={() =>
                void run(async () => {
                  const r = await adoptOverSsh(ip.trim(), user, pass);
                  setForm(false);
                  // Don't keep the AP's password around once it has been used.
                  setPass("");
                  return `${r.mac} is being adopted: it should report here within a minute.`;
                })
              }
            >
              {busy ? "Connecting…" : "Adopt over SSH"}
            </button>
            {!d.ssh.possible && (
              <span className="small muted">
                apctl doesn't know the URL APs should report to: set
                APCTL_INFORM_URL.
              </span>
            )}
          </div>
        </div>
      )}
      <Outcome msg={msg} />
    </div>
  );
}
