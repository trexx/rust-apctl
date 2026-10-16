import {
  applyChannelPlan,
  eventData,
  keys,
  runChannelAi,
  saveChannelAi,
  startScan,
  useCanEdit,
  useChannelAi,
  useDevices,
  useEvents,
} from "../api";
import type { ChannelPlanResult } from "../api";
import { band as bandName, clock } from "../format";
import { ErrorNote, Loading, Outcome, QueryState, useRunner } from "./common";

/**
 * Runs Channel AI actions. The settings checkboxes each send a patch built
 * from the current settings, so `busy` lasts until the refetched settings are
 * in: a second click can't send a patch built from stale ones.
 */
const useRun = () =>
  useRunner([keys.channelAi(), keys.rfPlan(), keys.events(), keys.rfRadios()]);

/** Scan now / Apply plan for one band's channel plan. */
export function PlanActions({
  band,
  plan,
}: {
  band: string;
  plan: ChannelPlanResult | undefined;
}) {
  const ai = useChannelAi();
  const canEdit = useCanEdit();
  const { busy, msg, run } = useRun();
  if (!canEdit || !ai.data) return null;
  const active = ai.data.active;
  const scanning = ai.data.scans.filter((s) => s.band === band);
  const changes = (plan?.plan ?? [])
    .filter((p) => p.change)
    .map((p) => ({
      mac: p.mac,
      name: p.name,
      from: p.current_channel,
      to: p.suggested_channel,
    }));
  return (
    <div className="actions">
      <div className="actions-row">
        <button
          className="btn small"
          disabled={!active || busy || scanning.length > 0}
          title="Each AP briefly listens on every channel of this band"
          onClick={() =>
            void run(
              async () =>
                `${(await startScan(band)).scanning.length} APs scanning; the plan updates when they finish.`,
            )
          }
        >
          {scanning.length > 0
            ? `Scanning (${scanning.length} APs)…`
            : "Scan now"}
        </button>
        <button
          className="btn small primary"
          disabled={!active || busy || changes.length === 0}
          onClick={() =>
            window.confirm(
              `Move ${changes.map((c) => `${c.name ?? c.mac} to channel ${c.to}`).join(", ")}? Clients reconnect briefly.`,
            ) &&
            void run(
              async () =>
                `${(await applyChannelPlan(band, changes)).applied} AP${changes.length === 1 ? "" : "s"} get the new channel with their next report.`,
            )
          }
        >
          Apply plan
        </button>
      </div>
      <Outcome
        msg={msg}
        why={active ? null : "Scanning and applying work after the cutover."}
      />
    </div>
  );
}

const HOURS = Array.from({ length: 24 }, (_, h) => h);

/** Channel AI: the nightly optimisation's settings, Run now, recent runs. */
export function ChannelAiPanel() {
  const ai = useChannelAi();
  const devices = useDevices();
  const canEdit = useCanEdit();
  const runs = useEvents({ kind: "channel_plan", limit: 10 });
  const { busy, msg, run } = useRun();
  if (ai.error) return <ErrorNote error={ai.error} />;
  if (!ai.data) return <Loading />;
  const d = ai.data;
  const s = d.settings;
  const can = d.active && canEdit && !busy;
  const save = (patch: Record<string, unknown>) =>
    void run(async () => (await saveChannelAi(patch)).what);
  const name = (mac: string) =>
    devices.data?.find((x) => x.mac === mac)?.name ?? mac;
  return (
    <div className="panel">
      <div className="panel-head">
        <b>Channel AI</b>
        <span className="muted small">
          {s.enabled
            ? `nightly at ${String(s.hour).padStart(2, "0")}:${String(s.minute).padStart(2, "0")} ${d.timezone ?? "UTC"}`
            : "nightly optimisation off"}
          {d.active && d.next_run ? ` · next ${clock(d.next_run)}` : ""}
        </span>
        <span className="spacer" />
        {canEdit && (
          <button
            className="btn small"
            disabled={!can || d.running}
            title="Scan, plan and apply now"
            onClick={() =>
              window.confirm(
                "Scan and move APs to better channels now? APs that move drop their clients for a moment.",
              ) &&
              void run(async () => {
                await runChannelAi();
                return "Running: the APs scan first (up to two minutes), then the plan is applied if it is clearly better.";
              })
            }
          >
            {d.running ? "Running…" : "Run now"}
          </button>
        )}
      </div>
      <p className="muted small">
        Each night every AP scans its bands, then APs move to clearly better
        channels (by more than 10%) among the ones allowed below, at their
        current width. APs on a wireless uplink, excluded APs and APs being
        upgraded keep their channel.
        {!d.active &&
          " In shadow mode your current controller does this; apctl takes over after the cutover."}
      </p>
      <div className="settings-form">
        <div className="form-row">
          <div className="form-label">Nightly</div>
          <div className="form-control">
            <label className="check">
              <input
                type="checkbox"
                checked={s.enabled}
                disabled={!can}
                onChange={(e) => save({ enabled: e.target.checked })}
              />
              Enabled
            </label>
            <select
              value={s.hour}
              disabled={!can}
              onChange={(e) => save({ hour: Number(e.target.value) })}
            >
              {HOURS.map((h) => (
                <option key={h} value={h}>
                  {String(h).padStart(2, "0")}:00
                </option>
              ))}
            </select>
            {(["ng", "na"] as const).map((b) => (
              <label key={b} className="check">
                <input
                  type="checkbox"
                  checked={s.radios.includes(b)}
                  disabled={!can}
                  onChange={(e) =>
                    save({
                      radios: e.target.checked
                        ? [...s.radios, b]
                        : s.radios.filter((x) => x !== b),
                    })
                  }
                />
                {bandName(b)}
              </label>
            ))}
          </div>
        </div>
        <div className="form-row">
          <div className="form-label">
            Allowed channels
            <div className="muted small">your country, minus the blacklist</div>
          </div>
          <div className="form-control small">
            <span>2.4 GHz: {d.allowed.ng?.join(", ") ?? "any"}</span>
            <span>5 GHz: {d.allowed.na?.join(", ") ?? "any"}</span>
            <label className="check">
              <input
                type="checkbox"
                checked={s.dfs}
                disabled={!can}
                onChange={(e) => save({ dfs: e.target.checked })}
              />
              DFS channels (radar can force an AP off them)
            </label>
          </div>
        </div>
        <div className="form-row">
          <div className="form-label">Excluded APs</div>
          <div className="form-control">
            {(devices.data ?? []).map((ap) => (
              <label key={ap.mac} className="check">
                <input
                  type="checkbox"
                  checked={s.exclude_devices.includes(ap.mac)}
                  disabled={!can}
                  onChange={(e) =>
                    save({
                      exclude_devices: e.target.checked
                        ? [...s.exclude_devices, ap.mac]
                        : s.exclude_devices.filter((m) => m !== ap.mac),
                    })
                  }
                />
                {ap.name ?? ap.mac}
              </label>
            ))}
          </div>
        </div>
      </div>
      <Outcome msg={msg} />
      <div className="small">
        <b>Recent runs</b>
        <QueryState q={runs}>
          {(data) =>
            data.length === 0 ? (
              <div className="muted">None yet.</div>
            ) : (
              <ul className="plain-list">
                {data.map((e) => {
                  const r = eventData<"channel_plan">(e);
                  const changes = r.changes ?? [];
                  return (
                    <li key={e.id}>
                      <span className="muted nowrap">{clock(e.ts)}</span>{" "}
                      {r.band ? bandName(r.band) : r.band} ({r.trigger}):{" "}
                      {changes.length === 0
                        ? "no clearly better plan, nothing moved"
                        : changes
                            .map(
                              (c) =>
                                `${c.name ?? name(c.mac)} ${c.from ?? "?"} → ${c.to}`,
                            )
                            .join(", ") +
                          (r.applied
                            ? ""
                            : ` (not applied: ${r.error ?? "?"})`)}
                    </li>
                  );
                })}
              </ul>
            )
          }
        </QueryState>
      </div>
    </div>
  );
}
