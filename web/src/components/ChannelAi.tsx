import {
  applyChannelPlan,
  eventData,
  keys,
  runChannelAi,
  saveChannelAi,
  startScan,
  useCanEdit,
  useChannelAi,
  useDeviceNames,
  useEvents,
} from "../api";
import type { ChannelPlanResult } from "../api";
import { band as bandName, clock, hhmm, useNow } from "../format";
import {
  Outcome,
  QueryNote,
  QueryState,
  Toggle,
  eventText,
  useRunner,
} from "./common";
import { ApChecklist, Row, Select, toggled } from "./settings/form";

/**
 * Runs Channel AI actions. The settings checkboxes each send a patch built
 * from the current settings, so `busy` lasts until the refetched settings are
 * in: a second click can't send a patch built from stale ones. (Event lists
 * refetch when the change's event arrives.)
 */
const useRun = () =>
  useRunner([keys.channelAi(), keys.rfPlan(), keys.rfRadios()]);

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
            void run(async () => {
              const { applied } = await applyChannelPlan(band, changes);
              return applied === 1
                ? "1 AP gets the new channel with its next report."
                : `${applied} APs get the new channel with their next report.`;
            })
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

const HOURS = Array.from({ length: 24 }, (_, h) => [h, hhmm(h * 60)] as const);

/** Channel AI: the nightly optimisation's settings, Run now, recent runs. */
export function ChannelAiPanel() {
  const ai = useChannelAi();
  const names = useDeviceNames();
  const canEdit = useCanEdit();
  const runs = useEvents({ kind: "channel_plan", limit: 10 });
  const { busy, msg, run } = useRun();
  const now = useNow();
  if (!ai.data) return <QueryNote q={ai} />;
  const d = ai.data;
  const s = d.settings;
  const can = d.active && canEdit && !busy;
  const save = (patch: Record<string, unknown>) =>
    void run(async () => (await saveChannelAi(patch)).what);
  return (
    <div className="panel">
      <div className="panel-head">
        <b>Channel AI</b>
        <span className="muted small">
          {s.enabled
            ? `nightly at ${hhmm(s.hour * 60 + s.minute)} ${d.timezone ?? "UTC"}`
            : "nightly optimisation off"}
          {d.active && d.next_run ? ` · next ${clock(d.next_run, now)}` : ""}
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
              void run(
                () => runChannelAi(),
                "Running: the APs scan first (up to two minutes), then the plan is applied if it is clearly better.",
              )
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
        <Row label="Nightly">
          <Toggle
            value={s.enabled}
            disabled={!can}
            onChange={(enabled) => save({ enabled })}
            label="Enabled"
          />
          <Select
            aria-label="Hour"
            value={s.hour}
            options={HOURS}
            disabled={!can}
            onChange={(hour) => save({ hour })}
          />
          {(["ng", "na"] as const).map((b) => (
            <Toggle
              key={b}
              value={s.radios.includes(b)}
              disabled={!can}
              onChange={(on) => save({ radios: toggled(s.radios, b, on) })}
              label={bandName(b)}
            />
          ))}
        </Row>
        <Row label="Allowed channels" hint="your country, minus the blacklist">
          <span className="small">
            2.4 GHz: {d.allowed.ng?.join(", ") ?? "any"}
          </span>
          <span className="small">
            5 GHz: {d.allowed.na?.join(", ") ?? "any"}
          </span>
          <Toggle
            value={s.dfs}
            disabled={!can}
            onChange={(dfs) => save({ dfs })}
            label="DFS channels (radar can force an AP off them)"
          />
        </Row>
        <Row label="Excluded APs">
          <ApChecklist
            aps={Object.entries(names).map(([mac, name]) => ({ mac, name }))}
            value={s.exclude_devices}
            disabled={!can}
            onChange={(v) => save({ exclude_devices: v })}
          />
        </Row>
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
                  // The event lists' own text, plus why a plan wasn't applied.
                  const { error, applied } = eventData<"channel_plan">(e);
                  return (
                    <li key={e.id}>
                      <span className="muted nowrap">{clock(e.ts, now)}</span>{" "}
                      {eventText(e, names).detail}
                      {!applied && error && (
                        <span className="error"> {error}</span>
                      )}
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
