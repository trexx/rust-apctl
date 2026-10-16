import {
  blockClient,
  forgetAp,
  keys,
  kickClient,
  lockClient,
  locateAp,
  provisionAp,
  restartAp,
  setClientSpeedLimit,
  useCanEdit,
  useStatus,
  useUserGroups,
} from "../api";
import type { DeviceSummary, Mac } from "../api";
import { speed } from "../format";
import { Outcome, useRunner } from "./common";

/** Whether actions can be used: active mode, signed in. */
function useCanAct(): { can: boolean; why: string | null } {
  const status = useStatus().data;
  const canEdit = useCanEdit();
  if (!canEdit) return { can: false, why: null };
  if (status && status.mode !== "active")
    return {
      can: false,
      why: "Actions work after the cutover: in shadow mode apctl never talks to the APs.",
    };
  return { can: !!status, why: null };
}

export function DeviceActions({
  mac,
  name,
  online,
  locating,
}: {
  mac: Mac;
  name: string;
  online: boolean;
  locating: boolean;
}) {
  const { can, why } = useCanAct();
  const { busy, msg, run } = useRunner([keys.device(mac), keys.devices()]);
  if (!can && !why) return null;
  const off = !can || busy || !online;
  return (
    <div className="actions">
      <div className="actions-row">
        <button
          className={`btn small${locating ? " primary" : ""}`}
          disabled={off}
          title="Flash the AP's LED so you can find it"
          onClick={() =>
            void run(
              () => locateAp(mac, !locating),
              locating
                ? "The LED goes back to normal with the AP's next report."
                : "The LED starts flashing with the AP's next report.",
            )
          }
        >
          {locating ? "Stop locating" : "Locate"}
        </button>
        <button
          className="btn small"
          disabled={off}
          title="Send the AP its configuration again"
          onClick={() =>
            void run(
              () => provisionAp(mac),
              "The configuration goes out with the AP's next report.",
            )
          }
        >
          Re-send config
        </button>
        <button
          className="btn small"
          disabled={off}
          onClick={() =>
            window.confirm(
              `Restart ${name}? Its clients drop off for a minute or two.`,
            ) &&
            void run(
              () => restartAp(mac),
              "The AP restarts with its next report.",
            )
          }
        >
          Restart
        </button>
        <button
          className="btn small"
          disabled={!can || busy}
          title="Remove this AP from apctl; if it is online it resets to factory defaults"
          onClick={() =>
            window.confirm(
              `Forget ${name}? apctl stops managing it${online ? ", and it resets to factory defaults (its clients drop off)" : ""}. To use it again, adopt it.`,
            ) &&
            void run(async () => {
              const r = await forgetAp(mac);
              return r.forgetting
                ? "It resets with its next report and is then removed."
                : "Removed.";
            }, "")
          }
        >
          Forget
        </button>
      </div>
      <Outcome msg={msg} why={why} />
    </div>
  );
}

export function ClientActions({
  mac,
  name,
  connected,
  blocked,
  lockedTo,
  aps,
  usergroupId,
}: {
  mac: Mac;
  name: string;
  connected: boolean;
  blocked: boolean;
  lockedTo: Mac | null;
  aps: DeviceSummary[];
  usergroupId: string | null;
}) {
  const { can, why } = useCanAct();
  const { busy, msg, run } = useRunner([
    keys.client(mac),
    keys.clients(),
    keys.settings(),
  ]);
  const groups = (useUserGroups().data?.groups ?? []).filter((g) => !g.default);
  if (!can && !why) return null;
  const off = !can || busy;
  return (
    <div className="actions">
      <div className="actions-row">
        <button
          className="btn small"
          disabled={off || !connected}
          title="Disconnect the client; it reconnects on its own"
          onClick={() =>
            void run(
              () => kickClient(mac),
              "It is disconnected with its AP's next report, and reconnects on its own.",
            )
          }
        >
          Reconnect
        </button>
        <button
          className="btn small"
          disabled={off}
          onClick={() =>
            (blocked ||
              window.confirm(
                `Block ${name}? It can't join any SSID until you unblock it.`,
              )) &&
            void run(
              () => blockClient(mac, !blocked),
              blocked
                ? "Unblocked: it can connect again."
                : "Blocked on every AP.",
            )
          }
        >
          {blocked ? "Unblock" : "Block"}
        </button>
        <label className="small">
          Lock to AP{" "}
          <select
            disabled={off}
            value={lockedTo ?? ""}
            onChange={(e) => {
              const ap = e.target.value || null;
              void run(
                () => lockClient(mac, ap),
                ap
                  ? "Locked: the other APs refuse it once their config is updated."
                  : "Unlocked: it can use any AP.",
              );
            }}
          >
            <option value="">Any AP</option>
            {aps.map((a) => (
              <option key={a.mac} value={a.mac}>
                {a.name ?? a.mac}
              </option>
            ))}
          </select>
        </label>
        {groups.length > 0 && (
          <label className="small">
            Speed limit{" "}
            <select
              disabled={off}
              value={usergroupId ?? ""}
              onChange={(e) => {
                const g = e.target.value || null;
                void run(
                  () => setClientSpeedLimit(mac, g),
                  g
                    ? "Limited: its AP gets the limit within a few seconds while it is connected."
                    : "Its own limit is removed: the SSID's limit applies again.",
                );
              }}
            >
              <option value="">Same as its SSID</option>
              {groups.map((g) => (
                <option key={g.id} value={g.id}>
                  {g.name} (down {speed(g.qos_rate_max_down)}, up{" "}
                  {speed(g.qos_rate_max_up)})
                </option>
              ))}
            </select>
          </label>
        )}
      </div>
      <Outcome msg={msg} why={why} />
    </div>
  );
}
