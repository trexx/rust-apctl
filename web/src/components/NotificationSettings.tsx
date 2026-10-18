import { useState } from "react";
import type { AlertCategory } from "../api";
import { loadPrefs, notificationsSupported, savePrefs, show } from "./Alerts";
import type { Prefs } from "./Alerts";

const CATEGORIES: [AlertCategory, string, string][] = [
  [
    "ap_status",
    "AP offline / back online",
    "An AP has had no contact for 4 minutes, and when it returns.",
  ],
  [
    "security",
    "Suspicious networks",
    "Copies of your networks, cloned APs and look-alike names.",
  ],
  [
    "health",
    "Wi-Fi health",
    "Sustained high retries, channel use or interference, or clients failing to connect.",
  ],
  [
    "changes",
    "AP changes",
    "Restarts, firmware changes, radar (DFS) and applied settings.",
  ],
];

/** Settings: enable notifications in this browser and pick categories. */
export function NotificationSettings() {
  const [prefs, setPrefs] = useState<Prefs>(loadPrefs);
  const [permission, setPermission] = useState<
    NotificationPermission | "unsupported"
  >(notificationsSupported() ? Notification.permission : "unsupported");
  const update = (p: Prefs) => {
    setPrefs(p);
    savePrefs(p);
  };
  const enable = async () => {
    if (!notificationsSupported()) return;
    const result =
      Notification.permission === "granted"
        ? "granted"
        : await Notification.requestPermission();
    setPermission(result);
    if (result === "granted") update({ ...prefs, enabled: true });
  };
  const on = prefs.enabled && permission === "granted";
  return (
    <div className="panel" id="notifications">
      <div className="panel-head">
        <b>Browser notifications</b>
        <span className="muted small">
          for this browser only, while an apctl tab is open
        </span>
      </div>
      {permission === "unsupported" ? (
        <div className="muted small">
          This browser can't show notifications here (they need HTTPS and a
          browser that supports them).
        </div>
      ) : permission === "denied" ? (
        <div className="small">
          Notifications are blocked for this site. Allow them in the browser's
          site settings, then reload.
        </div>
      ) : (
        <div className="notif-row">
          {on ? (
            <>
              <span className="tone-good">On</span>
              <button
                className="btn small"
                onClick={() => update({ ...prefs, enabled: false })}
              >
                Turn off
              </button>
              <button
                className="btn small"
                onClick={() =>
                  show(
                    "apctl test notification",
                    "Notifications from apctl will look like this.",
                    "apctl-test",
                    "/",
                    () => undefined,
                  )
                }
              >
                Send a test
              </button>
            </>
          ) : (
            <button className="btn small primary" onClick={enable}>
              Enable notifications
            </button>
          )}
        </div>
      )}
      <div className="notif-cats">
        {CATEGORIES.map(([k, label, help]) => (
          <label key={k} className="notif-cat">
            <input
              type="checkbox"
              checked={prefs.categories[k]}
              onChange={(e) =>
                update({
                  ...prefs,
                  categories: { ...prefs.categories, [k]: e.target.checked },
                })
              }
            />
            <span>
              {label}
              <span className="muted small"> — {help}</span>
            </span>
          </label>
        ))}
      </div>
      <p className="muted small">
        Every alert also appears under the bell at the top, whether or not
        notifications are on.
      </p>
    </div>
  );
}
