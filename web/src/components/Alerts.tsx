import { useEffect, useRef, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { keys, markAlertsRead, useAlerts } from "../api";
import type { AlertCategory, AlertItem } from "../api";
import { clock } from "../format";
import { useDismiss, useRunner } from "./common";

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

interface Prefs {
  enabled: boolean;
  categories: Record<AlertCategory, boolean>;
}

/** The app icon (the same inline image as the page's favicon). */
const ICON = "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Cpath d='M16 26a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm-7-9a10 10 0 0 1 14 0l-2 2a7 7 0 0 0-10 0zm-4-4a15 15 0 0 1 22 0l-2 2a12 12 0 0 0-18 0z' fill='%232f6fdf'/%3E%3C/svg%3E";

const PREFS_KEY = "apctl.notifications";
const DEFAULT_PREFS: Prefs = {
  enabled: false,
  categories: { ap_status: true, security: true, health: true, changes: true },
};

/** This browser's notification choices (stored only in this browser). */
function loadPrefs(): Prefs {
  try {
    const raw = localStorage.getItem(PREFS_KEY);
    if (raw)
      return {
        ...DEFAULT_PREFS,
        ...JSON.parse(raw),
        categories: {
          ...DEFAULT_PREFS.categories,
          ...JSON.parse(raw).categories,
        },
      };
  } catch {
    // Storage blocked or corrupt: fall back to defaults.
  }
  return DEFAULT_PREFS;
}

function savePrefs(p: Prefs) {
  try {
    localStorage.setItem(PREFS_KEY, JSON.stringify(p));
  } catch {
    // Storage blocked: the choice lasts until the page reloads.
  }
}

const notificationsSupported = () =>
  typeof window !== "undefined" &&
  "Notification" in window &&
  window.isSecureContext;

function show(
  title: string,
  body: string,
  tag: string,
  link: string | null,
  navigate: (to: string) => void,
) {
  try {
    const n = new Notification(title, { body, tag, icon: ICON });
    n.onclick = () => {
      window.focus();
      if (link) navigate(link);
      n.close();
    };
  } catch {
    // Some platforms only allow notifications from a service worker.
  }
}

/** Shows browser notifications for alerts while this tab is open. */
export function useNotifier() {
  const navigate = useNavigate();
  useEffect(() => {
    const onAlert = (e: Event) => {
      const a = (e as CustomEvent).detail as AlertItem & {
        action: "raised" | "resolved";
      };
      const prefs = loadPrefs();
      if (
        !prefs.enabled ||
        !prefs.categories[a.category] ||
        !notificationsSupported() ||
        Notification.permission !== "granted"
      )
        return;
      if (a.action === "resolved") {
        // Replaces the open notification (same tag) with the outcome.
        show(`Resolved: ${a.title}`, a.message, a.tag, a.link, navigate);
      } else {
        show(a.title, a.message, a.tag, a.link, navigate);
      }
    };
    window.addEventListener("apctl:alert", onAlert);
    return () => window.removeEventListener("apctl:alert", onAlert);
  }, [navigate]);
}

/** The header bell: unread count and the latest alerts. */
export function AlertBell() {
  const a = useAlerts();
  // The server stores the change a moment later.
  const { run } = useRunner([keys.alerts()], 800);
  const [open, setOpen] = useState(false);
  const box = useRef<HTMLDivElement>(null);
  useDismiss(box, () => setOpen(false), open);
  const unread = a.data?.unread ?? 0;
  const list = a.data?.alerts ?? [];
  const openNow = list.filter((x) => x.resolved_ts === null);
  const readAll = () => void run(markAlertsRead);
  return (
    <div className="bell-wrap" ref={box}>
      <button
        className={`bell ${openNow.some((x) => x.severity === "high") ? "bell-bad" : ""}`}
        aria-label={`Alerts, ${unread} unread`}
        onClick={() => setOpen((o) => !o)}
      >
        <svg viewBox="0 0 24 24" width="18" height="18" aria-hidden="true">
          <path
            d="M12 22a2.5 2.5 0 0 0 2.45-2h-4.9A2.5 2.5 0 0 0 12 22zm7-6V11a7 7 0 0 0-5.5-6.84V3a1.5 1.5 0 0 0-3 0v1.16A7 7 0 0 0 5 11v5l-2 2v1h18v-1z"
            fill="currentColor"
          />
        </svg>
        {unread > 0 && (
          <span className="bell-count">{unread > 99 ? "99+" : unread}</span>
        )}
      </button>
      {open && (
        <div className="bell-pop panel" role="dialog" aria-label="Alerts">
          <div className="panel-head">
            <b>Alerts</b>
            {openNow.length > 0 && (
              <span className="muted small">{openNow.length} open</span>
            )}
            <span className="spacer" />
            {unread > 0 && (
              <button className="btn small" onClick={readAll}>
                Mark all read
              </button>
            )}
          </div>
          {list.length === 0 ? (
            <div className="muted small">No alerts yet.</div>
          ) : (
            <ul className="alert-list">
              {list.slice(0, 20).map((x) => (
                <li
                  key={x.id}
                  className={`alert-item sev-border-${x.severity} ${x.read ? "" : "unread"}`}
                >
                  <div className="alert-top">
                    <span className="alert-title">
                      {x.link ? (
                        <Link to={x.link} onClick={() => setOpen(false)}>
                          {x.title}
                        </Link>
                      ) : (
                        x.title
                      )}
                    </span>
                    <span className="muted small nowrap">{clock(x.ts)}</span>
                  </div>
                  <div className="small muted">{x.message}</div>
                  {x.resolved_ts === null ? (
                    <span className="tag tag-warn">open</span>
                  ) : null}
                </li>
              ))}
            </ul>
          )}
          <div className="small">
            <Link to="/settings#notifications" onClick={() => setOpen(false)}>
              Browser notification settings
            </Link>
          </div>
        </div>
      )}
    </div>
  );
}

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
