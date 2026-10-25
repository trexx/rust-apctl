import { useEffect, useRef, useState } from "react";
import { Link, useNavigate } from "react-router";
import { keys, markAlertsRead, useAlerts, useCanEdit } from "../api";
import type { AlertCategory, AlertItem } from "../api";
import { clock, useNow } from "../format";
import { Outcome, useDismiss, useRunner } from "./common";

export interface Prefs {
  enabled: boolean;
  categories: Record<AlertCategory, boolean>;
}

/** The app icon: the page's favicon (an inline image in index.html). */
const icon = () =>
  document.querySelector<HTMLLinkElement>('link[rel="icon"]')?.href;

const PREFS_KEY = "apctl.notifications";
const DEFAULT_PREFS: Prefs = {
  enabled: false,
  categories: { ap_status: true, security: true, health: true, changes: true },
};

/** This browser's notification choices (stored only in this browser). */
export function loadPrefs(): Prefs {
  try {
    const raw = localStorage.getItem(PREFS_KEY);
    if (raw) {
      const saved = JSON.parse(raw) as Partial<Prefs>;
      return {
        ...DEFAULT_PREFS,
        ...saved,
        categories: { ...DEFAULT_PREFS.categories, ...saved.categories },
      };
    }
  } catch {
    // Storage blocked or corrupt: fall back to defaults.
  }
  return DEFAULT_PREFS;
}

export function savePrefs(p: Prefs) {
  try {
    localStorage.setItem(PREFS_KEY, JSON.stringify(p));
  } catch {
    // Storage blocked: the choice lasts until the page reloads.
  }
}

export const notificationsSupported = () =>
  typeof window !== "undefined" &&
  "Notification" in window &&
  window.isSecureContext;

export function show(
  title: string,
  body: string,
  tag: string,
  link: string | null,
  navigate: (to: string) => void,
) {
  try {
    const n = new Notification(title, { body, tag, icon: icon() });
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
      // A resolution replaces the open notification (same tag) with the outcome.
      const title = a.action === "resolved" ? `Resolved: ${a.title}` : a.title;
      show(title, a.message, a.tag, a.link, navigate);
    };
    window.addEventListener("apctl:alert", onAlert);
    return () => window.removeEventListener("apctl:alert", onAlert);
  }, [navigate]);
}

/** The header bell: unread count and the latest alerts. */
export function AlertBell() {
  const a = useAlerts();
  // Marking read is a change: read-only mode refuses it.
  const canEdit = useCanEdit();
  const now = useNow();
  // The server stores the change a moment later.
  const { busy, msg, run } = useRunner([keys.alerts()], 800);
  const [open, setOpen] = useState(false);
  const box = useRef<HTMLDivElement>(null);
  useDismiss(box, () => setOpen(false), open);
  const unread = a.data?.unread ?? 0;
  const openNow = a.data?.open ?? 0;
  const list = a.data?.alerts ?? [];
  const readAll = () => void run(markAlertsRead);
  return (
    <div className="bell-wrap" ref={box}>
      <button
        className={`bell ${a.data?.open_high ? "bell-bad" : ""}`}
        aria-label={`Alerts, ${unread} unread`}
        aria-haspopup="dialog"
        aria-expanded={open}
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
            {openNow > 0 && <span className="muted small">{openNow} open</span>}
            <span className="spacer" />
            {canEdit && unread > 0 && (
              <button className="btn small" disabled={busy} onClick={readAll}>
                Mark all read
              </button>
            )}
          </div>
          {/* Only a failure says anything; success shows in the list. */}
          <Outcome msg={msg} />
          {list.length === 0 ? (
            <div className="muted small">No alerts yet.</div>
          ) : (
            <ul className="alert-list">
              {list.map((x) => (
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
                    <span className="muted small nowrap">{clock(x.ts, now)}</span>
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
