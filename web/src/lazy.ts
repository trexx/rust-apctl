import { lazy } from "react";
import type { ComponentType, LazyExoticComponent } from "react";

const RELOADED = "apctl:reloaded-for-chunk";
// A chunk that fails again within this long of a reload fails for good.
const RELOAD_EVERY_MS = 60_000;

// Any props, as React.lazy itself takes.
type AnyComponent = ComponentType<any>;

/**
 * `React.lazy` for a named export. An upgrade replaces the fingerprinted chunk
 * files, so a tab opened before it can't load a page it hasn't loaded yet: it
 * then reloads to get the new build. A failure within a minute of that reload
 * is a real one (a chunk that can't load or evaluate in this browser) and
 * reaches the error boundary. The time is kept rather than cleared on success,
 * as another chunk loading says nothing about the one that failed.
 */
export function lazyNamed<M extends Record<K, AnyComponent>, K extends keyof M>(
  load: () => Promise<M>,
  name: K,
): LazyExoticComponent<M[K]> {
  return lazy(() =>
    load().then(
      (m) => ({ default: m[name] }),
      (e: unknown) => {
        let reload = false;
        try {
          const last = Number(sessionStorage.getItem(RELOADED));
          reload = !(Date.now() - last < RELOAD_EVERY_MS);
          if (reload) sessionStorage.setItem(RELOADED, String(Date.now()));
        } catch {
          // Storage blocked: never reload, or a broken build would loop.
          reload = false;
        }
        if (!reload) throw e;
        window.location.reload();
        // Keep showing the loading state until the page goes away.
        return new Promise<never>(() => {});
      },
    ),
  );
}
