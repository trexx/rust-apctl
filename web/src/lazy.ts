import { lazy } from "react";
import type { ComponentType, LazyExoticComponent } from "react";

const RELOADED = "apctl:reloaded-for-chunk";

// Any props, as React.lazy itself takes.
type AnyComponent = ComponentType<any>;

/**
 * `React.lazy` for a named export. An upgrade replaces the fingerprinted chunk
 * files, so a tab opened before it can't load a page it hasn't loaded yet: it
 * then reloads once to get the new build. A failure right after that reload is
 * a real one and reaches the error boundary.
 */
export function lazyNamed<M extends Record<K, AnyComponent>, K extends keyof M>(
  load: () => Promise<M>,
  name: K,
): LazyExoticComponent<M[K]> {
  return lazy(() =>
    load().then(
      (m) => {
        try {
          sessionStorage.removeItem(RELOADED);
        } catch {
          // Storage blocked: nothing to clear.
        }
        return { default: m[name] };
      },
      (e: unknown) => {
        let reloaded = true;
        try {
          reloaded = sessionStorage.getItem(RELOADED) !== null;
          if (!reloaded) sessionStorage.setItem(RELOADED, "1");
        } catch {
          // Storage blocked: never reload, or a broken build would loop.
        }
        if (reloaded) throw e;
        window.location.reload();
        // Keep showing the loading state until the page goes away.
        return new Promise<never>(() => {});
      },
    ),
  );
}
