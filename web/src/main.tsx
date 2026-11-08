import {
  Component,
  StrictMode,
  Suspense,
  useEffect,
  useLayoutEffect,
  useRef,
  useState,
} from "react";
import type { ReactNode, RefObject } from "react";
import { createRoot } from "react-dom/client";
import {
  QueryClient,
  QueryClientProvider,
  useQueryClient,
} from "@tanstack/react-query";
import {
  BrowserRouter,
  NavLink,
  Navigate,
  Route,
  Routes,
  useLocation,
  useNavigationType,
} from "react-router";
import {
  AuthError,
  HttpError,
  SIGNED_OUT,
  keys,
  login,
  logout,
  useLiveUpdates,
  useMe,
  useStatus,
} from "./api";
import { Overview } from "./pages/Overview";
import { AlertBell, useNotifier } from "./components/Alerts";
import { Loading, Outcome, useRunner } from "./components/common";
import { lazyNamed } from "./lazy";
import "./styles.css";

// The pages opened most load as soon as the first one is shown, so that
// moving to them doesn't wait; the rest load when first opened.
const OFTEN = {
  clients: () => import("./pages/Clients"),
  networks: () => import("./pages/Networks"),
  events: () => import("./pages/Events"),
  logs: () => import("./pages/Logs"),
};
const Clients = lazyNamed(OFTEN.clients, "Clients");
const Networks = lazyNamed(OFTEN.networks, "Networks");
const Events = lazyNamed(OFTEN.events, "Events");
const Logs = lazyNamed(OFTEN.logs, "Logs");
const Device = lazyNamed(() => import("./pages/Device"), "Device");
const Client = lazyNamed(() => import("./pages/Client"), "Client");
const Settings = lazyNamed(() => import("./pages/Settings"), "Settings");
const Radios = lazyNamed(() => import("./pages/Radios"), "Radios");
const Config = lazyNamed(() => import("./pages/Config"), "Config");

// The app keeps each page's scroll position (see ScrollKeeper): the browser's
// own restoration runs against the page still shown, since the router renders
// the next one in a transition.
history.scrollRestoration = "manual";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      // The live socket refreshes what changes; this only limits refetches on
      // focus and remount (hooks that need fresher data set their own).
      staleTime: 30_000,
      // A missing login won't fix itself (show the login page at once), nor
      // will another refusal (an unknown AP, nothing imported): only server
      // errors and lost connections are tried again.
      retry: (n, e) =>
        !(e instanceof AuthError) &&
        !(e instanceof HttpError && e.status < 500) &&
        n < 3,
    },
  },
});

/** Shows a failing page's error instead of unmounting the whole app. */
class ErrorBoundary extends Component<
  { children: ReactNode; resetKey: string },
  { error: Error | null }
> {
  state = { error: null as Error | null };
  static getDerivedStateFromError(error: Error) {
    return { error };
  }
  componentDidUpdate(prev: { resetKey: string }) {
    if (prev.resetKey !== this.props.resetKey && this.state.error)
      this.setState({ error: null });
  }
  render() {
    if (this.state.error)
      return (
        <div className="error pad">
          This page failed to render: {this.state.error.message}
        </div>
      );
    return this.props.children;
  }
}

function Login() {
  const qc = useQueryClient();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const { busy, msg, run } = useRunner();
  return (
    <div className="login">
      <form
        className="panel login-box"
        onSubmit={(e) => {
          e.preventDefault();
          void run(async () => {
            await login(username, password);
            await qc.invalidateQueries();
          });
        }}
      >
        <div className="brand">apctl</div>
        <label>
          Username
          <input
            className="search"
            autoFocus
            autoComplete="username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />
        </label>
        <label>
          Password
          <input
            className="search"
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </label>
        <Outcome msg={msg} />
        <button
          className="btn primary"
          type="submit"
          disabled={busy || !username || !password}
        >
          {busy ? "Signing in…" : "Sign in"}
        </button>
      </form>
    </div>
  );
}

/** Shows the login page when a session is required and missing. */
function Gate() {
  const qc = useQueryClient();
  const me = useMe();
  useEffect(() => {
    const onUnauthorized = () =>
      void qc.invalidateQueries({ queryKey: keys.me() });
    window.addEventListener("apctl:unauthorized", onUnauthorized);
    return () =>
      window.removeEventListener("apctl:unauthorized", onUnauthorized);
  }, [qc]);
  if (me.isLoading) return null;
  if (me.data && me.data.auth && !me.data.user) return <Login />;
  return (
    <Shell
      user={me.data?.user ?? null}
      readOnly={me.data?.read_only === true}
    />
  );
}

function Shell({ user, readOnly }: { user: string | null; readOnly: boolean }) {
  useLiveUpdates();
  useNotifier();
  const qc = useQueryClient();
  const status = useStatus();
  const location = useLocation();
  const header = useRef<HTMLElement>(null);
  useEffect(() => {
    // A failure here shows again, and is handled, when the page is opened.
    const t = setTimeout(() => {
      for (const load of Object.values(OFTEN)) load().catch(() => undefined);
    }, 1000);
    return () => clearTimeout(t);
  }, []);
  return (
    <div>
      <header className="top" ref={header}>
        <span className="brand">apctl</span>
        <nav>
          <NavLink to="/" end>
            Overview
          </NavLink>
          <NavLink to="/clients">Clients</NavLink>
          <NavLink to="/networks">Networks</NavLink>
          <NavLink to="/radios">Radios</NavLink>
          <NavLink to="/events">Events</NavLink>
          <NavLink to="/logs">Logs</NavLink>
          <NavLink to="/config">Config</NavLink>
          <NavLink to="/settings">Settings</NavLink>
        </nav>
        <span className="spacer" />
        <AlertBell />
        {status.data && (
          <span className="mode" title={status.data.source}>
            {status.data.mode} mode
          </span>
        )}
        {readOnly && (
          <span
            className="mode"
            title="No users are configured, so changes are disabled"
          >
            read-only
          </span>
        )}
        {user && (
          <span className="user">
            {user}
            <button
              className="btn small"
              onClick={async () => {
                await logout().catch(() => undefined);
                // Show the login page at once, and drop everything cached for this user.
                qc.setQueryData(keys.me(), SIGNED_OUT);
                qc.removeQueries({
                  predicate: (q) => q.queryKey[0] !== keys.me()[0],
                });
              }}
            >
              Sign out
            </button>
          </span>
        )}
      </header>
      <main>
        <Suspense fallback={<Loading />}>
          {/* With the search, so that another tab (?tab=) of a page that failed starts afresh. */}
          <ErrorBoundary resetKey={location.pathname + location.search}>
            <Routes>
              <Route path="/" element={<Overview />} />
              <Route path="/devices/:mac" element={<Device />} />
              <Route path="/clients" element={<Clients />} />
              <Route path="/radios" element={<Radios />} />
              <Route path="/clients/:mac" element={<Client />} />
              <Route path="/events" element={<Events />} />
              <Route path="/logs" element={<Logs />} />
              {/* The dry run is a tab of the Config page now. */}
              <Route
                path="/dryrun"
                element={<Navigate to="/config?tab=dryrun" replace />}
              />
              <Route path="/config" element={<Config />} />
              <Route path="/networks" element={<Networks />} />
              <Route path="/settings" element={<Settings />} />
              <Route
                path="*"
                element={<div className="pad muted">Page not found</div>}
              />
            </Routes>
          </ErrorBoundary>
          <ScrollKeeper header={header} />
        </Suspense>
      </main>
    </div>
  );
}

/** Scroll offsets by history entry, as last scrolled (see ScrollKeeper). */
const scrolled = new Map<string, number>();

/**
 * Each page's scroll position. A link opens its page at the top, or at the
 * element its #fragment names (a page still loading opens at its top), and so
 * does the first page loaded; another ?tab= of the same page keeps its place;
 * back and forward return to where that entry was left. Rendered after the
 * page in its Suspense boundary, its layout effect runs once the page (lazy or
 * not) is in the document and before it is painted. A #fragment's element
 * lands just below the sticky header, however tall it is at this width.
 *
 * An entry returned to while its page is shorter than where it was left (its
 * data still loading) keeps that offset and goes there as the page grows,
 * until it is reached, the user scrolls, or `REACH_MS` pass; meanwhile the
 * clamped offset is not stored for it. The offsets hold because every row is
 * laid out: rows skipped by `content-visibility` would count at a guessed
 * height on a page mounted again, and Back would land on another row.
 */
function ScrollKeeper({ header }: { header: RefObject<HTMLElement | null> }) {
  const location = useLocation();
  const navigation = useNavigationType();
  // The entry shown.
  const shown = useRef<{ key: string; path: string } | null>(null);
  // Its offset, while the page is still too short for it.
  const wanted = useRef<{ y: number; until: number } | null>(null);
  useEffect(() => {
    const waiting = () => {
      if (wanted.current && Date.now() > wanted.current.until)
        wanted.current = null;
      return wanted.current;
    };
    // Read when the browser scrolls, after the layout effect below has moved
    // `shown` to the entry on screen.
    const onScroll = () => {
      if (shown.current && !waiting())
        scrolled.set(shown.current.key, window.scrollY);
    };
    // Run after layout and before paint, as the page grows.
    const grown = new ResizeObserver(() => {
      const w = waiting();
      if (w && reach(w.y)) wanted.current = null;
    });
    grown.observe(document.body);
    // The user scrolling (or about to) takes over.
    const taken = () => {
      wanted.current = null;
    };
    const input = ["wheel", "touchstart", "keydown", "mousedown"] as const;
    window.addEventListener("scroll", onScroll, { passive: true });
    for (const e of input)
      window.addEventListener(e, taken, { capture: true, passive: true });
    return () => {
      window.removeEventListener("scroll", onScroll);
      for (const e of input)
        window.removeEventListener(e, taken, { capture: true });
      grown.disconnect();
    };
  }, []);
  useLayoutEffect(() => {
    const prev = shown.current;
    // The same entry again: the boundary shown again, or StrictMode's re-run.
    if (prev?.key === location.key) return;
    shown.current = { key: location.key, path: location.pathname };
    wanted.current = null;
    // An entry left in this session (one from before a reload opens as a link).
    const back = navigation === "POP" ? scrolled.get(location.key) : undefined;
    if (back !== undefined) {
      if (!reach(back))
        wanted.current = { y: back, until: Date.now() + REACH_MS };
    } else if (!prev || prev.path !== location.pathname || location.hash) {
      const target =
        location.hash && document.getElementById(location.hash.slice(1));
      const below = (header.current?.offsetHeight ?? 0) + 12;
      window.scrollTo(
        0,
        target
          ? target.getBoundingClientRect().top + window.scrollY - below
          : 0,
      );
    }
    // Where it opened (or is to), in case it is left without a scroll.
    scrolled.set(location.key, wanted.current?.y ?? window.scrollY);
  }, [location, navigation, header]);
  return null;
}

/** How long a returned-to entry's offset is tried again while its page grows. */
const REACH_MS = 2000;

/** Scrolls to `y`; false when the page is still too short to get there. */
function reach(y: number) {
  window.scrollTo(0, y);
  return window.scrollY >= y - 1;
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Gate />
      </BrowserRouter>
    </QueryClientProvider>
  </StrictMode>,
);
