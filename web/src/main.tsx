import { Component, StrictMode, Suspense, useEffect, useState } from "react";
import type { ReactNode } from "react";
import { createRoot } from "react-dom/client";
import {
  QueryClient,
  QueryClientProvider,
  useQueryClient,
} from "@tanstack/react-query";
import {
  BrowserRouter,
  NavLink,
  Route,
  Routes,
  useLocation,
} from "react-router-dom";
import {
  AuthError,
  SIGNED_OUT,
  keys,
  login,
  logout,
  useLiveUpdates,
  useMe,
  useStatus,
} from "./api";
import { Overview } from "./pages/Overview";
import { Clients } from "./pages/Clients";
import { Events } from "./pages/Events";
import { Logs } from "./pages/Logs";
import { Networks } from "./pages/Networks";
import { AlertBell, useNotifier } from "./components/Alerts";
import { Loading, Outcome, useRunner } from "./components/common";
import { lazyNamed } from "./lazy";
import "./styles.css";

// Pages that are seldom opened, or large, load on demand.
const Device = lazyNamed(() => import("./pages/Device"), "Device");
const Client = lazyNamed(() => import("./pages/Client"), "Client");
const Settings = lazyNamed(() => import("./pages/Settings"), "Settings");
const Radios = lazyNamed(() => import("./pages/Radios"), "Radios");
const Config = lazyNamed(() => import("./pages/Config"), "Config");
const DryRunPage = lazyNamed(() => import("./pages/DryRun"), "DryRunPage");

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      // The live socket refreshes what changes; this only limits refetches on
      // focus and remount (hooks that need fresher data set their own).
      staleTime: 30_000,
      refetchOnWindowFocus: true,
      // A missing login won't fix itself: show the login page at once.
      retry: (n, e) => !(e instanceof AuthError) && n < 3,
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
  return (
    <div className="shell">
      <header className="top">
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
        <ErrorBoundary resetKey={location.pathname}>
          <Suspense fallback={<Loading />}>
            <Routes>
              <Route path="/" element={<Overview />} />
              <Route path="/devices/:mac" element={<Device />} />
              <Route path="/clients" element={<Clients />} />
              <Route path="/radios" element={<Radios />} />
              <Route path="/clients/:mac" element={<Client />} />
              <Route path="/events" element={<Events />} />
              <Route path="/logs" element={<Logs />} />
              <Route path="/dryrun" element={<DryRunPage />} />
              <Route path="/config" element={<Config />} />
              <Route path="/networks" element={<Networks />} />
              <Route path="/settings" element={<Settings />} />
              <Route
                path="*"
                element={<div className="pad muted">Page not found</div>}
              />
            </Routes>
          </Suspense>
        </ErrorBoundary>
      </main>
    </div>
  );
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
