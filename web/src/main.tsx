import { Component, StrictMode } from "react";
import type { ReactNode } from "react";
import { createRoot } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, NavLink, Route, Routes, useLocation } from "react-router-dom";
import { useEffect, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { login, logout, useLiveUpdates, useMe, useStatus } from "./api";
import { Overview } from "./pages/Overview";
import { Device } from "./pages/Device";
import { Clients } from "./pages/Clients";
import { Client } from "./pages/Client";
import { Events } from "./pages/Events";
import { Logs } from "./pages/Logs";
import { DryRunPage } from "./pages/DryRun";
import { Settings } from "./pages/Settings";
import "./styles.css";

const queryClient = new QueryClient({
  defaultOptions: { queries: { staleTime: 5_000, refetchOnWindowFocus: true } },
});

/** Shows a failing page's error instead of unmounting the whole app. */
class ErrorBoundary extends Component<{ children: ReactNode; resetKey: string }, { error: Error | null }> {
  state = { error: null as Error | null };
  static getDerivedStateFromError(error: Error) {
    return { error };
  }
  componentDidUpdate(prev: { resetKey: string }) {
    if (prev.resetKey !== this.props.resetKey && this.state.error) this.setState({ error: null });
  }
  render() {
    if (this.state.error) return <div className="error pad">This page failed to render: {this.state.error.message}</div>;
    return this.props.children;
  }
}

function Login() {
  const qc = useQueryClient();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  return (
    <div className="login">
      <form
        className="panel login-box"
        onSubmit={async (e) => {
          e.preventDefault();
          setBusy(true);
          setError(null);
          try {
            await login(username, password);
            await qc.invalidateQueries();
          } catch (err) {
            setError(err instanceof Error ? err.message : String(err));
          } finally {
            setBusy(false);
          }
        }}
      >
        <div className="brand">apctl</div>
        <label>
          Username
          <input className="search" autoFocus autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} />
        </label>
        <label>
          Password
          <input className="search" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} />
        </label>
        {error && <div className="error small">{error}</div>}
        <button className="btn primary" type="submit" disabled={busy || !username || !password}>
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
    const onUnauthorized = () => void qc.invalidateQueries({ queryKey: ["me"] });
    window.addEventListener("apctl:unauthorized", onUnauthorized);
    return () => window.removeEventListener("apctl:unauthorized", onUnauthorized);
  }, [qc]);
  if (me.isLoading) return null;
  if (me.data && me.data.auth && !me.data.user) return <Login />;
  return <Shell user={me.data?.user ?? null} readOnly={me.data?.read_only ?? false} />;
}

function Shell({ user, readOnly }: { user: string | null; readOnly: boolean }) {
  useLiveUpdates();
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
          <NavLink to="/events">Events</NavLink>
          <NavLink to="/logs">Logs</NavLink>
          <NavLink to="/dryrun">Dry run</NavLink>
          <NavLink to="/settings">Settings</NavLink>
        </nav>
        <span className="spacer" />
        {status.data && (
          <span className="mode" title={status.data.source}>
            {status.data.mode} mode
          </span>
        )}
        {readOnly && (
          <span className="mode" title="No users are configured, so changes are disabled">
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
                qc.setQueryData(["me"], { auth: true, user: null });
                qc.removeQueries({ predicate: (q) => q.queryKey[0] !== "me" });
              }}
            >
              Sign out
            </button>
          </span>
        )}
      </header>
      <main>
        <ErrorBoundary resetKey={location.pathname}>
        <Routes>
          <Route path="/" element={<Overview />} />
          <Route path="/devices/:mac" element={<Device />} />
          <Route path="/clients" element={<Clients />} />
          <Route path="/clients/:mac" element={<Client />} />
          <Route path="/events" element={<Events />} />
          <Route path="/logs" element={<Logs />} />
          <Route path="/dryrun" element={<DryRunPage />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="*" element={<div className="pad muted">Page not found</div>} />
        </Routes>
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
