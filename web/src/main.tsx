import { Component, StrictMode } from "react";
import type { ReactNode } from "react";
import { createRoot } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, NavLink, Route, Routes, useLocation } from "react-router-dom";
import { useLiveUpdates, useStatus } from "./api";
import { Overview } from "./pages/Overview";
import { Device } from "./pages/Device";
import { Clients } from "./pages/Clients";
import { Client } from "./pages/Client";
import { Events } from "./pages/Events";
import { Logs } from "./pages/Logs";
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

function Shell() {
  useLiveUpdates();
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
        </nav>
        <span className="spacer" />
        {status.data && (
          <span className="mode" title={status.data.source}>
            {status.data.mode} mode
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
        <Shell />
      </BrowserRouter>
    </QueryClientProvider>
  </StrictMode>,
);
