import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useDevices, useLogs } from "../api";
import { ErrorNote, Loading, LogList, deviceNames } from "../components/common";

export function Logs() {
  const [params, setParams] = useSearchParams();
  const device = params.get("device") ?? "";
  const q = params.get("q") ?? "";
  const [text, setText] = useState(q);
  const devices = useDevices();
  const names = deviceNames(devices.data);
  const logs = useLogs({
    device: device || undefined,
    q: q || undefined,
    limit: 1000,
  });

  // Search as you type, debounced.
  useEffect(() => {
    const t = window.setTimeout(() => {
      if (text !== q) {
        const next = new URLSearchParams(params);
        if (text) next.set("q", text);
        else next.delete("q");
        setParams(next, { replace: true });
      }
    }, 300);
    return () => window.clearTimeout(t);
  }, [text, q, params, setParams]);

  const setDevice = (mac: string) => {
    const next = new URLSearchParams(params);
    if (mac) next.set("device", mac);
    else next.delete("device");
    setParams(next, { replace: true });
  };

  return (
    <div className="page">
      <div className="page-head">
        <h1>Logs</h1>
        <span className="muted">
          {logs.data ? `${logs.data.length} lines` : ""}
        </span>
        <span className="spacer" />
        <select
          value={device}
          onChange={(e) => setDevice(e.target.value)}
          aria-label="Access point"
        >
          <option value="">All APs</option>
          {(devices.data ?? []).map((d) => (
            <option key={d.mac} value={d.mac}>
              {d.name ?? d.mac}
            </option>
          ))}
        </select>
        <input
          className="search"
          placeholder="Search log text (all words must match)"
          value={text}
          onChange={(e) => setText(e.target.value)}
        />
      </div>
      <div className="panel">
        {logs.error ? (
          <ErrorNote error={logs.error} />
        ) : logs.data ? (
          <LogList logs={logs.data} names={names} />
        ) : (
          <Loading />
        )}
      </div>
    </div>
  );
}
