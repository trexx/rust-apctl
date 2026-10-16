import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useDevices, useLogs } from "../api";
import {
  ApSelect,
  LogList,
  QueryState,
  deviceNames,
} from "../components/common";

export function Logs() {
  const [params, setParams] = useSearchParams();
  const device = params.get("device") ?? "";
  const q = params.get("q") ?? "";
  const [text, setText] = useState(q);
  // When the URL's search changes from outside (the Logs link, Back), show it.
  const [shown, setShown] = useState(q);
  if (q !== shown) {
    setShown(q);
    setText(q);
  }
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
        <ApSelect value={device} onChange={setDevice} />
        <input
          className="search"
          placeholder="Search log text (all words must match)"
          value={text}
          onChange={(e) => setText(e.target.value)}
        />
      </div>
      <div className="panel">
        <QueryState q={logs}>
          {(data) => <LogList logs={data} names={names} />}
        </QueryState>
      </div>
    </div>
  );
}
