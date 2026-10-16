import { useEffect, useEffectEvent, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { useDeviceNames, useLogs } from "../api";
import {
  ApSelect,
  LogList,
  QueryState,
  useSetParams,
} from "../components/common";

export function Logs() {
  const [params] = useSearchParams();
  const setUrl = useSetParams();
  const device = params.get("device") ?? "";
  const q = params.get("q") ?? "";
  const [text, setText] = useState(q);
  // When the URL's search changes from outside (the Logs link, Back), show it.
  const [shown, setShown] = useState(q);
  if (q !== shown) {
    setShown(q);
    setText(q);
  }
  const names = useDeviceNames();
  const logs = useLogs({
    device: device || undefined,
    q: q || undefined,
    limit: 1000,
  });

  // Search as you type, debounced.
  const search = useEffectEvent((t: string) =>
    setUrl({ q: t }, { replace: true }),
  );
  useEffect(() => {
    if (text === q) return;
    const t = window.setTimeout(() => search(text), 300);
    return () => window.clearTimeout(t);
  }, [text, q]);

  const setDevice = (mac: string) => setUrl({ device: mac }, { replace: true });

  return (
    <div className="page">
      <div className="page-head">
        <h1>Logs</h1>
        <span className="muted">
          {logs.data && !logs.isPlaceholderData
            ? `${logs.data.length} lines`
            : ""}
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
      <div className={logs.isPlaceholderData ? "panel dim" : "panel"}>
        <QueryState q={logs}>
          {(data) => <LogList logs={data} names={names} />}
        </QueryState>
      </div>
    </div>
  );
}
