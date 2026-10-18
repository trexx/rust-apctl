import { useEffect, useEffectEvent, useState } from "react";
import { useSearchParams } from "react-router";
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
  // The search this page last put in the URL. The router commits it in a
  // transition, so more may have been typed by the time it lands: then the box
  // keeps what was typed.
  const [sent, setSent] = useState<string | null>(null);
  // When the URL's search changes from outside (the Logs link, Back), show it.
  const [shown, setShown] = useState(q);
  if (q !== shown) {
    setShown(q);
    if (q === sent) setSent(null);
    else setText(q);
  }
  const names = useDeviceNames();
  const logs = useLogs({
    device: device || undefined,
    q: q || undefined,
    limit: 1000,
  });

  // Search as you type, debounced.
  const search = useEffectEvent((t: string) => {
    setSent(t);
    setUrl({ q: t }, { replace: true });
  });
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
          aria-label="Search log text"
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
