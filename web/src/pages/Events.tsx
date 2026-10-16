import { useSearchParams } from "react-router-dom";
import { useClientNames, useDeviceNames, useEvents } from "../api";
import { ApSelect, EventList, QueryState } from "../components/common";

const KINDS: { value: string; label: string }[] = [
  { value: "", label: "All events" },
  { value: "client", label: "Clients" },
  { value: "client_roamed", label: "Roams" },
  { value: "client_disconnected", label: "Disconnects" },
  { value: "ap", label: "Access points" },
  { value: "radio", label: "Radio changes" },
  { value: "config", label: "Config pushes" },
];

export function Events() {
  // Filters live in the URL (`?kind=&device=`), as on the Logs page.
  const [params, setParams] = useSearchParams();
  const kind = params.get("kind") ?? "";
  const device = params.get("device") ?? "";
  const set = (key: string, value: string) =>
    setParams(
      (prev) => {
        const next = new URLSearchParams(prev);
        if (value) next.set(key, value);
        else next.delete(key);
        return next;
      },
      { replace: true },
    );
  const names = useDeviceNames();
  const cnames = useClientNames();
  const events = useEvents({
    kind: kind || undefined,
    device: device || undefined,
    limit: 500,
  });

  return (
    <div className="page">
      <div className="page-head">
        <h1>Events</h1>
        <span className="spacer" />
        <ApSelect value={device} onChange={(mac) => set("device", mac)} />
        <div className="segmented" role="group" aria-label="Event type">
          {KINDS.map((k) => (
            <button
              key={k.value}
              className={kind === k.value ? "active" : ""}
              onClick={() => set("kind", k.value)}
            >
              {k.label}
            </button>
          ))}
        </div>
      </div>
      <div className="panel">
        <QueryState q={events}>
          {(data) => (
            <EventList events={data} names={names} clientNames={cnames} />
          )}
        </QueryState>
      </div>
    </div>
  );
}
