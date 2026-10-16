import { useSearchParams } from "react-router-dom";
import { useClientNames, useDeviceNames, useEvents } from "../api";
import {
  ApSelect,
  EventList,
  QueryState,
  Segmented,
  useSetParams,
} from "../components/common";

const KINDS = [
  ["", "All events"],
  ["client", "Clients"],
  ["client_roamed", "Roams"],
  ["client_disconnected", "Disconnects"],
  ["ap", "Access points"],
  ["radio", "Radio changes"],
  ["config", "Config pushes"],
] as const;

export function Events() {
  // Filters live in the URL (`?kind=&device=`), as on the Logs page.
  const [params] = useSearchParams();
  const kind = params.get("kind") ?? "";
  const device = params.get("device") ?? "";
  const setUrl = useSetParams();
  const set = (key: string, value: string) =>
    setUrl({ [key]: value }, { replace: true });
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
        <Segmented
          label="Event type"
          options={KINDS}
          value={kind}
          onChange={(k) => set("kind", k)}
        />
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
