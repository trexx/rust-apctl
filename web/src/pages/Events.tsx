import { useState } from "react";
import { useClients, useDevices, useEvents } from "../api";
import { ErrorNote, EventList, Loading, clientNames, deviceNames } from "../components/common";

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
  const [kind, setKind] = useState("");
  const [device, setDevice] = useState("");
  const devices = useDevices();
  const names = deviceNames(devices.data);
  const cnames = clientNames(useClients().data);
  const events = useEvents({ kind: kind || undefined, device: device || undefined, limit: 500 });

  return (
    <div className="page">
      <div className="page-head">
        <h1>Events</h1>
        <span className="spacer" />
        <select value={device} onChange={(e) => setDevice(e.target.value)} aria-label="Access point">
          <option value="">All APs</option>
          {(devices.data ?? []).map((d) => (
            <option key={d.mac} value={d.mac}>
              {d.name ?? d.mac}
            </option>
          ))}
        </select>
        <div className="segmented" role="group" aria-label="Event type">
          {KINDS.map((k) => (
            <button key={k.value} className={kind === k.value ? "active" : ""} onClick={() => setKind(k.value)}>
              {k.label}
            </button>
          ))}
        </div>
      </div>
      <div className="panel">
        {events.error ? <ErrorNote error={events.error} /> : events.data ? <EventList events={events.data} names={names} clientNames={cnames} /> : <Loading />}
      </div>
    </div>
  );
}
