import { useState } from "react";
import { wlanPassphrase } from "../../../api";
import type { WlanSettings } from "../../../api";
import { Row, Select, Toggle } from "../form";
import { PROTECTION } from "./form";
import type { Protection, WlanSection } from "./form";
import { SpeedLimitRow } from "./SpeedLimitRow";

/** The stored passphrase, fetched when asked for. */
function ShowPassphrase({ id }: { id: string }) {
  const [shown, setShown] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  if (shown !== null) return <span className="mono small">{shown}</span>;
  return (
    <>
      <button
        className="btn small"
        onClick={() => {
          setError(null);
          wlanPassphrase(id)
            .then((r) => setShown(r.passphrase ?? ""))
            .catch((e: unknown) =>
              setError(e instanceof Error ? e.message : String(e)),
            );
        }}
      >
        Show current
      </button>
      {error && <span className="error small">{error}</span>}
    </>
  );
}

/** Name, security, bands, which APs, network and speed limit. */
export function Basics({
  w,
  list,
  wlan,
  password,
  setPassword,
  setProtection,
}: WlanSection & {
  wlan: WlanSettings | null;
  password: string;
  setPassword: (v: string) => void;
  setProtection: (v: Protection) => void;
}) {
  const { form: f, set, bind } = w;
  const bands = f.wlan_bands ?? [];
  const toggleBand = (b: string, on: boolean) =>
    set("wlan_bands", on ? [...bands, b] : bands.filter((x) => x !== b));
  const aps = f.aps;
  const iot = f.enhanced_iot === true;
  return (
    <>
      <Row label="Name (SSID)">
        <input
          className="search"
          maxLength={32}
          value={f.name ?? ""}
          onChange={(e) => set("name", e.target.value)}
        />
      </Row>
      <Row label="Status">
        <Toggle {...bind("enabled")} label="Enabled" />
        <Toggle
          {...bind("hide_ssid")}
          label="Hidden (not in the network list)"
        />
      </Row>
      <Row label="Security">
        <Select
          value={f.protection ?? ""}
          onChange={(v) => setProtection(v || null)}
          options={[
            // Shown, not chosen: the SSID's security is one this editor doesn't offer.
            ...(f.protection === null
              ? [["", "(other, set elsewhere)", true] as const]
              : []),
            ...PROTECTION.map(
              ([v, l]) => [v, l, iot && v !== "wpa2" && v !== "open"] as const,
            ),
          ]}
        />
      </Row>
      {f.protection !== "open" && (
        <Row
          label="Password"
          hint={wlan ? "leave empty to keep it" : "8 to 63 characters"}
        >
          <input
            className="search"
            type="text"
            autoComplete="off"
            placeholder={wlan?.has_passphrase ? "unchanged" : ""}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
          {wlan?.has_passphrase && <ShowPassphrase id={wlan.id} />}
        </Row>
      )}
      <Row label="Bands">
        <Toggle
          value={bands.includes("2g")}
          onChange={(v) => toggleBand("2g", v)}
          disabled={iot}
          label="2.4 GHz"
        />
        <Toggle
          value={bands.includes("5g")}
          onChange={(v) => toggleBand("5g", v)}
          disabled={iot}
          label="5 GHz"
        />
        {iot && (
          <span className="muted small">Force Wi-Fi 4 is on: 2.4 GHz only</span>
        )}
      </Row>
      <Row label="Broadcast from">
        <Toggle
          value={aps === null}
          onChange={(v) => set("aps", v ? null : list.aps.map((a) => a.mac))}
          label="All APs"
        />
        {aps !== null &&
          list.aps.map((a) => (
            <Toggle
              key={a.mac}
              value={aps.includes(a.mac)}
              onChange={(v) =>
                set("aps", v ? [...aps, a.mac] : aps.filter((m) => m !== a.mac))
              }
              label={a.name ?? a.mac}
            />
          ))}
      </Row>
      {list.networks.length > 1 && (
        <Row label="Network">
          <Select
            {...bind("networkconf_id")}
            fallback=""
            options={list.networks.map(
              (n) =>
                [
                  n.id,
                  `${n.name}${n.vlan ? ` (VLAN ${n.vlan})` : ""}`,
                ] as const,
            )}
          />
        </Row>
      )}
      <SpeedLimitRow {...bind("usergroup_id")} />
    </>
  );
}
