import { useState } from "react";
import { wlanPassphrase } from "../../../api";
import type { WlanSettings } from "../../../api";
import { errorText } from "../../common";
import { ApChecklist, Row, Select, TextInput, Toggle, toggled } from "../form";
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
            .catch((e: unknown) => setError(errorText(e)));
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
    set("wlan_bands", toggled(bands, b, on));
  const aps = f.aps;
  const iot = f.enhanced_iot === true;
  // The networks the server lets an SSID go on, as the official UI offers
  // them: not a WAN or VPN one (a gateway's settings have those).
  const networks = list.networks.filter((n) => n.for_ssid);
  const network = f.networkconf_id;
  const strayNetwork = !!network && !networks.some((n) => n.id === network);
  return (
    <>
      <Row label="Name (SSID)">
        <TextInput {...bind("name")} maxLength={32} />
      </Row>
      <Row label="Status">
        {/* Unset is on, as the APs are told. */}
        <Toggle
          {...bind("enabled")}
          value={f.enabled !== false}
          label="Enabled"
        />
        <Toggle
          {...bind("hide_ssid")}
          label="Hidden (not in the network list)"
        />
      </Row>
      <Row label="Security">
        <Select
          value={f.protection}
          onChange={setProtection}
          // Shown, not chosen: the SSID's security is one this editor doesn't offer.
          stray={() => "(other, set elsewhere)"}
          options={PROTECTION.map(
            ([v, l]) => [v, l, iot && v !== "wpa2" && v !== "open"] as const,
          )}
        />
      </Row>
      {f.protection !== "open" && (
        <Row
          label="Password"
          hint={
            wlan
              ? "leave empty to keep it"
              : // WPA3 alone takes longer passwords; WPA2 (also in transition) stops at 63.
                `8 to ${f.protection === "wpa3" ? 255 : 63} characters`
          }
        >
          <TextInput
            autoComplete="off"
            placeholder={wlan?.has_passphrase ? "unchanged" : ""}
            value={password}
            onChange={setPassword}
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
        {aps !== null && (
          <ApChecklist
            aps={list.aps}
            value={aps}
            onChange={(v) => set("aps", v)}
          />
        )}
      </Row>
      {(networks.length > 1 || strayNetwork) && (
        <Row label="Network">
          <Select
            {...bind("networkconf_id")}
            // A new SSID goes on the server's default network.
            stray={(v) => {
              const name = list.networks.find((n) => n.id === v)?.name;
              if (name) return `${name} (not for SSIDs)`;
              return v ? "(unknown network)" : "(the default network)";
            }}
            options={networks.map(
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
