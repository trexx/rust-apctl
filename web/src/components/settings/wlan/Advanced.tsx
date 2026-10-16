import {
  ListInput,
  NumberInput,
  Row,
  Select,
  Toggle,
  onePerLine,
  words,
} from "../form";
import type { Option } from "../form";
import type { PmfMode, WlanSection } from "./form";
import { Unsupported } from "./Unsupported";

const RATES_NG = [
  1000, 2000, 5500, 6000, 9000, 11000, 12000, 18000, 24000, 36000, 48000, 54000,
];
const RATES_NA = [6000, 9000, 12000, 18000, 24000, 36000, 48000, 54000];
const rates = (list: number[]): Option<number>[] =>
  list.map((kbps) => [kbps, `${kbps / 1000} Mbps`]);

const LOG_LEVELS: Option<number>[] = [
  [-1, "AP default"],
  [0, "0 (verbose debug)"],
  [1, "1 (debug)"],
  [2, "2 (info)"],
  [3, "3 (notice)"],
  [4, "4 (warning)"],
];

export function Advanced({ w, list }: WlanSection) {
  const { form: f, set, bind } = w;
  const iot = f.enhanced_iot === true;
  const wpa3 = f.protection === "wpa3" || f.protection === "wpa2_wpa3";
  const pmf: Option<PmfMode | "">[] = [
    ["disabled", "Disabled"],
    ["optional", "Optional"],
    ["required", "Required"],
  ];
  return (
    <details>
      <summary>Advanced</summary>
      <Row
        label="DNS Assistance"
        hint="the APs cache DNS and fall back to other servers when the network's is slow or fails"
      >
        <Select
          {...bind("dns_assistance_mode")}
          fallback="off"
          disabled={iot}
          options={[
            ["off", "Off"],
            ["auto", "Automatic fallback servers"],
            ["manual", "These fallback servers"],
          ]}
        />
        {f.dns_assistance_mode === "manual" && (
          <ListInput
            {...bind("dns_assistance_servers")}
            placeholder="e.g. 192.168.1.1, 9.9.9.9"
            parse={words}
            format={(v) => v.join(", ")}
          />
        )}
        <Unsupported
          feature="dns_assistance"
          on={(f.dns_assistance_mode ?? "off") !== "off"}
          aps={f.aps}
          list={list}
        />
      </Row>
      <Row
        label="AP name in beacons"
        hint="clients can see which AP they're on"
      >
        <Toggle
          {...bind("advertise_device_name_in_beacon")}
          disabled={iot}
          label="Enabled"
        />
        <Unsupported
          feature="advertise_ap_name"
          on={f.advertise_device_name_in_beacon === true}
          aps={f.aps}
          list={list}
        />
      </Row>
      <Row label="Protected management frames">
        <Select
          value={f.pmf_mode ?? ""}
          disabled={iot}
          onChange={(v) => set("pmf_mode", v || undefined)}
          options={[["", "(from the security choice)"], ...pmf]}
        />
      </Row>
      <Row label="Client isolation" hint="clients can't reach each other">
        <Toggle {...bind("l2_isolation")} label="Enabled" />
      </Row>
      <Row label="Guest network">
        <Toggle {...bind("is_guest")} label="Guest" />
      </Row>
      <Row label="U-APSD" hint="power saving for phones">
        <Toggle {...bind("uapsd_enabled")} label="Enabled" />
      </Row>
      <Row label="Beacon country" hint="802.11d">
        <Toggle {...bind("country_beacon")} label="Enabled" />
      </Row>
      <Row label="Minimum data rates">
        <Select
          {...bind("minrate_setting_preference")}
          fallback="auto"
          options={[
            ["auto", "Automatic"],
            ["manual", "Manual"],
          ]}
        />
        {f.minrate_setting_preference === "manual" && (
          <>
            <label className="small">
              2.4 GHz{" "}
              <Select
                {...bind("minrate_ng_data_rate_kbps")}
                fallback={1000}
                options={rates(RATES_NG)}
              />
            </label>
            <Toggle {...bind("minrate_na_enabled")} label="5 GHz" />
            {f.minrate_na_enabled === true && (
              <Select
                {...bind("minrate_na_data_rate_kbps")}
                fallback={6000}
                options={rates(RATES_NA)}
              />
            )}
          </>
        )}
      </Row>
      <Row label="DTIM period">
        <Select
          {...bind("dtim_mode")}
          fallback="default"
          disabled={iot}
          options={[
            ["default", "Default (2.4 GHz 1, 5 GHz 3)"],
            ["custom", "Custom"],
          ]}
        />
        {f.dtim_mode === "custom" &&
          (
            [
              ["dtim_ng", "2.4 GHz"],
              ["dtim_na", "5 GHz"],
            ] as const
          ).map(([k, l]) => (
            <label key={k} className="small">
              {l}{" "}
              <NumberInput
                {...bind(k)}
                fallback={1}
                min={1}
                max={255}
                disabled={k === "dtim_ng" && f.iot_dtim_lock === true}
              />
            </label>
          ))}
      </Row>
      <Row label="Group rekey" hint="seconds; 0 is off">
        <NumberInput
          {...bind("group_rekey")}
          fallback={0}
          min={0}
          max={86400}
          disabled={iot}
        />
      </Row>
      {wpa3 && (
        <Row
          label="SAE timers"
          hint="WPA3, seconds; changing them is rarely needed"
        >
          {(
            [
              ["sae_anti_clogging", "anti-clogging"],
              ["sae_sync", "sync"],
            ] as const
          ).map(([k, l]) => (
            <label key={k} className="small">
              {l} <NumberInput {...bind(k)} fallback={5} min={1} max={60} />
            </label>
          ))}
        </Row>
      )}
      <Row label="Client-to-client links" hint="not in the official UI">
        <Toggle {...bind("tdls_prohibit")} label="Prohibit TDLS" />
        <Toggle {...bind("p2p")} label="Wi-Fi Direct (P2P)" />
        {f.p2p === true && (
          <Toggle {...bind("p2p_cross_connect")} label="P2P cross-connect" />
        )}
      </Row>
      <Row
        label="hostapd log level"
        hint="for debugging; not in the official UI"
      >
        <Select {...bind("log_level")} fallback={-1} options={LOG_LEVELS} />
      </Row>
      <Row label="MAC address filter">
        <Toggle {...bind("mac_filter_enabled")} label="Enabled" />
        {f.mac_filter_enabled === true && (
          <Select
            {...bind("mac_filter_policy")}
            fallback="allow"
            options={[
              ["allow", "Only these may join"],
              ["deny", "These may not join"],
            ]}
          />
        )}
      </Row>
      {f.mac_filter_enabled === true && (
        <Row label="Filtered addresses" hint="MAC addresses, one per line">
          <ListInput
            {...bind("mac_filter_list")}
            rows={5}
            parse={words}
            format={onePerLine}
          />
        </Row>
      )}
    </details>
  );
}
