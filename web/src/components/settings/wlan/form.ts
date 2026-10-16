import type {
  Mac,
  MdnsRule,
  WlanSettings,
  WlanSettingsList,
} from "../../../api";
import type { Option, SettingsForm } from "../form";

/** A time the SSID is off: from a start on some days, for a while. */
export interface Blackout {
  start_days_of_week: string[];
  start_hour: number;
  start_minute: number;
  duration_minutes: number;
  name?: string;
}

export type Protection = WlanSettings["protection"];
export type PmfMode = "disabled" | "optional" | "required";

/**
 * The editable fields of an SSID, as the form holds them. The server sends
 * more than these; they ride along unchanged.
 */
export type WlanForm = {
  name: string;
  enabled?: boolean | null;
  hide_ssid?: boolean | null;
  protection: Protection;
  /** Unset: the server derives it from the protection. */
  pmf_mode?: PmfMode | null;
  wlan_bands?: string[] | null;
  /** null: broadcast from every AP. */
  aps: Mac[] | null;
  networkconf_id?: string | null;
  usergroup_id?: string | null;
  schedule_with_duration?: Blackout[] | null;

  fast_roaming_enabled?: boolean | null;
  wpa3_fast_roaming?: boolean | null;
  rrm_enabled?: boolean | null;
  bss_transition?: boolean | null;
  roaming_assistant_na_enabled?: boolean | null;
  roaming_assistant_na_rssi?: number | null;
  no2ghz_oui?: boolean | null;

  enhanced_iot?: boolean | null;
  iot_channel_lock?: boolean | null;
  iot_dtim_lock?: boolean | null;

  mdns_proxy_mode?: "off" | "auto" | "custom" | null;
  mdns_proxy_custom?: MdnsRule[] | null;

  mcastenhance_enabled?: boolean | null;
  multicast_suppressor_mode?: "off" | "conservative" | "aggressive" | null;
  bc_filter_list?: string[] | null;
  proxy_arp?: boolean | null;

  dns_assistance_mode?: "off" | "auto" | "manual" | null;
  dns_assistance_servers?: string[] | null;
  advertise_device_name_in_beacon?: boolean | null;
  l2_isolation?: boolean | null;
  is_guest?: boolean | null;
  uapsd_enabled?: boolean | null;
  country_beacon?: boolean | null;
  minrate_setting_preference?: "auto" | "manual" | null;
  minrate_ng_data_rate_kbps?: number | null;
  minrate_na_enabled?: boolean | null;
  minrate_na_data_rate_kbps?: number | null;
  dtim_mode?: "default" | "custom" | null;
  dtim_ng?: number | null;
  dtim_na?: number | null;
  group_rekey?: number | null;
  sae_anti_clogging?: number | null;
  sae_sync?: number | null;
  tdls_prohibit?: boolean | null;
  p2p?: boolean | null;
  p2p_cross_connect?: boolean | null;
  log_level?: number | null;
  mac_filter_enabled?: boolean | null;
  mac_filter_policy?: "allow" | "deny" | null;
  mac_filter_list?: string[] | null;
};

/** The form's fields for an SSID, or a new one's when `w` is null. */
export function wlanForm(w: WlanSettings | null): WlanForm {
  if (!w)
    return {
      name: "",
      enabled: true,
      protection: "wpa2_wpa3",
      wlan_bands: ["2g", "5g"],
      aps: null,
    };
  const { id: _id, editable: _e, has_passphrase: _h, ...rest } = w;
  return rest as WlanForm;
}

/** What each section of the SSID editor gets. */
export interface WlanSection {
  w: SettingsForm<WlanForm>;
  list: WlanSettingsList;
}

export const PROTECTION: Option<NonNullable<Protection>>[] = [
  ["wpa2_wpa3", "WPA2/WPA3 Personal"],
  ["wpa2", "WPA2 Personal"],
  ["wpa3", "WPA3 Personal"],
  ["open", "Open (no password)"],
];

/** The SSID's bands (`2g`, `5g`, `6g`) as radio names, for `band()`. */
export const BAND_RADIO: Record<string, string> = {
  "2g": "ng",
  "5g": "na",
  "6g": "6e",
};
