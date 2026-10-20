import type { WlanFields, WlanSettings, WlanSettingsList } from "../../../api";
import type { Option, SettingsForm } from "../form";

export type Protection = WlanSettings["protection"];
export type PmfMode = NonNullable<WlanFields["pmf_mode"]>;

/** An SSID's fields as the form holds them (all of them: those it doesn't edit ride along unchanged). */
export type WlanForm = WlanFields;

/**
 * The form's fields for an SSID, or a new one's when `w` is null: with the
 * values the server creates it with where a control's own fallback differs
 * (create_wlan), so the form shows and sends what will be created.
 */
export function wlanForm(w: WlanSettings | null): WlanForm {
  if (!w)
    return {
      name: "",
      enabled: true,
      protection: "wpa2_wpa3",
      wlan_bands: ["2g", "5g"],
      aps: null,
      bss_transition: true,
      no2ghz_oui: true,
      group_rekey: 0,
    };
  const { id: _id, editable: _e, has_passphrase: _h, ...rest } = w;
  return rest;
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
