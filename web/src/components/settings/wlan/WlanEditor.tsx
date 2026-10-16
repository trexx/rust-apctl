import { useState } from "react";
import type { WlanSettings, WlanSettingsList } from "../../../api";
import { useSettingsForm } from "../form";
import type { Fields } from "../form";
import { EditorShell } from "../Review";
import { wlanForm } from "./form";
import type { Protection } from "./form";
import { Advanced } from "./Advanced";
import { Basics } from "./Basics";
import { Iot } from "./Iot";
import { Mdns } from "./Mdns";
import { Multicast } from "./Multicast";
import { Roaming } from "./Roaming";
import { ScheduleEditor } from "./Schedule";

/** An SSID's editor, or a new SSID's when `wlan` is null. */
export function WlanEditor({
  wlan,
  list,
  onClose,
}: {
  wlan: WlanSettings | null;
  list: WlanSettingsList;
  onClose: () => void;
}) {
  const w = useSettingsForm(() => wlanForm(wlan));
  const { form, setForm, bind } = w;
  const [password, setPassword] = useState("");
  const setProtection = (p: Protection) =>
    setForm((x) => ({ ...x, protection: p, pmf_mode: undefined }));
  /** Force Wi-Fi 4 clears what it can't be combined with, as the official UI does. */
  const setIot = (on: boolean) =>
    setForm((x) => ({
      ...x,
      enhanced_iot: on,
      ...(on && {
        wlan_bands: ["2g"],
        protection: x.protection === "open" ? "open" : "wpa2",
        pmf_mode: undefined,
        fast_roaming_enabled: false,
        wpa3_fast_roaming: false,
        bss_transition: false,
        proxy_arp: false,
        no2ghz_oui: false,
        group_rekey: 0,
        dtim_mode: "default",
        advertise_device_name_in_beacon: false,
        dns_assistance_mode: "off",
        roaming_assistant_na_enabled: false,
      }),
    }));
  const patch: Fields = wlan ? w.changes() : { ...form };
  if (password) patch.passphrase = password;
  const section = { w, list };
  return (
    <EditorShell
      target={{ kind: "wlan", id: wlan?.id ?? null }}
      active={list.active}
      patch={patch}
      onClose={onClose}
    >
      <Basics
        {...section}
        wlan={wlan}
        password={password}
        setPassword={setPassword}
        setProtection={setProtection}
      />
      <ScheduleEditor {...bind("schedule_with_duration")} />
      <Roaming {...section} />
      <Iot w={w} setIot={setIot} />
      <Mdns {...section} />
      <Multicast {...section} />
      <Advanced {...section} />
    </EditorShell>
  );
}
