import { useState } from "react";
import type { ConfigNetwork, DeviceSettings } from "../../../api";
import { band } from "../../../format";
import {
  Row,
  Select,
  TextInput,
  Toggle,
  changed,
  useSettingsForm,
} from "../form";
import type { Fields } from "../form";
import { EditorShell } from "../Review";
import { AddressFields } from "./AddressFields";
import { RadioFields, keepAllowed, radioForm } from "./RadioFields";

type NonNull<T, K extends keyof T> = NonNullable<T[K]>;

/** An AP's own editable fields, as the form holds them. */
type DeviceForm = {
  name: string;
  led_override: NonNull<DeviceSettings, "led_override">;
  led_override_color: string;
  led_override_color_brightness: number;
  outdoor_mode_override: NonNull<DeviceSettings, "outdoor_mode_override">;
  bandsteering_mode: NonNull<DeviceSettings, "bandsteering_mode">;
  atf_enabled: boolean;
  green_ap_enabled: boolean;
  resetbtn_enabled: NonNull<DeviceSettings, "resetbtn_enabled">;
  jumboframe_enabled: boolean;
  config_network: ConfigNetwork;
  snmp_location: string;
  snmp_contact: string;
  antenna_id: number;
};

function deviceForm(d: DeviceSettings): DeviceForm {
  return {
    name: d.name ?? "",
    led_override: d.led_override ?? "default",
    led_override_color: d.led_override_color ?? "#0000ff",
    led_override_color_brightness: d.led_override_color_brightness ?? 100,
    outdoor_mode_override: d.outdoor_mode_override ?? "default",
    bandsteering_mode: d.bandsteering_mode ?? "off",
    atf_enabled: d.atf_enabled ?? false,
    green_ap_enabled: d.green_ap_enabled ?? false,
    resetbtn_enabled: d.resetbtn_enabled ?? "on",
    jumboframe_enabled: d.jumboframe_enabled ?? false,
    config_network: d.config_network ?? { type: "dhcp" },
    snmp_location: d.snmp_location ?? "",
    snmp_contact: d.snmp_contact ?? "",
    antenna_id:
      d.radios.find((r) => r.antenna_id !== null && r.antenna_id >= 0)
        ?.antenna_id ??
      d.antennas.find((a) => a.default)?.id ??
      -1,
  };
}

export function DeviceEditor({
  d: live,
  onClose,
}: {
  d: DeviceSettings;
  onClose: () => void;
}) {
  // The AP as the editor opened: its radios and the form's baseline stay put
  // while the settings refetch in the background.
  const [d] = useState(live);
  const { form, set, bind, changes } = useSettingsForm(() => deviceForm(d));
  const [radios0] = useState(() => d.radios.map(radioForm));
  const [radios, setRadios] = useState(radios0);
  const has = (f: string) => d.features.includes(f);
  const optional: [string, string][] = [
    ["band_steering", "band steering"],
    ["airtime_fairness", "airtime fairness"],
    ["green_ap", "Green AP"],
    ["led_color", "LED colour"],
  ];
  const missing = optional.filter(([f]) => !has(f));
  const isOutdoor = (o: DeviceForm["outdoor_mode_override"]) =>
    o === "on" || (o === "default" && d.site_outdoor);
  const outdoor = isOutdoor(form.outdoor_mode_override);
  /** Outdoor mode changes which channels are allowed: a fixed one that no longer is falls back to auto. */
  const setOutdoor = (o: DeviceForm["outdoor_mode_override"]) => {
    set("outdoor_mode_override", o);
    setRadios((all) =>
      all.map((x, i) => {
        const r = d.radios[i];
        return r ? keepAllowed(r, x, isOutdoor(o)) : x;
      }),
    );
  };
  const patch: Fields = changes();
  const r = d.radios
    .map((x, i) => {
      const before = radios0[i];
      const after = radios[i];
      const c = before && after ? changed(before, after) : {};
      // As in the official UI, the power goes only with custom power: the AP
      // reads it in any mode.
      if (after?.tx_power_mode !== "custom") delete c.tx_power;
      return Object.keys(c).length ? { radio: x.radio, ...c } : null;
    })
    .filter(Boolean);
  if (r.length) patch.radios = r;
  return (
    <EditorShell
      target={{ kind: "device", mac: d.mac }}
      active={live.active}
      patch={patch}
      onClose={onClose}
    >
      <Row label="Name">
        <TextInput {...bind("name")} maxLength={128} />
      </Row>
      <Row label="LED">
        <Select
          {...bind("led_override")}
          options={[
            ["default", "Site default"],
            ["on", "On"],
            ["off", "Off"],
          ]}
        />
        {has("led") && form.led_override !== "off" && (
          <label className="small">
            brightness{" "}
            <input
              type="range"
              aria-label="LED brightness"
              min={1}
              max={100}
              value={form.led_override_color_brightness}
              onChange={(e) =>
                set("led_override_color_brightness", Number(e.target.value))
              }
            />{" "}
            {form.led_override_color_brightness}%
          </label>
        )}
        {has("led_color") && form.led_override !== "off" && (
          <TextInput
            {...bind("led_override_color")}
            type="color"
            className=""
            aria-label="LED colour"
          />
        )}
      </Row>
      <Row label="Antenna" hint="the gain sets the power limits">
        {d.antennas.length > 1 && (
          <Select
            {...bind("antenna_id")}
            options={d.antennas.map((a) => [a.id, a.name] as const)}
          />
        )}
        <span className="muted small">
          {d.radios
            .map((r) => `${band(r.radio)} ${r.antenna_gain ?? 6} dBi`)
            .join(", ")}
        </span>
      </Row>
      <Row label="Outdoor mode" hint="changes which channels are allowed">
        <Select
          value={form.outdoor_mode_override}
          onChange={setOutdoor}
          options={[
            [
              "default",
              `Site default (${d.site_outdoor ? "outdoor" : "indoor"})`,
            ],
            ["on", "Outdoor"],
            ["off", "Indoor"],
          ]}
        />
      </Row>
      {has("band_steering") &&
        d.radios.some((r) => r.radio === "ng") &&
        d.radios.some((r) => r.radio === "na") && (
          <Row
            label="Band steering"
            hint="move dual-band clients between this AP's radios"
          >
            <Select
              {...bind("bandsteering_mode")}
              options={[
                ["off", "Off"],
                ["equal", "Balance the bands"],
                ["prefer_5g", "Prefer 5 GHz"],
              ]}
            />
            {!d.advanced_features && form.bandsteering_mode !== "off" && (
              <div className="form-warn">
                The site's advanced features are off, so band steering is not
                sent to the AP.
              </div>
            )}
          </Row>
        )}
      {(has("airtime_fairness") || has("green_ap")) && (
        <Row label="Radio features">
          {has("airtime_fairness") && (
            <Toggle {...bind("atf_enabled")} label="Airtime fairness" />
          )}
          {has("green_ap") && (
            <Toggle
              {...bind("green_ap_enabled")}
              label="Green AP (power saving when idle)"
            />
          )}
        </Row>
      )}
      <Row label="Hardware" hint="not in the official UI">
        <Toggle
          value={form.resetbtn_enabled !== "off"}
          onChange={(v) => set("resetbtn_enabled", v ? "on" : "off")}
          label="Reset button works"
        />
        {has("jumbo_frames") && (
          <Toggle
            {...bind("jumboframe_enabled")}
            label="Jumbo frames on its port"
          />
        )}
      </Row>
      {has("snmp") && (
        <Row label="SNMP" hint="sent while SNMP is on in the site settings">
          <TextInput
            {...bind("snmp_location")}
            maxLength={255}
            placeholder="location"
            aria-label="SNMP location"
          />
          <TextInput
            {...bind("snmp_contact")}
            maxLength={255}
            placeholder="contact"
            aria-label="SNMP contact"
          />
        </Row>
      )}
      <Row label="IP address" hint="the AP's own management address">
        <AddressFields {...bind("config_network")} />
      </Row>
      {d.reported && missing.length > 0 && (
        <div className="muted small">
          Not supported by this AP: {missing.map(([, l]) => l).join(", ")}.
        </div>
      )}
      {d.radios.map((r, i) => {
        const f = radios[i];
        return (
          f && (
            <details key={r.radio} open>
              <summary>{band(r.radio)} radio</summary>
              <RadioFields
                r={r}
                d={d}
                outdoor={outdoor}
                form={f}
                onChange={(x) =>
                  setRadios((all) => all.map((y, j) => (j === i ? x : y)))
                }
              />
            </details>
          )
        );
      })}
    </EditorShell>
  );
}
