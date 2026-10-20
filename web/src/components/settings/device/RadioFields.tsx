import type { DeviceSettings, RadioSettings } from "../../../api";
import { NumberInput, RangeInput, Row, Select, Toggle, binder } from "../form";
import type { Option } from "../form";

/** A radio's editable fields, as the form holds them. */
type RadioForm = {
  radio: string;
  channel: number | "auto";
  ht: number;
  tx_power_mode: string;
  /** dBm; null while the AP decides. */
  tx_power: number | null;
  min_rssi_enabled: boolean;
  min_rssi: number;
  hard_noise_floor_enabled: boolean;
  sens_level_enabled: boolean;
  sens_level: number;
  loadbalance_enabled: boolean;
  maxsta: number;
};

/** The form's fields from the settings, with numbers held as text ("20") read as numbers. */
export function radioForm(r: RadioSettings): RadioForm {
  return {
    radio: r.radio,
    channel: r.channel === "auto" ? "auto" : Number(r.channel),
    ht: Number(r.ht),
    tx_power_mode: r.tx_power_mode,
    tx_power:
      r.tx_power === null || r.tx_power === "auto" ? null : Number(r.tx_power),
    min_rssi_enabled: r.min_rssi_enabled ?? false,
    min_rssi: r.min_rssi ?? -80,
    hard_noise_floor_enabled: r.hard_noise_floor_enabled ?? false,
    sens_level_enabled: r.sens_level_enabled ?? false,
    sens_level: r.sens_level ?? -90,
    loadbalance_enabled: r.loadbalance_enabled ?? false,
    maxsta: r.maxsta ?? 50,
  };
}

/** The channels allowed at a width, indoors or in outdoor mode. */
const allowed = (r: RadioSettings, outdoor: boolean, ht: number) =>
  (outdoor ? r.channels_outdoor : r.channels)[String(ht)] ?? [];

/** A fixed channel that isn't allowed (at this width, indoors or out) falls back to auto. */
export const keepAllowed = (
  r: RadioSettings,
  f: RadioForm,
  outdoor: boolean,
): RadioForm =>
  f.channel !== "auto" && !allowed(r, outdoor, f.ht).includes(f.channel)
    ? { ...f, channel: "auto" }
    : f;

const POWER: Option<string>[] = [
  ["auto", "Auto"],
  ["high", "High"],
  ["medium", "Medium"],
  ["low", "Low"],
  ["custom", "Custom"],
  ["disabled", "Off (radio disabled)"],
];

export function RadioFields({
  r,
  form,
  onChange,
  outdoor,
  d,
}: {
  r: RadioSettings;
  form: RadioForm;
  onChange: (f: RadioForm) => void;
  outdoor: boolean;
  d: DeviceSettings;
}) {
  const set = <K extends keyof RadioForm>(k: K, v: RadioForm[K]) =>
    onChange({ ...form, [k]: v });
  const bind = binder(form, set);
  const widths =
    r.radio === "ng"
      ? [20, 40]
      : [20, 40, 80, ...(r.caps?.has_ht160 ? [160] : [])];
  const legal = allowed(r, outdoor, form.ht);
  const lo = r.caps?.min_txpower ?? 1;
  const hi = r.caps?.max_txpower ?? 30;
  // Custom power starts at the most the radio can do (what High gives), so
  // the power shown is the one sent; with none, the AP would stay on auto.
  const setPowerMode = (m: string) =>
    onChange({
      ...form,
      tx_power_mode: m,
      tx_power: m === "custom" ? (form.tx_power ?? hi) : form.tx_power,
    });
  return (
    <>
      <Row label="Channel">
        <Select
          aria-label="Channel width"
          value={form.ht}
          onChange={(w) =>
            onChange(keepAllowed(r, { ...form, ht: w }, outdoor))
          }
          stray={(w) => `${w} MHz`}
          options={widths.map((w) => [w, `${w} MHz`] as const)}
        />
        <Select
          {...bind("channel")}
          stray={(c) => `${c} (not allowed here)`}
          options={[
            ["auto", "Auto"],
            ...legal.map((c) => {
              // DFS is a 5 GHz rule; 6 GHz reuses the channel numbers.
              const dfs = r.radio === "na" && c >= 52 && c <= 144;
              return [c, `${c}${dfs ? " (DFS)" : ""}`] as const;
            }),
          ]}
        />
      </Row>
      <Row label="Transmit power">
        <Select
          value={form.tx_power_mode}
          onChange={setPowerMode}
          options={POWER}
        />
        {form.tx_power_mode === "custom" && (
          <label className="small">
            <NumberInput
              {...bind("tx_power")}
              aria-label="Custom transmit power"
              fallback={hi}
              min={lo}
              max={hi}
            />{" "}
            dBm ({lo}–{hi})
          </label>
        )}
      </Row>
      <Row label="Minimum signal" hint="disconnect clients weaker than this">
        <Toggle {...bind("min_rssi_enabled")} label="Enabled" />
        {form.min_rssi_enabled && (
          <RangeInput
            {...bind("min_rssi")}
            aria-label="Minimum signal"
            fallback={-80}
            min={-90}
            max={-67}
            unit=" dBm"
          />
        )}
      </Row>
      {r.has_blocker && form.min_rssi_enabled && (
        <Row
          label="Interference blocker"
          hint="ignore signals below the minimum"
        >
          <Toggle {...bind("hard_noise_floor_enabled")} label="Enabled" />
        </Row>
      )}
      {r.has_blocker && (
        <Row
          label="Sensitivity"
          hint="ignore signals weaker than this, instead of deriving it from the minimum signal (not in the official UI)"
        >
          <Toggle {...bind("sens_level_enabled")} label="Fixed level" />
          {form.sens_level_enabled && (
            <RangeInput
              {...bind("sens_level")}
              aria-label="Sensitivity level"
              fallback={-90}
              min={-90}
              max={-50}
              unit=" dBm"
            />
          )}
        </Row>
      )}
      <Row
        label="Client limit"
        hint="clients this radio accepts (not in the official UI)"
      >
        <Toggle {...bind("loadbalance_enabled")} label="Enabled" />
        {form.loadbalance_enabled && (
          <label className="small">
            <NumberInput {...bind("maxsta")} fallback={50} min={1} max={200} />{" "}
            clients
          </label>
        )}
      </Row>
      {!d.advanced_features &&
        (form.min_rssi_enabled ||
          form.loadbalance_enabled ||
          form.sens_level_enabled) && (
          <div className="form-warn">
            The site's advanced features are off, so the minimum signal,
            sensitivity and client limit are not sent to the AP.
          </div>
        )}
    </>
  );
}
