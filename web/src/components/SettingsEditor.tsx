import { useEffect, useState } from "react";
import type { ReactNode } from "react";
import { useQueryClient } from "@tanstack/react-query";
import {
  changeSettings,
  useDeviceSettings,
  useMe,
  useWlanSettings,
  wlanPassphrase,
} from "../api";
import type {
  DeviceSettings,
  RadioSettings,
  SettingsPreview,
  SettingsTarget,
  WlanSettings,
  WlanSettingsList,
} from "../api";
import { ChangeGroups, summarise } from "./ConfigDiff";
import { ErrorNote, Loading } from "./common";

type Fields = Record<string, unknown>;

/** The fields of `form` that differ from `original`. */
function changed(original: Fields, form: Fields): Fields {
  const out: Fields = {};
  for (const [k, v] of Object.entries(form))
    if (JSON.stringify(v) !== JSON.stringify(original[k])) out[k] = v;
  return out;
}

function Row({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: ReactNode;
}) {
  return (
    <div className="form-row">
      <div className="form-label">
        {label}
        {hint && <div className="muted small">{hint}</div>}
      </div>
      <div className="form-control">{children}</div>
    </div>
  );
}

function Toggle({
  value,
  onChange,
  label,
  disabled,
}: {
  value: unknown;
  onChange: (v: boolean) => void;
  label: string;
  disabled?: boolean;
}) {
  return (
    <label className="check">
      <input
        type="checkbox"
        checked={value === true}
        disabled={disabled}
        onChange={(e) => onChange(e.target.checked)}
      />
      {label}
    </label>
  );
}

const macs = (text: string) =>
  text
    .split(/[\s,;]+/)
    .map((m) => m.trim())
    .filter(Boolean);

/** A list of MAC addresses, one per line (the text is kept as typed). */
function MacList({
  value,
  rows,
  onChange,
}: {
  value: unknown;
  rows: number;
  onChange: (v: string[]) => void;
}) {
  const [text, setText] = useState(((value as string[]) ?? []).join("\n"));
  return (
    <textarea
      className="search mono"
      rows={rows}
      value={text}
      onChange={(e) => {
        setText(e.target.value);
        onChange(macs(e.target.value));
      }}
    />
  );
}

/**
 * Review, then save: shows what each AP's config would become before the
 * change is saved. Saving needs active mode.
 */
function Review({
  target,
  patch,
  active,
  onBack,
  onSaved,
}: {
  target: SettingsTarget;
  patch: Fields;
  active: boolean;
  onBack: () => void;
  onSaved: () => void;
}) {
  const qc = useQueryClient();
  const [preview, setPreview] = useState<SettingsPreview | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  // The preview is asked for once, when the review opens.
  const request = JSON.stringify([target, patch]);
  useEffect(() => {
    const [t, p] = JSON.parse(request) as [SettingsTarget, Fields];
    changeSettings<SettingsPreview>(t, p, false)
      .then(setPreview)
      .catch((e: Error) => setError(e.message));
  }, [request]);
  const save = async () => {
    setBusy(true);
    try {
      await changeSettings(target, patch, true);
      await qc.invalidateQueries({ queryKey: ["settings"] });
      void qc.invalidateQueries({ queryKey: ["wlans"] });
      void qc.invalidateQueries({ queryKey: ["events"] });
      onSaved();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="review">
      {error ? (
        <div className="error small">{error}</div>
      ) : !preview ? (
        <Loading />
      ) : (
        <>
          <div className="small">
            <b>{preview.what}</b>
          </div>
          {preview.aps.map((a) => {
            const { changes, groups } = summarise(a as Record<string, any>);
            return (
              <div key={a.mac} className="cfg-entry">
                <div className="cfg-head">
                  <b>{a.name ?? a.mac}</b>
                  <span className="muted small">
                    {a.error
                      ? `cannot render its config: ${a.error}`
                      : changes.length === 0
                        ? "no change to its config"
                        : `${changes.length} config line${changes.length === 1 ? "" : "s"} change`}
                  </span>
                </div>
                {changes.length > 0 && <ChangeGroups groups={groups} />}
              </div>
            );
          })}
          {preview.aps.length === 0 && (
            <div className="muted small">
              No AP has reported yet, so there is nothing to compare.
            </div>
          )}
        </>
      )}
      <div className="actions-row">
        <button className="btn" onClick={onBack} disabled={busy}>
          Back
        </button>
        <button
          className="btn primary"
          disabled={!active || busy || !!error || !preview}
          onClick={() => void save()}
        >
          Save and send to the APs
        </button>
        {!active && (
          <span className="muted small">
            Saving works after the cutover: in shadow mode the settings belong
            to your current controller.
          </span>
        )}
      </div>
    </div>
  );
}

const PROTECTION: [string, string][] = [
  ["wpa2_wpa3", "WPA2/WPA3 Personal"],
  ["wpa2", "WPA2 Personal"],
  ["wpa3", "WPA3 Personal"],
  ["open", "Open (no password)"],
];

const RATES_NG = [
  1000, 2000, 5500, 6000, 9000, 11000, 12000, 18000, 24000, 36000, 48000, 54000,
];
const RATES_NA = [6000, 9000, 12000, 18000, 24000, 36000, 48000, 54000];
const mbps = (kbps: number) => `${kbps / 1000} Mbps`;

/** The editable fields of an SSID, as the form holds them. */
function wlanForm(w: WlanSettings | null): Fields {
  if (!w)
    return {
      name: "",
      enabled: true,
      protection: "wpa2_wpa3",
      wlan_bands: ["2g", "5g"],
      aps: null,
    };
  const { id: _id, editable: _e, has_passphrase: _h, ...rest } = w;
  return rest;
}

export function WlanEditor({
  wlan,
  list,
  onClose,
}: {
  wlan: WlanSettings | null;
  list: WlanSettingsList;
  onClose: () => void;
}) {
  const original = wlanForm(wlan);
  const [form, setForm] = useState<Fields>(original);
  const [password, setPassword] = useState("");
  const [shown, setShown] = useState<string | null>(null);
  const [review, setReview] = useState<Fields | null>(null);
  const set = (k: string, v: unknown) => setForm((f) => ({ ...f, [k]: v }));
  const f = form;
  const bands = (f.wlan_bands as string[] | null) ?? [];
  const toggleBand = (b: string, on: boolean) =>
    set("wlan_bands", on ? [...bands, b] : bands.filter((x) => x !== b));
  const aps = f.aps as string[] | null;
  const target: SettingsTarget = { kind: "wlan", id: wlan?.id ?? null };
  const patch = () => {
    const p = wlan ? changed(original, form) : { ...form };
    if (password) p.passphrase = password;
    return p;
  };
  if (review)
    return (
      <Review
        target={target}
        patch={review}
        active={list.active}
        onBack={() => setReview(null)}
        onSaved={onClose}
      />
    );
  const nothing = wlan !== null && Object.keys(patch()).length === 0;
  return (
    <div className="settings-form">
      <Row label="Name (SSID)">
        <input
          className="search"
          maxLength={32}
          value={String(f.name ?? "")}
          onChange={(e) => set("name", e.target.value)}
        />
      </Row>
      <Row label="Status">
        <Toggle
          value={f.enabled}
          onChange={(v) => set("enabled", v)}
          label="Enabled"
        />
        <Toggle
          value={f.hide_ssid}
          onChange={(v) => set("hide_ssid", v)}
          label="Hidden (not in the network list)"
        />
      </Row>
      <Row label="Security">
        <select
          value={String(f.protection ?? "")}
          onChange={(e) => {
            set("protection", e.target.value);
            set("pmf_mode", undefined);
          }}
        >
          {f.protection === null && (
            <option value="">(other, set elsewhere)</option>
          )}
          {PROTECTION.map(([v, l]) => (
            <option key={v} value={v}>
              {l}
            </option>
          ))}
        </select>
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
          {wlan?.has_passphrase &&
            (shown === null ? (
              <button
                className="btn small"
                onClick={() =>
                  void wlanPassphrase(wlan.id).then((r) =>
                    setShown(r.passphrase ?? ""),
                  )
                }
              >
                Show current
              </button>
            ) : (
              <span className="mono small">{shown}</span>
            ))}
        </Row>
      )}
      <Row label="Bands">
        <Toggle
          value={bands.includes("2g")}
          onChange={(v) => toggleBand("2g", v)}
          label="2.4 GHz"
        />
        <Toggle
          value={bands.includes("5g")}
          onChange={(v) => toggleBand("5g", v)}
          label="5 GHz"
        />
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
          <select
            value={String(f.networkconf_id ?? "")}
            onChange={(e) => set("networkconf_id", e.target.value)}
          >
            {list.networks.map((n) => (
              <option key={n.id} value={n.id}>
                {n.name}
                {n.vlan ? ` (VLAN ${n.vlan})` : ""}
              </option>
            ))}
          </select>
        </Row>
      )}
      <details>
        <summary>Roaming</summary>
        <Row label="Fast roaming" hint="802.11r">
          <Toggle
            value={f.fast_roaming_enabled}
            onChange={(v) => set("fast_roaming_enabled", v)}
            label="Enabled"
          />
        </Row>
        <Row label="BSS transition" hint="802.11v: APs suggest a better AP">
          <Toggle
            value={f.bss_transition}
            onChange={(v) => set("bss_transition", v)}
            label="Enabled"
          />
        </Row>
        <Row
          label="Roaming assistant (5 GHz)"
          hint="nudge clients away below this signal"
        >
          <Toggle
            value={f.roaming_assistant_na_enabled}
            onChange={(v) => set("roaming_assistant_na_enabled", v)}
            label="Enabled"
          />
          {f.roaming_assistant_na_enabled === true && (
            <label className="small">
              <input
                type="range"
                min={-80}
                max={-60}
                value={Number(f.roaming_assistant_na_rssi ?? -75)}
                onChange={(e) =>
                  set("roaming_assistant_na_rssi", Number(e.target.value))
                }
              />{" "}
              {String(f.roaming_assistant_na_rssi ?? -75)} dBm
            </label>
          )}
        </Row>
      </details>
      <details>
        <summary>Multicast and broadcast</summary>
        <Row
          label="Multicast enhancement"
          hint="send multicast to each client directly"
        >
          <Toggle
            value={f.mcastenhance_enabled}
            onChange={(v) => set("mcastenhance_enabled", v)}
            label="Enabled"
          />
        </Row>
        <Row label="Multicast and broadcast control">
          <select
            value={String(f.multicast_suppressor_mode ?? "off")}
            onChange={(e) => set("multicast_suppressor_mode", e.target.value)}
          >
            <option value="off">Off</option>
            <option value="conservative">Conservative</option>
            <option value="aggressive">Aggressive (allow list only)</option>
          </select>
        </Row>
        {f.multicast_suppressor_mode === "aggressive" && (
          <Row label="Allowed senders" hint="MAC addresses, one per line">
            <MacList
              value={f.bc_filter_list}
              rows={4}
              onChange={(v) => set("bc_filter_list", v)}
            />
          </Row>
        )}
        <Row label="Proxy ARP">
          <Toggle
            value={f.proxy_arp}
            onChange={(v) => set("proxy_arp", v)}
            label="Enabled"
          />
        </Row>
      </details>
      <details>
        <summary>Advanced</summary>
        <Row label="Protected management frames">
          <select
            value={String(f.pmf_mode ?? "")}
            onChange={(e) => set("pmf_mode", e.target.value || undefined)}
          >
            <option value="">(from the security choice)</option>
            <option value="disabled">Disabled</option>
            <option value="optional">Optional</option>
            <option value="required">Required</option>
          </select>
        </Row>
        <Row label="Client isolation" hint="clients can't reach each other">
          <Toggle
            value={f.l2_isolation}
            onChange={(v) => set("l2_isolation", v)}
            label="Enabled"
          />
        </Row>
        <Row label="Guest network">
          <Toggle
            value={f.is_guest}
            onChange={(v) => set("is_guest", v)}
            label="Guest"
          />
        </Row>
        <Row label="U-APSD" hint="power saving for phones">
          <Toggle
            value={f.uapsd_enabled}
            onChange={(v) => set("uapsd_enabled", v)}
            label="Enabled"
          />
        </Row>
        <Row label="Beacon country" hint="802.11d">
          <Toggle
            value={f.country_beacon}
            onChange={(v) => set("country_beacon", v)}
            label="Enabled"
          />
        </Row>
        <Row label="Minimum data rates">
          <select
            value={String(f.minrate_setting_preference ?? "auto")}
            onChange={(e) => set("minrate_setting_preference", e.target.value)}
          >
            <option value="auto">Automatic</option>
            <option value="manual">Manual</option>
          </select>
          {f.minrate_setting_preference === "manual" && (
            <>
              <label className="small">
                2.4 GHz{" "}
                <select
                  value={Number(f.minrate_ng_data_rate_kbps ?? 1000)}
                  onChange={(e) =>
                    set("minrate_ng_data_rate_kbps", Number(e.target.value))
                  }
                >
                  {RATES_NG.map((r) => (
                    <option key={r} value={r}>
                      {mbps(r)}
                    </option>
                  ))}
                </select>
              </label>
              <Toggle
                value={f.minrate_na_enabled}
                onChange={(v) => set("minrate_na_enabled", v)}
                label="5 GHz"
              />
              {f.minrate_na_enabled === true && (
                <select
                  value={Number(f.minrate_na_data_rate_kbps ?? 6000)}
                  onChange={(e) =>
                    set("minrate_na_data_rate_kbps", Number(e.target.value))
                  }
                >
                  {RATES_NA.map((r) => (
                    <option key={r} value={r}>
                      {mbps(r)}
                    </option>
                  ))}
                </select>
              )}
            </>
          )}
        </Row>
        <Row label="DTIM period">
          <select
            value={String(f.dtim_mode ?? "default")}
            onChange={(e) => set("dtim_mode", e.target.value)}
          >
            <option value="default">Default (2.4 GHz 1, 5 GHz 3)</option>
            <option value="custom">Custom</option>
          </select>
          {f.dtim_mode === "custom" &&
            (["dtim_ng", "dtim_na"] as const).map((k) => (
              <label key={k} className="small">
                {k === "dtim_ng" ? "2.4 GHz" : "5 GHz"}{" "}
                <input
                  type="number"
                  className="search num-input"
                  min={1}
                  max={255}
                  value={Number(f[k] ?? 1)}
                  onChange={(e) => set(k, Number(e.target.value))}
                />
              </label>
            ))}
        </Row>
        <Row label="Group rekey" hint="seconds; 0 is off">
          <input
            type="number"
            className="search num-input"
            min={0}
            max={86400}
            value={Number(f.group_rekey ?? 0)}
            onChange={(e) => set("group_rekey", Number(e.target.value))}
          />
        </Row>
        <Row label="MAC address filter">
          <Toggle
            value={f.mac_filter_enabled}
            onChange={(v) => set("mac_filter_enabled", v)}
            label="Enabled"
          />
          {f.mac_filter_enabled === true && (
            <select
              value={String(f.mac_filter_policy ?? "allow")}
              onChange={(e) => set("mac_filter_policy", e.target.value)}
            >
              <option value="allow">Only these may join</option>
              <option value="deny">These may not join</option>
            </select>
          )}
        </Row>
        {f.mac_filter_enabled === true && (
          <Row label="Filtered addresses" hint="MAC addresses, one per line">
            <MacList
              value={f.mac_filter_list}
              rows={5}
              onChange={(v) => set("mac_filter_list", v)}
            />
          </Row>
        )}
      </details>
      <div className="actions-row">
        <button className="btn" onClick={onClose}>
          Cancel
        </button>
        <button
          className="btn primary"
          disabled={nothing}
          onClick={() => setReview(patch())}
        >
          {nothing ? "No changes" : "Review changes"}
        </button>
      </div>
    </div>
  );
}

/** The Networks page's settings section: every SSID, editable. */
export function WlanSettingsPanel() {
  const s = useWlanSettings();
  const readOnly = useMe().data?.read_only ?? true;
  const [editing, setEditing] = useState<string | "new" | null>(null);
  const [removing, setRemoving] = useState<WlanSettings | null>(null);
  if (s.error) return <ErrorNote error={s.error} />;
  if (!s.data) return <Loading />;
  const list = s.data;
  if (list.wlans.length === 0 && !list.active) return null;
  const current = list.wlans.find((w) => w.id === editing) ?? null;
  return (
    <div className="panel">
      <div className="panel-head">
        <b>Settings</b>
        <span className="muted small">
          {list.active
            ? "changes are reviewed, then sent to the APs"
            : "shadow mode: you can try changes and see what they would send"}
        </span>
        <span className="spacer" />
        {!readOnly && editing === null && !removing && (
          <button className="btn small" onClick={() => setEditing("new")}>
            Add SSID
          </button>
        )}
      </div>
      {removing ? (
        <Review
          target={{ kind: "wlan", id: removing.id, remove: true }}
          patch={{}}
          active={list.active}
          onBack={() => setRemoving(null)}
          onSaved={() => setRemoving(null)}
        />
      ) : editing !== null ? (
        <>
          <div className="small">
            <b>{editing === "new" ? "New SSID" : `Editing ${current?.name}`}</b>
          </div>
          <WlanEditor
            key={editing}
            wlan={editing === "new" ? null : current}
            list={list}
            onClose={() => setEditing(null)}
          />
        </>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <tbody>
              {list.wlans.map((w) => (
                <tr key={w.id}>
                  <td>
                    <b>{w.name}</b>
                    {w.enabled === false && <span className="tag">off</span>}
                  </td>
                  <td className="muted small">
                    {PROTECTION.find((p) => p[0] === w.protection)?.[1] ??
                      "other security"}{" "}
                    ·{" "}
                    {((w.wlan_bands as string[]) ?? [])
                      .map((b) => b.replace("g", " GHz").replace("2 ", "2.4 "))
                      .join(" + ")}{" "}
                    ·{" "}
                    {w.aps === null
                      ? "all APs"
                      : w.aps
                          .map(
                            (m) => list.aps.find((a) => a.mac === m)?.name ?? m,
                          )
                          .join(", ")}
                  </td>
                  <td className="nowrap">
                    {!readOnly && w.editable && (
                      <>
                        <button
                          className="btn small"
                          onClick={() => setEditing(w.id)}
                        >
                          Edit
                        </button>{" "}
                        <button
                          className="btn small"
                          onClick={() => setRemoving(w)}
                        >
                          Delete
                        </button>
                      </>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// ---- APs ----

const POWER: [string, string][] = [
  ["auto", "Auto"],
  ["high", "High"],
  ["medium", "Medium"],
  ["low", "Low"],
  ["custom", "Custom"],
  ["disabled", "Off (radio disabled)"],
];

function radioForm(r: RadioSettings): Fields {
  return {
    radio: r.radio,
    channel: r.channel,
    ht: r.ht,
    tx_power_mode: r.tx_power_mode,
    tx_power:
      r.tx_power === null || r.tx_power === "auto" ? null : Number(r.tx_power),
    min_rssi_enabled: r.min_rssi_enabled ?? false,
    min_rssi: r.min_rssi ?? -80,
    hard_noise_floor_enabled: r.hard_noise_floor_enabled ?? false,
  };
}

function RadioFields({
  r,
  form,
  set,
}: {
  r: RadioSettings;
  form: Fields;
  set: (k: string, v: unknown) => void;
}) {
  const widths =
    r.radio === "ng"
      ? [20, 40]
      : [20, 40, 80, ...(r.caps?.has_ht160 ? [160] : [])];
  const ht = Number(form.ht ?? 20);
  const legal = r.channels[String(ht)] ?? [];
  const lo = r.caps?.min_txpower ?? 1;
  const hi = r.caps?.max_txpower ?? 30;
  return (
    <>
      <Row label="Channel">
        <select
          value={String(form.ht)}
          onChange={(e) => {
            const w = Number(e.target.value);
            set("ht", w);
            // A fixed channel not legal at the new width falls back to auto.
            if (
              form.channel !== "auto" &&
              !(r.channels[String(w)] ?? []).includes(Number(form.channel))
            )
              set("channel", "auto");
          }}
        >
          {widths.map((w) => (
            <option key={w} value={w}>
              {w} MHz
            </option>
          ))}
        </select>
        <select
          value={String(form.channel)}
          onChange={(e) =>
            set(
              "channel",
              e.target.value === "auto" ? "auto" : Number(e.target.value),
            )
          }
        >
          <option value="auto">Auto</option>
          {legal.map((c) => (
            <option key={c} value={c}>
              {c}
              {c >= 52 && c <= 144 ? " (DFS)" : ""}
            </option>
          ))}
        </select>
      </Row>
      <Row label="Transmit power">
        <select
          value={String(form.tx_power_mode)}
          onChange={(e) => set("tx_power_mode", e.target.value)}
        >
          {POWER.map(([v, l]) => (
            <option key={v} value={v}>
              {l}
            </option>
          ))}
        </select>
        {form.tx_power_mode === "custom" && (
          <label className="small">
            <input
              type="number"
              className="search num-input"
              min={lo}
              max={hi}
              value={Number(form.tx_power ?? lo)}
              onChange={(e) => set("tx_power", Number(e.target.value))}
            />{" "}
            dBm ({lo}–{hi})
          </label>
        )}
      </Row>
      <Row label="Minimum signal" hint="disconnect clients weaker than this">
        <Toggle
          value={form.min_rssi_enabled}
          onChange={(v) => set("min_rssi_enabled", v)}
          label="Enabled"
        />
        {form.min_rssi_enabled === true && (
          <label className="small">
            <input
              type="range"
              min={-90}
              max={-67}
              value={Number(form.min_rssi ?? -80)}
              onChange={(e) => set("min_rssi", Number(e.target.value))}
            />{" "}
            {String(form.min_rssi)} dBm
          </label>
        )}
      </Row>
      {r.has_blocker && (
        <Row
          label="Interference blocker"
          hint="ignore signals below the minimum"
        >
          <Toggle
            value={form.hard_noise_floor_enabled}
            onChange={(v) => set("hard_noise_floor_enabled", v)}
            label="Enabled"
          />
        </Row>
      )}
    </>
  );
}

function DeviceEditor({
  d,
  onClose,
}: {
  d: DeviceSettings;
  onClose: () => void;
}) {
  const original: Fields = {
    name: d.name ?? "",
    led_override: d.led_override ?? "default",
  };
  const [form, setForm] = useState<Fields>(original);
  const [radios, setRadios] = useState<Fields[]>(d.radios.map(radioForm));
  const [review, setReview] = useState<Fields | null>(null);
  const patch = () => {
    const p = changed(original, form);
    const r = d.radios
      .map((x, i) => {
        const c = changed(radioForm(x), radios[i]);
        return Object.keys(c).length ? { radio: x.radio, ...c } : null;
      })
      .filter(Boolean);
    if (r.length) p.radios = r;
    return p;
  };
  if (review)
    return (
      <Review
        target={{ kind: "device", mac: d.mac }}
        patch={review}
        active={d.active}
        onBack={() => setReview(null)}
        onSaved={onClose}
      />
    );
  const nothing = Object.keys(patch()).length === 0;
  return (
    <div className="settings-form">
      <Row label="Name">
        <input
          className="search"
          maxLength={128}
          value={String(form.name)}
          onChange={(e) => setForm({ ...form, name: e.target.value })}
        />
      </Row>
      <Row label="LED">
        <select
          value={String(form.led_override)}
          onChange={(e) => setForm({ ...form, led_override: e.target.value })}
        >
          <option value="default">Site default</option>
          <option value="on">On</option>
          <option value="off">Off</option>
        </select>
      </Row>
      {d.radios.map((r, i) => (
        <details key={r.radio} open>
          <summary>
            {r.radio === "ng"
              ? "2.4 GHz radio"
              : r.radio === "na"
                ? "5 GHz radio"
                : r.radio}
          </summary>
          <RadioFields
            r={r}
            form={radios[i]}
            set={(k, v) =>
              setRadios((all) =>
                all.map((x, j) => (j === i ? { ...x, [k]: v } : x)),
              )
            }
          />
        </details>
      ))}
      <div className="actions-row">
        <button className="btn" onClick={onClose}>
          Cancel
        </button>
        <button
          className="btn primary"
          disabled={nothing}
          onClick={() => setReview(patch())}
        >
          {nothing ? "No changes" : "Review changes"}
        </button>
      </div>
    </div>
  );
}

/** The AP page's settings section. */
export function DeviceSettingsPanel({ mac }: { mac: string }) {
  const s = useDeviceSettings(mac);
  const readOnly = useMe().data?.read_only ?? true;
  const [editing, setEditing] = useState(false);
  if (!s.data || readOnly) return null;
  const d = s.data;
  const radio = (r: RadioSettings) =>
    `${r.radio === "ng" ? "2.4 GHz" : "5 GHz"}: ${r.channel === "auto" ? "auto channel" : `channel ${r.channel}`}, ${r.ht} MHz, power ${r.tx_power_mode === "custom" ? `${r.tx_power} dBm` : r.tx_power_mode}${r.min_rssi_enabled ? `, min signal ${r.min_rssi} dBm` : ""}`;
  return (
    <div className="panel">
      <div className="panel-head">
        <b>Settings</b>
        <span className="muted small">
          {editing ? "" : d.radios.map(radio).join(" · ")}
        </span>
        <span className="spacer" />
        {!editing && (
          <button className="btn small" onClick={() => setEditing(true)}>
            Edit
          </button>
        )}
      </div>
      {editing && <DeviceEditor d={d} onClose={() => setEditing(false)} />}
    </div>
  );
}
