import { useEffect, useState } from "react";
import type { ReactNode } from "react";
import { useQueryClient } from "@tanstack/react-query";
import {
  changeSettings,
  useDeviceSettings,
  speed,
  useMe,
  useUserGroups,
  useWlanSettings,
  wlanPassphrase,
} from "../api";
import type {
  DeviceSettings,
  RadioSettings,
  SettingsPreview,
  SettingsTarget,
  UserGroup,
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

const words = (text: string) =>
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
        onChange(words(e.target.value));
      }}
    />
  );
}

/** IPv4 addresses, separated by commas or spaces (the text is kept as typed). */
function ServerList({
  value,
  onChange,
}: {
  value: unknown;
  onChange: (v: string[]) => void;
}) {
  const [text, setText] = useState(((value as string[]) ?? []).join(", "));
  return (
    <input
      className="search mono"
      placeholder="e.g. 192.168.1.1, 9.9.9.9"
      value={text}
      onChange={(e) => {
        setText(e.target.value);
        onChange(words(e.target.value));
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

/**
 * Names the APs broadcasting this SSID that lack `feature`: they get the
 * SSID without it. Shown while the feature is on.
 */
function Unsupported({
  feature,
  on,
  aps,
  list,
}: {
  feature: string;
  on: boolean;
  aps: string[] | null;
  list: WlanSettingsList;
}) {
  if (!on) return null;
  const from = aps ?? list.aps.map((a) => a.mac);
  const name = (m: string) => list.aps.find((a) => a.mac === m)?.name ?? m;
  const missing = (list.unsupported?.[feature] ?? []).filter((m) =>
    from.includes(m),
  );
  const unknown = (list.unknown ?? []).filter((m) => from.includes(m));
  if (missing.length === 0 && unknown.length === 0) return null;
  return (
    <div className="form-warn">
      {missing.length > 0 && (
        <>
          Not supported by {missing.map(name).join(", ")}:{" "}
          {missing.length === 1 ? "it broadcasts" : "they broadcast"} this SSID
          without it.{" "}
        </>
      )}
      {unknown.length > 0 && (
        <>
          {unknown.map(name).join(", ")}{" "}
          {unknown.length === 1 ? "hasn't" : "haven't"} reported yet, so support
          is unknown.
        </>
      )}
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
  const iot = f.enhanced_iot === true;
  const wpa3 = f.protection === "wpa3" || f.protection === "wpa2_wpa3";
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
            <option
              key={v}
              value={v}
              disabled={iot && v !== "wpa2" && v !== "open"}
            >
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
      <SpeedLimitRow
        value={f.usergroup_id}
        onChange={(v) => set("usergroup_id", v)}
      />
      <ScheduleEditor
        value={f.schedule_with_duration}
        onChange={(v) => set("schedule_with_duration", v)}
      />
      <details>
        <summary>Roaming</summary>
        <Row label="Fast roaming" hint="802.11r">
          <Toggle
            value={f.fast_roaming_enabled}
            disabled={iot}
            onChange={(v) => set("fast_roaming_enabled", v)}
            label="Enabled"
          />
          {f.protection === "wpa2_wpa3" && (
            <Toggle
              value={f.wpa3_fast_roaming}
              disabled={iot}
              onChange={(v) => set("wpa3_fast_roaming", v)}
              label="Also for WPA3 clients (not in the official UI)"
            />
          )}
          <Unsupported
            feature="wpa3_fast_roaming"
            on={f.protection === "wpa2_wpa3" && f.wpa3_fast_roaming === true}
            aps={aps}
            list={list}
          />
        </Row>
        <Row
          label="Neighbour reports"
          hint="802.11k: clients learn the nearby APs (not in the official UI)"
        >
          <Toggle
            value={f.rrm_enabled}
            onChange={(v) => set("rrm_enabled", v)}
            label="Enabled"
          />
        </Row>
        <Row label="BSS transition" hint="802.11v: APs suggest a better AP">
          <Toggle
            value={f.bss_transition}
            disabled={iot}
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
            disabled={iot}
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
          <Unsupported
            feature="roaming_assistant"
            on={f.roaming_assistant_na_enabled === true}
            aps={aps}
            list={list}
          />
        </Row>
        <Row
          label="Band steering"
          hint="keep dual-band clients the APs have seen on 5 GHz off 2.4 GHz"
        >
          <Toggle
            value={f.no2ghz_oui}
            disabled={iot || !(bands.includes("2g") && bands.includes("5g"))}
            onChange={(v) => set("no2ghz_oui", v)}
            label="Enabled"
          />
          {!(bands.includes("2g") && bands.includes("5g")) && (
            <span className="muted small">needs both 2.4 and 5 GHz</span>
          )}
        </Row>
      </details>
      <details
        open={iot || f.iot_channel_lock === true || f.iot_dtim_lock === true}
      >
        <summary>IoT</summary>
        <Row
          label="Force Wi-Fi 4"
          hint="for legacy devices: WPA2 or open on 2.4 GHz, without the newer features"
        >
          <Toggle value={f.enhanced_iot} onChange={setIot} label="Enabled" />
        </Row>
        <Row
          label="Lock 2.4 GHz to channel 6"
          hint="on every AP broadcasting this SSID"
        >
          <Toggle
            value={f.iot_channel_lock}
            disabled={!bands.includes("2g")}
            onChange={(v) => set("iot_channel_lock", v)}
            label="Enabled"
          />
        </Row>
        <Row label="DTIM interval lock" hint="2.4 GHz DTIM held at 3">
          <Toggle
            value={f.iot_dtim_lock}
            disabled={!bands.includes("2g")}
            onChange={(v) => {
              set("iot_dtim_lock", v);
              if (v) set("dtim_ng", 3);
            }}
            label="Enabled"
          />
        </Row>
        {!bands.includes("2g") && (
          <div className="muted small">The locks need 2.4 GHz.</div>
        )}
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
          <Unsupported
            feature="multicast_suppression"
            on={(f.multicast_suppressor_mode ?? "off") !== "off"}
            aps={aps}
            list={list}
          />
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
            disabled={iot}
            onChange={(v) => set("proxy_arp", v)}
            label="Enabled"
          />
        </Row>
      </details>
      <details>
        <summary>Advanced</summary>
        <Row
          label="DNS Assistance"
          hint="the APs cache DNS and fall back to other servers when the network's is slow or fails"
        >
          <select
            disabled={iot}
            value={String(f.dns_assistance_mode ?? "off")}
            onChange={(e) => set("dns_assistance_mode", e.target.value)}
          >
            <option value="off">Off</option>
            <option value="auto">Automatic fallback servers</option>
            <option value="manual">These fallback servers</option>
          </select>
          {f.dns_assistance_mode === "manual" && (
            <ServerList
              value={f.dns_assistance_servers}
              onChange={(v) => set("dns_assistance_servers", v)}
            />
          )}
          <Unsupported
            feature="dns_assistance"
            on={(f.dns_assistance_mode ?? "off") !== "off"}
            aps={aps}
            list={list}
          />
        </Row>
        <Row
          label="AP name in beacons"
          hint="clients can see which AP they're on"
        >
          <Toggle
            value={f.advertise_device_name_in_beacon}
            disabled={iot}
            onChange={(v) => set("advertise_device_name_in_beacon", v)}
            label="Enabled"
          />
          <Unsupported
            feature="advertise_ap_name"
            on={f.advertise_device_name_in_beacon === true}
            aps={aps}
            list={list}
          />
        </Row>
        <Row label="Protected management frames">
          <select
            disabled={iot}
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
            disabled={iot}
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
                  disabled={k === "dtim_ng" && f.iot_dtim_lock === true}
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
            disabled={iot}
            value={Number(f.group_rekey ?? 0)}
            onChange={(e) => set("group_rekey", Number(e.target.value))}
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
                {l}{" "}
                <input
                  type="number"
                  className="search num-input"
                  min={1}
                  max={60}
                  value={Number(f[k] ?? 5)}
                  onChange={(e) => set(k, Number(e.target.value))}
                />
              </label>
            ))}
          </Row>
        )}
        <Row label="Client-to-client links" hint="not in the official UI">
          <Toggle
            value={f.tdls_prohibit}
            onChange={(v) => set("tdls_prohibit", v)}
            label="Prohibit TDLS"
          />
          <Toggle
            value={f.p2p}
            onChange={(v) => set("p2p", v)}
            label="Wi-Fi Direct (P2P)"
          />
          {f.p2p === true && (
            <Toggle
              value={f.p2p_cross_connect}
              onChange={(v) => set("p2p_cross_connect", v)}
              label="P2P cross-connect"
            />
          )}
        </Row>
        <Row
          label="hostapd log level"
          hint="for debugging; not in the official UI"
        >
          <select
            value={Number(f.log_level ?? -1)}
            onChange={(e) => set("log_level", Number(e.target.value))}
          >
            <option value={-1}>AP default</option>
            <option value={0}>0 (verbose debug)</option>
            <option value={1}>1 (debug)</option>
            <option value={2}>2 (info)</option>
            <option value={3}>3 (notice)</option>
            <option value={4}>4 (warning)</option>
          </select>
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

/** The SSID's speed limit: a user group; the default group means none. */
function SpeedLimitRow({
  value,
  onChange,
}: {
  value: unknown;
  onChange: (v: string) => void;
}) {
  const groups = useUserGroups().data?.groups ?? [];
  const def = groups.find((g) => g.default);
  const current = typeof value === "string" && value !== def?.id ? value : "";
  return (
    <Row label="Speed limit" hint="per client on this SSID">
      <select value={current} onChange={(e) => onChange(e.target.value)}>
        <option value="">No limit</option>
        {groups
          .filter((g) => !g.default)
          .map((g) => (
            <option key={g.id} value={g.id}>
              {g.name} (down {speed(g.qos_rate_max_down)}, up{" "}
              {speed(g.qos_rate_max_up)})
            </option>
          ))}
      </select>
      {groups.length <= 1 && (
        <span className="muted small">add limits under Speed limits below</span>
      )}
    </Row>
  );
}

const WEEK = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"] as const;
const WEEK_LABEL: Record<string, string> = {
  sun: "Su",
  mon: "Mo",
  tue: "Tu",
  wed: "We",
  thu: "Th",
  fri: "Fr",
  sat: "Sa",
};

interface Blackout {
  start_days_of_week: string[];
  start_hour: number;
  start_minute: number;
  duration_minutes: number;
  name?: string;
}

const time = (m: number) =>
  `${String(Math.floor(m / 60) % 24).padStart(2, "0")}:${String(m % 60).padStart(2, "0")}`;
const minutes = (t: string) => {
  const [h, m] = t.split(":").map(Number);
  return (h || 0) * 60 + (m || 0);
};

/** Blackout periods: when the SSID is off. An end at or before the start runs past midnight. */
function ScheduleEditor({
  value,
  onChange,
}: {
  value: unknown;
  onChange: (v: Blackout[]) => void;
}) {
  const list = (Array.isArray(value) ? value : []) as Blackout[];
  const update = (i: number, e: Partial<Blackout>) =>
    onChange(list.map((x, j) => (j === i ? { ...x, ...e } : x)));
  return (
    <details open={list.length > 0}>
      <summary>
        Schedule
        {list.length > 0
          ? ` (${list.length} off period${list.length === 1 ? "" : "s"})`
          : ": always on"}
      </summary>
      <p className="muted small">
        Times this SSID is off, in the site's time zone. The APs follow it on
        their own clock.
      </p>
      {list.map((e, i) => {
        const start = e.start_hour * 60 + e.start_minute;
        const end = (start + e.duration_minutes) % 1440;
        const days = Math.floor((start + e.duration_minutes - 1) / 1440);
        return (
          <div key={i} className="form-row">
            <div className="form-label">
              <input
                className="search"
                placeholder="Name (optional)"
                value={e.name ?? ""}
                onChange={(ev) => update(i, { name: ev.target.value })}
              />
            </div>
            <div className="form-control">
              {WEEK.map((d) => (
                <label key={d} className="check">
                  <input
                    type="checkbox"
                    checked={e.start_days_of_week.includes(d)}
                    onChange={(ev) =>
                      update(i, {
                        start_days_of_week: ev.target.checked
                          ? [...e.start_days_of_week, d]
                          : e.start_days_of_week.filter((x) => x !== d),
                      })
                    }
                  />
                  {WEEK_LABEL[d]}
                </label>
              ))}
              <label className="small">
                off from{" "}
                <input
                  type="time"
                  className="search time-input"
                  value={time(start)}
                  onChange={(ev) => {
                    const s = minutes(ev.target.value);
                    update(i, {
                      start_hour: Math.floor(s / 60),
                      start_minute: s % 60,
                      duration_minutes: (end - s + 1440) % 1440 || 1440,
                    });
                  }}
                />
              </label>
              <label className="small">
                until{" "}
                <input
                  type="time"
                  className="search time-input"
                  value={time(end)}
                  onChange={(ev) =>
                    update(i, {
                      duration_minutes:
                        (minutes(ev.target.value) - start + 1440) % 1440 ||
                        1440,
                    })
                  }
                />
                {days > 0 && <span className="muted"> next day</span>}
              </label>
              <button
                className="btn small"
                onClick={() => onChange(list.filter((_, j) => j !== i))}
              >
                Remove
              </button>
            </div>
          </div>
        );
      })}
      <button
        className="btn small"
        onClick={() =>
          onChange([
            ...list,
            {
              start_days_of_week: ["mon", "tue", "wed", "thu", "fri"],
              start_hour: 0,
              start_minute: 0,
              duration_minutes: 360,
            },
          ])
        }
      >
        Add off period
      </button>
    </details>
  );
}

function SpeedLimitEditor({
  group,
  onClose,
  active,
}: {
  group: UserGroup | null;
  onClose: () => void;
  active: boolean;
}) {
  const mbps = (k: number | null | undefined) =>
    k && k > 0 ? String(k / 1000) : "";
  const [name, setName] = useState(group?.name ?? "");
  const [down, setDown] = useState(mbps(group?.qos_rate_max_down));
  const [up, setUp] = useState(mbps(group?.qos_rate_max_up));
  const [review, setReview] = useState<Fields | null>(null);
  const kbps = (v: string) =>
    v.trim() === "" ? -1 : Math.round(Number(v) * 1000);
  const patch: Fields = {
    name,
    qos_rate_max_down: kbps(down),
    qos_rate_max_up: kbps(up),
  };
  if (review)
    return (
      <Review
        target={{ kind: "usergroup", id: group?.id ?? null }}
        patch={review}
        active={active}
        onBack={() => setReview(null)}
        onSaved={onClose}
      />
    );
  return (
    <div className="settings-form">
      {!group?.default && (
        <Row label="Name">
          <input
            className="search"
            maxLength={128}
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
        </Row>
      )}
      <Row label="Download" hint="Mbps per client; empty for no limit">
        <input
          className="search num-input"
          type="number"
          min={0.002}
          max={100}
          step="any"
          value={down}
          onChange={(e) => setDown(e.target.value)}
        />
      </Row>
      <Row label="Upload" hint="Mbps per client; empty for no limit">
        <input
          className="search num-input"
          type="number"
          min={0.002}
          max={100}
          step="any"
          value={up}
          onChange={(e) => setUp(e.target.value)}
        />
      </Row>
      <div className="actions-row">
        <button className="btn" onClick={onClose}>
          Cancel
        </button>
        <button
          className="btn primary"
          disabled={!name.trim()}
          onClick={() =>
            setReview(
              group?.default
                ? { qos_rate_max_down: kbps(down), qos_rate_max_up: kbps(up) }
                : patch,
            )
          }
        >
          Review changes
        </button>
      </div>
    </div>
  );
}

/** Speed limits (user groups): used by SSIDs and by single clients. */
export function SpeedLimitsPanel() {
  const g = useUserGroups();
  const readOnly = useMe().data?.read_only ?? true;
  const [editing, setEditing] = useState<string | "new" | null>(null);
  const [removing, setRemoving] = useState<UserGroup | null>(null);
  if (!g.data) return null;
  const { active, groups } = g.data;
  const current = groups.find((x) => x.id === editing) ?? null;
  return (
    <div className="panel">
      <div className="panel-head">
        <b>Speed limits</b>
        <span className="muted small">
          per client, for an SSID or a single device
        </span>
        <span className="spacer" />
        {!readOnly && editing === null && !removing && (
          <button className="btn small" onClick={() => setEditing("new")}>
            Add speed limit
          </button>
        )}
      </div>
      {removing ? (
        <Review
          target={{ kind: "usergroup", id: removing.id, remove: true }}
          patch={{}}
          active={active}
          onBack={() => setRemoving(null)}
          onSaved={() => setRemoving(null)}
        />
      ) : editing !== null ? (
        <SpeedLimitEditor
          key={editing}
          group={editing === "new" ? null : current}
          active={active}
          onClose={() => setEditing(null)}
        />
      ) : (
        <div className="table-wrap">
          <table className="table">
            <tbody>
              {groups.map((x) => (
                <tr key={x.id}>
                  <td>
                    <b>{x.default ? "No limit (default)" : x.name}</b>
                  </td>
                  <td className="small">
                    down {speed(x.qos_rate_max_down)} · up{" "}
                    {speed(x.qos_rate_max_up)}
                  </td>
                  <td className="muted small">
                    {x.used_by.length ? x.used_by.join(", ") : "unused"}
                  </td>
                  <td className="nowrap">
                    {!readOnly && !x.default && (
                      <>
                        <button
                          className="btn small"
                          onClick={() => setEditing(x.id)}
                        >
                          Edit
                        </button>{" "}
                        <button
                          className="btn small"
                          disabled={x.used_by.length > 0}
                          title={x.used_by.length ? "still in use" : ""}
                          onClick={() => setRemoving(x)}
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
    sens_level_enabled: r.sens_level_enabled ?? false,
    sens_level: r.sens_level ?? -90,
    loadbalance_enabled: r.loadbalance_enabled ?? false,
    maxsta: r.maxsta ?? 50,
  };
}

function RadioFields({
  r,
  form,
  set,
  outdoor,
  d,
}: {
  r: RadioSettings;
  form: Fields;
  set: (k: string, v: unknown) => void;
  outdoor: boolean;
  d: DeviceSettings;
}) {
  const chans = outdoor ? r.channels_outdoor : r.channels;
  const widths =
    r.radio === "ng"
      ? [20, 40]
      : [20, 40, 80, ...(r.caps?.has_ht160 ? [160] : [])];
  const ht = Number(form.ht ?? 20);
  const legal = chans[String(ht)] ?? [];
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
              !(chans[String(w)] ?? []).includes(Number(form.channel))
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
      {r.has_blocker && form.min_rssi_enabled === true && (
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
      {r.has_blocker && (
        <Row
          label="Sensitivity"
          hint="ignore signals weaker than this, instead of deriving it from the minimum signal (not in the official UI)"
        >
          <Toggle
            value={form.sens_level_enabled}
            onChange={(v) => set("sens_level_enabled", v)}
            label="Fixed level"
          />
          {form.sens_level_enabled === true && (
            <label className="small">
              <input
                type="range"
                min={-90}
                max={-50}
                value={Number(form.sens_level ?? -90)}
                onChange={(e) => set("sens_level", Number(e.target.value))}
              />{" "}
              {String(form.sens_level)} dBm
            </label>
          )}
        </Row>
      )}
      <Row
        label="Client limit"
        hint="clients this radio accepts (not in the official UI)"
      >
        <Toggle
          value={form.loadbalance_enabled}
          onChange={(v) => set("loadbalance_enabled", v)}
          label="Enabled"
        />
        {form.loadbalance_enabled === true && (
          <label className="small">
            <input
              type="number"
              className="search num-input"
              min={1}
              max={200}
              value={Number(form.maxsta ?? 50)}
              onChange={(e) => set("maxsta", Number(e.target.value))}
            />{" "}
            clients
          </label>
        )}
      </Row>
      {!d.advanced_features &&
        (form.min_rssi_enabled === true ||
          form.loadbalance_enabled === true ||
          form.sens_level_enabled === true) && (
          <div className="form-warn">
            The site's advanced features are off, so the minimum signal,
            sensitivity and client limit are not sent to the AP.
          </div>
        )}
    </>
  );
}

/** The AP's own address; static needs care, as a wrong one cuts the AP off. */
function AddressFields({
  value,
  onChange,
}: {
  value: Fields;
  onChange: (v: Fields) => void;
}) {
  const field = (k: string, label: string, placeholder?: string) => (
    <label className="small">
      {label}{" "}
      <input
        className="search mono"
        placeholder={placeholder}
        value={String(value[k] ?? "")}
        onChange={(e) => onChange({ ...value, [k]: e.target.value })}
      />
    </label>
  );
  return (
    <>
      <select
        value={String(value.type ?? "dhcp")}
        onChange={(e) => onChange({ ...value, type: e.target.value })}
      >
        <option value="dhcp">DHCP</option>
        <option value="static">Static</option>
      </select>
      {value.type === "static" && (
        <>
          {field("ip", "address", "192.168.1.20")}
          {field("netmask", "netmask", "255.255.255.0")}
          {field("gateway", "gateway", "192.168.1.1")}
          {field("dns1", "DNS", "192.168.1.1")}
          {field("dns2", "DNS 2")}
          {field("dnssuffix", "search domain")}
          <div className="form-warn">
            A wrong address leaves the AP unreachable until it is reset. Check
            it against your network before saving.
          </div>
        </>
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
    led_override_color: d.led_override_color ?? "#0000ff",
    led_override_color_brightness: d.led_override_color_brightness ?? 100,
    outdoor_mode_override: d.outdoor_mode_override ?? "default",
    bandsteering_mode: d.bandsteering_mode ?? "off",
    atf_enabled: d.atf_enabled ?? false,
    green_ap_enabled: d.green_ap_enabled ?? false,
    resetbtn_enabled: d.resetbtn_enabled ?? "on",
    jumboframe_enabled: d.jumboframe_enabled ?? false,
    config_network: d.config_network ?? { type: "dhcp" },
    antenna_id:
      d.radios.find((r) => r.antenna_id !== null && r.antenna_id >= 0)
        ?.antenna_id ??
      d.antennas.find((a) => a.default)?.id ??
      -1,
  };
  const has = (f: string) => d.features.includes(f);
  const missing = [
    ["band_steering", "band steering"],
    ["airtime_fairness", "airtime fairness"],
    ["green_ap", "Green AP"],
    ["led_color", "LED colour"],
  ].filter(([f]) => !has(f));
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
  const set = (k: string, v: unknown) => setForm({ ...form, [k]: v });
  const outdoor =
    form.outdoor_mode_override === "on" ||
    (form.outdoor_mode_override === "default" && d.site_outdoor);
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
        {has("led") && form.led_override !== "off" && (
          <label className="small">
            brightness{" "}
            <input
              type="range"
              min={1}
              max={100}
              value={Number(form.led_override_color_brightness)}
              onChange={(e) =>
                set("led_override_color_brightness", Number(e.target.value))
              }
            />{" "}
            {String(form.led_override_color_brightness)}%
          </label>
        )}
        {has("led_color") && form.led_override !== "off" && (
          <input
            type="color"
            value={String(form.led_override_color)}
            onChange={(e) => set("led_override_color", e.target.value)}
          />
        )}
      </Row>
      <Row label="Antenna" hint="the gain sets the power limits">
        {d.antennas.length > 1 && (
          <select
            value={Number(form.antenna_id)}
            onChange={(e) => set("antenna_id", Number(e.target.value))}
          >
            {d.antennas.map((a) => (
              <option key={a.id} value={a.id}>
                {a.name}
              </option>
            ))}
          </select>
        )}
        <span className="muted small">
          {d.radios
            .map(
              (r) =>
                `${r.radio === "ng" ? "2.4 GHz" : r.radio === "na" ? "5 GHz" : r.radio} ${r.antenna_gain ?? 6} dBi`,
            )
            .join(", ")}
        </span>
      </Row>
      <Row label="Outdoor mode" hint="changes which channels are allowed">
        <select
          value={String(form.outdoor_mode_override)}
          onChange={(e) => set("outdoor_mode_override", e.target.value)}
        >
          <option value="default">
            Site default ({d.site_outdoor ? "outdoor" : "indoor"})
          </option>
          <option value="on">Outdoor</option>
          <option value="off">Indoor</option>
        </select>
      </Row>
      {has("band_steering") &&
        d.radios.some((r) => r.radio === "ng") &&
        d.radios.some((r) => r.radio === "na") && (
          <Row
            label="Band steering"
            hint="move dual-band clients between this AP's radios"
          >
            <select
              value={String(form.bandsteering_mode)}
              onChange={(e) => set("bandsteering_mode", e.target.value)}
            >
              <option value="off">Off</option>
              <option value="equal">Balance the bands</option>
              <option value="prefer_5g">Prefer 5 GHz</option>
            </select>
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
            <Toggle
              value={form.atf_enabled}
              onChange={(v) => set("atf_enabled", v)}
              label="Airtime fairness"
            />
          )}
          {has("green_ap") && (
            <Toggle
              value={form.green_ap_enabled}
              onChange={(v) => set("green_ap_enabled", v)}
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
            value={form.jumboframe_enabled}
            onChange={(v) => set("jumboframe_enabled", v)}
            label="Jumbo frames on its port"
          />
        )}
      </Row>
      <Row label="IP address" hint="the AP's own management address">
        <AddressFields
          value={form.config_network as Fields}
          onChange={(v) => set("config_network", v)}
        />
      </Row>
      {d.reported && missing.length > 0 && (
        <div className="muted small">
          Not supported by this AP: {missing.map(([, l]) => l).join(", ")}.
        </div>
      )}
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
            d={d}
            outdoor={outdoor}
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
