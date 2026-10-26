import type { SiteSettings } from "../../../api";
import {
  ListInput,
  NumberInput,
  Row,
  Select,
  TextInput,
  Toggle,
  lines,
  onePerLine,
} from "../form";
import type { SettingsForm } from "../form";
import { NTP_SERVERS } from "./form";
import type { MgmtForm, NtpForm, SnmpForm, SyslogForm, TopForm } from "./form";
import { randomPassword } from "./randomPassword";

/** A secret typed in the editor; it is sent only when set, and never shown back. */
interface Secret {
  value: string;
  set: (v: string) => void;
}

export function CountryTimezone({
  top,
  d,
}: {
  top: SettingsForm<TopForm>;
  d: SiteSettings;
}) {
  const { form: f, set } = top;
  // The site's own zone stays among the choices when the list leaves it out
  // (a link such as US/Pacific, or Etc/GMT+5), so it can be picked again.
  const zones =
    d.timezone === null || d.timezones.includes(d.timezone)
      ? d.timezones
      : [...d.timezones, d.timezone].sort();
  return (
    <>
      <Row label="Country" hint="decides the legal channels and power">
        <Select
          value={f.country}
          onChange={(v) => set("country", v)}
          stray={(c) => `(code ${c})`}
          options={d.countries.map((c) => [c.code, c.name] as const)}
        />
      </Row>
      <Row label="Time zone" hint="for schedules and the APs' clocks">
        <Select
          value={f.timezone}
          onChange={(v) => set("timezone", v)}
          options={zones.map((z) => [z, z] as const)}
        />
      </Row>
    </>
  );
}

export function ApDefaults({ mgmt }: { mgmt: SettingsForm<MgmtForm> }) {
  return (
    <Row label="AP defaults" hint="each AP can override these">
      <Toggle {...mgmt.bind("led_enabled")} label="LEDs on" />
      <Toggle {...mgmt.bind("outdoor_mode_enabled")} label="Outdoor mode" />
    </Row>
  );
}

export function Ssh({
  mgmt,
  d,
  password,
}: {
  mgmt: SettingsForm<MgmtForm>;
  d: SiteSettings;
  password: Secret;
}) {
  const { bind } = mgmt;
  const rules = "12+ characters with upper, lower, digit and symbol, or 20+";
  return (
    <details>
      <summary>SSH access to the APs</summary>
      <Row label="SSH">
        <Toggle {...bind("x_ssh_enabled")} label="Enabled" />
        <Toggle
          {...bind("x_ssh_auth_password_enabled")}
          label="Password logins"
        />
      </Row>
      <Row label="User name">
        <TextInput {...bind("x_ssh_username")} maxLength={30} />
      </Row>
      <Row
        label="Password"
        hint={
          d.mgmt.has_ssh_password ? `leave empty to keep it; ${rules}` : rules
        }
      >
        <TextInput
          className="search mono"
          autoComplete="off"
          placeholder={d.mgmt.has_ssh_password ? "unchanged" : ""}
          size={30}
          value={password.value}
          onChange={password.set}
        />
        <button
          className="btn small"
          onClick={() => password.set(randomPassword())}
        >
          Generate
        </button>
        {password.value && (
          <span className="muted small">
            Store it in your password manager before saving.
          </span>
        )}
      </Row>
      <Row label="Public keys" hint="one OpenSSH key per line (RSA or Ed25519)">
        <ListInput
          {...bind("x_ssh_keys")}
          rows={3}
          parse={lines}
          format={onePerLine}
        />
      </Row>
    </details>
  );
}

export function Logging({
  syslog,
  d,
}: {
  syslog: SettingsForm<SyslogForm>;
  d: SiteSettings;
}) {
  const { form: f, bind } = syslog;
  const port = d.syslog_port;
  return (
    <details>
      <summary>Logging</summary>
      <Row
        label="Syslog"
        hint={
          port === null
            ? "to apctl needs its syslog listener (--syslog-listen)"
            : `to apctl: APs send to its listener on port ${port}`
        }
      >
        <Select
          {...bind("mode")}
          options={[
            ["off", "Off"],
            ["controller", "To apctl"],
            ["server", "To a syslog server"],
          ]}
        />
        {f.mode === "server" && (
          <>
            <TextInput
              {...bind("ip")}
              className="search mono"
              placeholder="server"
              aria-label="Syslog server"
            />
            <NumberInput
              {...bind("port")}
              aria-label="Syslog server port"
              fallback={514}
              min={1}
              max={65535}
            />
          </>
        )}
        {f.mode !== "off" && <Toggle {...bind("debug")} label="Debug level" />}
      </Row>
      {f.mode === "controller" && port === null && (
        <div className="form-warn">
          apctl runs without its syslog listener (--syslog-listen), so nothing
          receives the logs the APs send it.
        </div>
      )}
      {f.mode === "server" && (
        <Row label="Netconsole" hint="kernel messages, for crash debugging">
          <Toggle {...bind("netconsole_enabled")} label="Enabled" />
          {f.netconsole_enabled && (
            <>
              <TextInput
                {...bind("netconsole_host")}
                className="search mono"
                placeholder="host"
                aria-label="Netconsole host"
              />
              <NumberInput
                {...bind("netconsole_port")}
                aria-label="Netconsole port"
                fallback={514}
                min={1}
                max={65535}
              />
            </>
          )}
        </Row>
      )}
    </details>
  );
}

export function Snmp({
  snmp,
  d,
  v3password,
}: {
  snmp: SettingsForm<SnmpForm>;
  d: SiteSettings;
  v3password: Secret;
}) {
  const { form: f, bind } = snmp;
  return (
    <details>
      <summary>SNMP</summary>
      <Row label="SNMP v1/v2c">
        <Toggle {...bind("enabled")} label="Enabled" />
        {f.enabled && (
          <TextInput
            {...bind("community")}
            className="search mono"
            placeholder="community"
            aria-label="Community"
          />
        )}
      </Row>
      <Row label="SNMPv3" hint="on firmware that supports it">
        <Toggle {...bind("enabledV3")} label="Enabled" />
        {f.enabledV3 && (
          <>
            <TextInput
              {...bind("username")}
              className="search mono"
              placeholder="user name"
              maxLength={30}
              aria-label="SNMPv3 user name"
            />
            <TextInput
              className="search mono"
              autoComplete="off"
              maxLength={32}
              placeholder={
                d.snmp.has_v3_password
                  ? "password unchanged"
                  : "password (8 to 32)"
              }
              aria-label="SNMPv3 password"
              value={v3password.value}
              onChange={v3password.set}
            />
          </>
        )}
      </Row>
    </details>
  );
}

export function Ntp({ ntp }: { ntp: SettingsForm<NtpForm> }) {
  const { form: f, bind } = ntp;
  return (
    <details>
      <summary>Time servers</summary>
      <Row label="NTP">
        <Select
          {...bind("setting_preference")}
          options={[
            ["auto", "Automatic"],
            ["manual", "These servers"],
          ]}
        />
        {f.setting_preference === "manual" &&
          NTP_SERVERS.map((k, i) => (
            <TextInput
              key={k}
              {...bind(k)}
              className="search mono"
              placeholder={i === 0 ? "pool.ntp.org" : ""}
              aria-label={`NTP server ${i + 1}`}
            />
          ))}
      </Row>
    </details>
  );
}
