import type { SiteSettings, SshKey } from "../../../api";

// Each group of site settings as its form holds it; each is patched as its own object.

export type TopForm = { country: number | null; timezone: string };

export const topForm = (d: SiteSettings): TopForm => ({
  country: d.country,
  timezone: d.timezone ?? "UTC",
});

export type MgmtForm = {
  led_enabled: boolean;
  outdoor_mode_enabled: boolean;
  x_ssh_enabled: boolean;
  x_ssh_username: string;
  x_ssh_auth_password_enabled: boolean;
  x_ssh_bind_wildcard: boolean;
  /** One OpenSSH key line each. */
  x_ssh_keys: string[];
};

const keyLine = (k: SshKey) =>
  [k.type, k.key, k.comment].filter(Boolean).join(" ");

export const mgmtForm = ({ mgmt }: SiteSettings): MgmtForm => ({
  led_enabled: mgmt.led_enabled ?? true,
  outdoor_mode_enabled: mgmt.outdoor_mode_enabled ?? false,
  x_ssh_enabled: mgmt.x_ssh_enabled ?? true,
  // Unset, the APs are given "ubnt", as the summary says.
  x_ssh_username: mgmt.x_ssh_username ?? "ubnt",
  x_ssh_auth_password_enabled: mgmt.x_ssh_auth_password_enabled ?? true,
  x_ssh_bind_wildcard: mgmt.x_ssh_bind_wildcard ?? false,
  x_ssh_keys: (mgmt.x_ssh_keys ?? []).map(keyLine),
});

export type SyslogForm = {
  mode: SiteSettings["rsyslogd"]["mode"];
  ip: string;
  port: number;
  debug: boolean;
  netconsole_enabled: boolean;
  netconsole_host: string;
  netconsole_port: number;
};

export const syslogForm = ({ rsyslogd: r }: SiteSettings): SyslogForm => ({
  mode: r.mode,
  ip: r.ip ?? "",
  port: Number(r.port ?? 514),
  debug: r.debug ?? false,
  netconsole_enabled: r.netconsole_enabled ?? false,
  netconsole_host: r.netconsole_host ?? "",
  netconsole_port: Number(r.netconsole_port ?? 514),
});

export type SnmpForm = {
  enabled: boolean;
  community: string;
  enabledV3: boolean;
  username: string;
};

export const snmpForm = ({ snmp }: SiteSettings): SnmpForm => ({
  enabled: snmp.enabled ?? false,
  // Read-only mode leaves the community out: no default in its place.
  community: snmp.community ?? (snmp.enabled ? "" : "public"),
  enabledV3: snmp.enabledV3 ?? false,
  username: snmp.username ?? "",
});

export const NTP_SERVERS = [
  "ntp_server_1",
  "ntp_server_2",
  "ntp_server_3",
  "ntp_server_4",
] as const;

export type NtpForm = {
  setting_preference: "auto" | "manual";
} & Record<(typeof NTP_SERVERS)[number], string>;

export const ntpForm = ({ ntp }: SiteSettings): NtpForm => ({
  setting_preference: ntp.setting_preference ?? "auto",
  ntp_server_1: ntp.ntp_server_1 ?? "",
  ntp_server_2: ntp.ntp_server_2 ?? "",
  ntp_server_3: ntp.ntp_server_3 ?? "",
  ntp_server_4: ntp.ntp_server_4 ?? "",
});
