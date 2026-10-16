import { useState } from "react";
import { useMe, useSiteSettings } from "../../../api";
import type { SiteSettings } from "../../../api";
import { ErrorNote, Loading } from "../../common";
import { useSettingsForm } from "../form";
import type { Fields } from "../form";
import { EditorShell } from "../Review";
import { mgmtForm, ntpForm, snmpForm, syslogForm, topForm } from "./form";
import {
  ApDefaults,
  CountryTimezone,
  Logging,
  Ntp,
  Snmp,
  Ssh,
} from "./sections";

function SiteEditor({ d, onClose }: { d: SiteSettings; onClose: () => void }) {
  const top = useSettingsForm(() => topForm(d));
  const mgmt = useSettingsForm(() => mgmtForm(d));
  const syslog = useSettingsForm(() => syslogForm(d));
  const snmp = useSettingsForm(() => snmpForm(d));
  const ntp = useSettingsForm(() => ntpForm(d));
  const [password, setPassword] = useState("");
  const [v3password, setV3password] = useState("");
  const patch: Fields = top.changes();
  const m: Fields = mgmt.changes();
  if (password) m.x_ssh_password = password;
  if (Object.keys(m).length) patch.mgmt = m;
  const r = syslog.changes();
  if (Object.keys(r).length) patch.rsyslogd = r;
  const sn: Fields = snmp.changes();
  if (v3password) sn.x_password = v3password;
  if (Object.keys(sn).length) patch.snmp = sn;
  // Manual servers are sent as a whole list.
  if (Object.keys(ntp.changes()).length)
    patch.ntp =
      ntp.form.setting_preference === "manual"
        ? ntp.form
        : { setting_preference: ntp.form.setting_preference };
  return (
    <EditorShell
      target={{ kind: "site" }}
      active={d.active}
      patch={patch}
      onClose={onClose}
    >
      <CountryTimezone top={top} d={d} />
      <ApDefaults mgmt={mgmt} />
      <Ssh mgmt={mgmt} d={d} password={{ value: password, set: setPassword }} />
      <Logging syslog={syslog} />
      <Snmp
        snmp={snmp}
        d={d}
        v3password={{ value: v3password, set: setV3password }}
      />
      <Ntp ntp={ntp} />
    </EditorShell>
  );
}

/** Site-wide device settings: LED, outdoor, SSH, syslog, NTP, country, time zone. */
export function SiteSettingsPanel() {
  const q = useSiteSettings();
  const readOnly = useMe().data?.read_only ?? false;
  const [editing, setEditing] = useState(false);
  if (q.isLoading) return <Loading />;
  if (q.error) return <ErrorNote error={q.error} />;
  if (!q.data) return null;
  const d = q.data;
  const country = d.countries.find((c) => c.code === d.country)?.name;
  return (
    <div className="panel">
      <div className="panel-head">
        <b>Site settings</b>
        <span className="muted small">
          {editing
            ? ""
            : `${country ?? `country ${d.country ?? "?"}`}, ${d.timezone ?? "UTC"}, SSH user ${d.mgmt.x_ssh_username ?? "ubnt"}`}
        </span>
        <span className="spacer" />
        {!editing && !readOnly && (
          <button className="btn small" onClick={() => setEditing(true)}>
            Edit
          </button>
        )}
      </div>
      {editing && <SiteEditor d={d} onClose={() => setEditing(false)} />}
    </div>
  );
}
