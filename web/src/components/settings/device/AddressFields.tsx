import type { ConfigNetwork } from "../../../api";
import { TextField } from "../../common";
import { Select } from "../form";

/** The AP's own address; static needs care, as a wrong one cuts the AP off. */
export function AddressFields({
  value,
  onChange,
}: {
  value: ConfigNetwork;
  onChange: (v: ConfigNetwork) => void;
}) {
  const field = (
    k: Exclude<keyof ConfigNetwork, "type">,
    label: string,
    placeholder?: string,
  ) => (
    <label className="small">
      {label}{" "}
      <TextField
        className="search mono"
        placeholder={placeholder}
        value={value[k]}
        onChange={(v) => onChange({ ...value, [k]: v })}
      />
    </label>
  );
  return (
    <>
      <Select
        value={value.type}
        fallback="dhcp"
        onChange={(type) => onChange({ ...value, type })}
        options={[
          ["dhcp", "DHCP"],
          ["static", "Static"],
        ]}
      />
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
