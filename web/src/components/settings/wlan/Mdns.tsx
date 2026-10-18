import { useState } from "react";
import type { MdnsRule, WlanSettingsList } from "../../../api";
import { ListInput, Row, Select, Toggle, lines } from "../form";
import type { WlanSection } from "./form";
import { Unsupported } from "./Unsupported";

type CustomService = { address: string; name?: string };

/** Own service types, one per line: `_service._tcp.local` and an optional name. */
const parseServices = (text: string): CustomService[] =>
  lines(text).map((l) => {
    const [address = "", ...name] = l.split(/\s+/);
    return name.length ? { address, name: name.join(" ") } : { address };
  });

const formatServices = (v: CustomService[]) =>
  v
    .map((s) =>
      s.name && s.name !== s.address ? `${s.address} ${s.name}` : s.address,
    )
    .join("\n");

/**
 * A client-side id for each rule, so a rule keeps its row (and the text in
 * it) when one before it is removed. Never sent to the server.
 */
const ruleIds = new WeakMap<MdnsRule, number>();
let nextRuleId = 0;
function ruleId(r: MdnsRule): number {
  let id = ruleIds.get(r);
  if (id === undefined) {
    id = nextRuleId++;
    ruleIds.set(r, id);
  }
  return id;
}

/** Custom mDNS rules: where each applies and which services pass. */
function MdnsRules({
  value,
  onChange,
  list,
}: {
  value: MdnsRule[];
  onChange: (v: MdnsRule[]) => void;
  list: WlanSettingsList;
}) {
  const services = list.mdns_services ?? [];
  const update = (i: number, r: Partial<MdnsRule>) =>
    onChange(
      value.map((x, j) => {
        if (j !== i) return x;
        const next = { ...x, ...r };
        ruleIds.set(next, ruleId(x));
        return next;
      }),
    );
  return (
    <>
      {value.map((r, i) => {
        const codes = (r.predefined_services ?? []).map((s) => s.code);
        return (
          <div key={ruleId(r)} className="form-row">
            <div className="form-label">
              Rule {i + 1}
              <div>
                <button
                  className="btn small"
                  onClick={() => onChange(value.filter((_, j) => j !== i))}
                >
                  Remove
                </button>
              </div>
            </div>
            <div className="form-control">
              <label className="small">
                on{" "}
                <Select
                  aria-label={`Rule ${i + 1}: where`}
                  value={r.ap_scope_mode}
                  onChange={(v) =>
                    update(i, {
                      ap_scope_mode: v,
                      ap_macs:
                        v === "specific"
                          ? (r.ap_macs ?? list.aps.map((a) => a.mac))
                          : r.ap_macs,
                    })
                  }
                  options={[
                    ["all", "all APs"],
                    ["specific", "these APs"],
                    ...(r.ap_scope_mode === "group"
                      ? [["group", "AP groups (set elsewhere)"] as const]
                      : []),
                  ]}
                />
              </label>
              {r.ap_scope_mode === "specific" &&
                list.aps.map((a) => (
                  <Toggle
                    key={a.mac}
                    value={(r.ap_macs ?? []).includes(a.mac)}
                    onChange={(v) =>
                      update(i, {
                        ap_macs: v
                          ? [...(r.ap_macs ?? []), a.mac]
                          : (r.ap_macs ?? []).filter((m) => m !== a.mac),
                      })
                    }
                    label={a.name ?? a.mac}
                  />
                ))}
              <label className="small">
                pass{" "}
                <Select
                  aria-label={`Rule ${i + 1}: which services`}
                  value={r.services_mode}
                  onChange={(v) => update(i, { services_mode: v })}
                  options={[
                    ["all", "all services"],
                    ["specific", "these services"],
                    ["none", "no services"],
                  ]}
                />
              </label>
              {r.services_mode === "specific" && (
                <>
                  <div className="mdns-services">
                    {services.map((s) => (
                      <Toggle
                        key={s.code}
                        value={codes.includes(s.code)}
                        onChange={(v) =>
                          update(i, {
                            predefined_services: (v
                              ? [...codes, s.code]
                              : codes.filter((c) => c !== s.code)
                            ).map((code) => ({ code })),
                          })
                        }
                        label={s.name}
                      />
                    ))}
                  </div>
                  <ListInput
                    aria-label={`Rule ${i + 1}: other services`}
                    rows={2}
                    placeholder="other services, one per line: _myapp._tcp.local My app"
                    value={r.custom_services}
                    parse={parseServices}
                    format={formatServices}
                    onChange={(v) => update(i, { custom_services: v })}
                  />
                </>
              )}
              {(r.networkconf_ids ?? []).length > 0 && (
                <span className="muted small">
                  also bridges {(r.networkconf_ids ?? []).length} other
                  network(s), kept as they are
                </span>
              )}
            </div>
          </div>
        );
      })}
      <div className="actions-row">
        <button
          className="btn small"
          onClick={() =>
            onChange([...value, { ap_scope_mode: "all", services_mode: "all" }])
          }
        >
          Add rule
        </button>
      </div>
    </>
  );
}

export function Mdns({ w, list }: WlanSection) {
  const { form: f, setForm, set } = w;
  // Open at first for custom rules; afterwards the user's choice.
  const [open] = useState(f.mdns_proxy_mode === "custom");
  return (
    <details open={open}>
      <summary>mDNS</summary>
      <Row
        label="mDNS proxy"
        hint="which service announcements (AirPlay, Chromecast, printers…) reach this SSID's clients"
      >
        <Select
          value={f.mdns_proxy_mode}
          fallback="off"
          onChange={(v) =>
            setForm((x) => ({
              ...x,
              mdns_proxy_mode: v,
              // Custom starts with one rule that passes everything.
              ...(v === "custom" &&
                !x.mdns_proxy_custom?.length && {
                  mdns_proxy_custom: [
                    { ap_scope_mode: "all", services_mode: "all" },
                  ],
                }),
            }))
          }
          options={[
            ["off", "Off"],
            ["auto", "Automatic (standard services, this SSID's network)"],
            ["custom", "Custom rules"],
          ]}
        />
        <Unsupported
          feature="mdns_proxy"
          on={(f.mdns_proxy_mode ?? "off") !== "off"}
          aps={f.aps}
          list={list}
        />
      </Row>
      {f.mdns_proxy_mode === "custom" && (
        <MdnsRules
          value={f.mdns_proxy_custom ?? []}
          onChange={(v) => set("mdns_proxy_custom", v)}
          list={list}
        />
      )}
    </details>
  );
}
