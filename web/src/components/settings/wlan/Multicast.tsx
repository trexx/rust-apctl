import { ListInput, Row, Select, Toggle, onePerLine, words } from "../form";
import type { WlanSection } from "./form";
import { Unsupported } from "./Unsupported";

export function Multicast({ w, list }: WlanSection) {
  const { form: f, bind } = w;
  return (
    <details>
      <summary>Multicast and broadcast</summary>
      <Row
        label="Multicast enhancement"
        hint="send multicast to each client directly"
      >
        <Toggle {...bind("mcastenhance_enabled")} label="Enabled" />
      </Row>
      <Row label="Multicast and broadcast control">
        <Select
          {...bind("multicast_suppressor_mode")}
          fallback="off"
          options={[
            ["off", "Off"],
            ["conservative", "Conservative"],
            ["aggressive", "Aggressive (allow list only)"],
          ]}
        />
        <Unsupported
          feature="multicast_suppression"
          on={(f.multicast_suppressor_mode ?? "off") !== "off"}
          aps={f.aps}
          list={list}
        />
      </Row>
      {f.multicast_suppressor_mode === "aggressive" && (
        <Row label="Allowed senders" hint="MAC addresses, one per line">
          <ListInput
            {...bind("bc_filter_list")}
            rows={4}
            parse={words}
            format={onePerLine}
          />
        </Row>
      )}
      <Row label="Proxy ARP">
        <Toggle
          {...bind("proxy_arp")}
          disabled={f.enhanced_iot === true}
          label="Enabled"
        />
      </Row>
    </details>
  );
}
