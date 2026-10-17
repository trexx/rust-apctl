import type { UserGroup } from "../../api";
import { speed } from "../../format";

/**
 * The `<option>`s of a speed-limit drop-down: every limit (user group) but the
 * default one, which means no limit and is the caller's own first option.
 */
export const speedLimitOptions = (groups: UserGroup[]) =>
  groups
    .filter((g) => !g.default)
    .map((g) => (
      <option key={g.id} value={g.id}>
        {g.name} (down {speed(g.qos_rate_max_down)}, up{" "}
        {speed(g.qos_rate_max_up)})
      </option>
    ));
