import type { UserGroup } from "../../api";
import { speed } from "../../format";
import type { Option } from "./form";

/**
 * The options of a speed-limit `Select`: every limit (user group) but the
 * default one, which means no limit and is the caller's own first option.
 */
export const speedLimitOptions = (groups: UserGroup[]): Option<string>[] =>
  groups.filter((g) => !g.default).map((g) => [g.id, speedLimitLabel(g)]);

/** A limit's name and rates, as its option shows it. */
export const speedLimitLabel = (g: UserGroup) =>
  `${g.name} (down ${speed(g.qos_rate_max_down)}, up ${speed(g.qos_rate_max_up)})`;
