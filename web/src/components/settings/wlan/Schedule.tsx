import { useState } from "react";
import { hhmm as time, minutesOf } from "../../../format";
import { TextInput, TimeInput, Toggle, toggled } from "../form";
import type { Blackout } from "../../../api";

const WEEK = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"] as const;
const WEEK_LABEL: Record<(typeof WEEK)[number], string> = {
  sun: "Su",
  mon: "Mo",
  tue: "Tu",
  wed: "We",
  thu: "Th",
  fri: "Fr",
  sat: "Sa",
};

/** Blackout periods: when the SSID is off. An end at or before the start runs past midnight. */
export function ScheduleEditor({
  value,
  onChange,
}: {
  value: Blackout[] | null | undefined;
  onChange: (v: Blackout[]) => void;
}) {
  const list = Array.isArray(value) ? value : [];
  const update = (i: number, e: Partial<Blackout>) =>
    onChange(list.map((x, j) => (j === i ? { ...x, ...e } : x)));
  // Open at first when there are periods; afterwards the user's choice (a
  // live `open` would snap shut on removing the last one).
  const [open] = useState(list.length > 0);
  return (
    <details open={open}>
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
              <TextInput
                placeholder="Name (optional)"
                aria-label="Name of the off period"
                value={e.name}
                onChange={(name) => update(i, { name })}
              />
            </div>
            <div className="form-control">
              {WEEK.map((d) => (
                <Toggle
                  key={d}
                  value={e.start_days_of_week.includes(d)}
                  onChange={(on) =>
                    update(i, {
                      start_days_of_week: toggled(e.start_days_of_week, d, on),
                    })
                  }
                  label={WEEK_LABEL[d]}
                />
              ))}
              <label className="small">
                off from{" "}
                <TimeInput
                  value={time(start)}
                  onChange={(t) => {
                    const s = minutesOf(t);
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
                <TimeInput
                  value={time(end)}
                  onChange={(t) =>
                    update(i, {
                      duration_minutes:
                        (minutesOf(t) - start + 1440) % 1440 || 1440,
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
