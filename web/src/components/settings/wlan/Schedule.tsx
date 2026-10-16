import { hhmm as time } from "../../../format";
import type { Blackout } from "../../../api";

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

const minutes = (t: string) => {
  const [h, m] = t.split(":").map(Number);
  return (h || 0) * 60 + (m || 0);
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
