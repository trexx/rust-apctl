import { useState } from "react";
import { useSiteActivity } from "../../api";
import { bitrate } from "../../format";
import {
  COLORS,
  Chart,
  RangePicker,
  SpanContext,
  ZoomContext,
  useTimeSpan,
} from "../Chart";
import { QueryState } from "../common";
import { BandPicker } from "./shared";

/** Site-wide Wi-Fi activity and airtime, the first thing on the overview. */
export function SiteActivity() {
  const [view, setView] = useState<"activity" | "airtime">("activity");
  const [range, setRange] = useTimeSpan(86400);
  const [band, setBand] = useState("all");
  const a = useSiteActivity(range, band);
  return (
    <ZoomContext.Provider value={(from, to) => setRange({ from, to })}>
      <SpanContext.Provider value={range}>
        <div className="panel">
          <div className="panel-head">
            <div className="segmented" role="group" aria-label="View">
              <button
                className={view === "activity" ? "active" : ""}
                onClick={() => setView("activity")}
              >
                Activity
              </button>
              <button
                className={view === "airtime" ? "active" : ""}
                onClick={() => setView("airtime")}
              >
                Airtime
              </button>
            </div>
            <BandPicker value={band} onChange={setBand} />
            <span className="spacer" />
            <RangePicker value={range} onChange={setRange} />
          </div>
          <QueryState q={a}>
            {({ activity, airtime }) =>
              view === "activity" ? (
                <>
                  <Chart
                    title="Wi-Fi traffic"
                    ts={activity.ts}
                    height={200}
                    format={(v) => bitrate(v / 8)}
                    formatRight={(v) => `${Math.round(v)}`}
                    series={[
                      {
                        label: "Download",
                        values: activity.download_bps,
                        color: COLORS.blue,
                        fill: true,
                      },
                      {
                        label: "Upload",
                        values: activity.upload_bps,
                        color: COLORS.purple,
                      },
                      {
                        label: "Clients",
                        values: activity.clients,
                        color: COLORS.green,
                        right: true,
                        dashed: true,
                      },
                    ]}
                  />
                  <Chart
                    title="TX retries and multicast"
                    ts={activity.ts}
                    height={120}
                    min={0}
                    format={(v) => `${v.toFixed(0)}%`}
                    series={[
                      {
                        label: "TX retries",
                        values: activity.tx_retry_pct,
                        color: COLORS.orange,
                      },
                      {
                        label: "Multicast + broadcast share",
                        values: activity.multicast_pct,
                        color: COLORS.teal,
                        dashed: true,
                      },
                    ]}
                  />
                </>
              ) : (
                <Chart
                  title="Airtime (channel utilisation, average across radios)"
                  ts={airtime.ts}
                  height={240}
                  min={0}
                  format={(v) => `${v.toFixed(0)}%`}
                  series={[
                    {
                      label: "Total",
                      values: airtime.total,
                      color: COLORS.orange,
                      fill: true,
                    },
                    {
                      label: "Own traffic",
                      values: airtime.own_traffic,
                      color: COLORS.blue,
                    },
                    {
                      label: "External interference",
                      values: airtime.external_interference,
                      color: COLORS.red,
                    },
                  ]}
                />
              )
            }
          </QueryState>
        </div>
      </SpanContext.Provider>
    </ZoomContext.Provider>
  );
}
