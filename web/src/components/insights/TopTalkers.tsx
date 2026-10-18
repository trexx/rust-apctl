import { Link } from "react-router";
import { useSiteTop } from "../../api";
import { bytes, spanText } from "../../format";
import { useTimeSpan } from "../Chart";
import { QueryState } from "../common";

function TopList({
  title,
  items,
  link,
}: {
  title: string;
  items: {
    mac: string;
    name: string | null;
    sub?: string | null;
    total: number;
  }[];
  link: string;
}) {
  return (
    <div className="top-list">
      <div className="muted small">{title}</div>
      <div className="chips">
        {items.map((i) => (
          <Link
            key={i.mac}
            to={`/${link}/${i.mac}`}
            className="chip"
            title={i.sub ?? undefined}
          >
            <span className="chip-name">{i.name ?? i.mac}</span>
            <span className="muted small">{bytes(i.total)}</span>
          </Link>
        ))}
        {items.length === 0 && (
          <span className="muted small">No traffic in this range</span>
        )}
      </div>
    </div>
  );
}

const total = (x: { download_bytes: number; upload_bytes: number }) =>
  x.download_bytes + x.upload_bytes;

export function TopTalkers() {
  const [span] = useTimeSpan(86400);
  const t = useSiteTop(span);
  return (
    <QueryState q={t} panel>
      {(data) => (
        <div className="panel">
          <div className="panel-head">
            <b>Top traffic</b>
            <span className="muted small">{spanText(span)}</span>
          </div>
          <div className="top-split">
            <TopList
              title="Access points"
              link="devices"
              items={data.aps.map((a) => ({
                mac: a.mac,
                name: a.name,
                total: total(a),
              }))}
            />
            <TopList
              title="Clients"
              link="clients"
              items={data.clients.slice(0, 15).map((c) => ({
                mac: c.mac,
                name: c.name,
                sub: c.vendor,
                total: total(c),
              }))}
            />
          </div>
        </div>
      )}
    </QueryState>
  );
}
