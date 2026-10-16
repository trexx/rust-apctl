import { Fragment, useState } from "react";
import type { ReactNode } from "react";
import { Review } from "./Review";

/**
 * A panel listing things (SSIDs, speed limits) that are added, edited and
 * deleted one at a time: the table, or the one editor, or the review of a
 * deletion.
 */
export function ListPanel<T extends { id: string }>({
  title,
  note,
  add,
  kind,
  items,
  active,
  readOnly,
  gone,
  editor,
  rows,
}: {
  title: string;
  note: ReactNode;
  /** The label of the button that adds one. */
  add: string;
  kind: "wlan" | "usergroup";
  items: T[];
  active: boolean;
  readOnly: boolean;
  /** Said when the one being edited was deleted meanwhile. */
  gone: string;
  /** The editor for `item`, or for a new one when it is null. */
  editor: (item: T | null, onClose: () => void) => ReactNode;
  /** The table rows, with the actions their buttons take. */
  rows: (edit: (x: T) => void, remove: (x: T) => void) => ReactNode;
}) {
  const [editing, setEditing] = useState<string | "new" | null>(null);
  const [removing, setRemoving] = useState<T | null>(null);
  const current = items.find((x) => x.id === editing) ?? null;
  const close = () => setEditing(null);
  let body: ReactNode;
  if (removing)
    body = (
      <Review
        target={{ kind, id: removing.id, remove: true }}
        patch={{}}
        active={active}
        onBack={() => setRemoving(null)}
        onSaved={() => setRemoving(null)}
      />
    );
  else if (editing === "new" || current)
    body = <Fragment key={editing}>{editor(current, close)}</Fragment>;
  else if (editing !== null)
    // Saving an editor whose item is gone would create it anew.
    body = (
      <div className="form-warn">
        {gone}{" "}
        <button className="btn small" onClick={close}>
          Close
        </button>
      </div>
    );
  else
    body = (
      <div className="table-wrap">
        <table className="table">
          <tbody>
            {rows(
              (x) => setEditing(x.id),
              (x) => setRemoving(x),
            )}
          </tbody>
        </table>
      </div>
    );
  return (
    <div className="panel">
      <div className="panel-head">
        <b>{title}</b>
        <span className="muted small">{note}</span>
        <span className="spacer" />
        {!readOnly && editing === null && !removing && (
          <button className="btn small" onClick={() => setEditing("new")}>
            {add}
          </button>
        )}
      </div>
      {body}
    </div>
  );
}
