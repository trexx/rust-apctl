import { useState } from "react";
import type { ReactNode } from "react";

/**
 * A settings section edited in place: its title and a one-line summary, and
 * (unless `readOnly`) an Edit button that opens `editor` in the summary's
 * place; the editor closes itself with the function it is given.
 */
export function EditPanel({
  title,
  summary,
  readOnly,
  editor,
}: {
  title: string;
  summary: string;
  readOnly?: boolean;
  editor: (onClose: () => void) => ReactNode;
}) {
  const [editing, setEditing] = useState(false);
  return (
    <div className="panel">
      <div className="panel-head">
        <b>{title}</b>
        <span className="muted small">{editing ? "" : summary}</span>
        <span className="spacer" />
        {!editing && !readOnly && (
          <button className="btn small" onClick={() => setEditing(true)}>
            Edit
          </button>
        )}
      </div>
      {editing && editor(() => setEditing(false))}
    </div>
  );
}
