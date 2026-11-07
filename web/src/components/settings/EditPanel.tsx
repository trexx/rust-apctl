import { useState } from "react";
import type { ReactNode } from "react";
import { useImported } from "../../api";
import { QueryNote } from "../common";

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

/**
 * A settings section before any settings are imported: its title, and where
 * to import them (the server has none to show, and answers 409).
 */
function NotImported({ title }: { title: string }) {
  return (
    <div className="panel">
      <div className="panel-head">
        <b>{title}</b>
        <span className="muted small">
          no settings imported: import them on the Settings page
        </span>
      </div>
    </div>
  );
}

/**
 * `useImported`, for a section whose data the server has only after an
 * import: `gate` is what the section shows until then (the state loading, or
 * NotImported with `title`), null once they are.
 */
export function useImportGate(title: string): {
  imported: boolean;
  gate: ReactNode;
} {
  const { state, imported } = useImported();
  const gate = !state.data ? (
    <QueryNote q={state} panel />
  ) : !imported ? (
    <NotImported title={title} />
  ) : null;
  return { imported, gate };
}
