import { useState } from "react";
import type { ReactNode } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { changeSettings, keys } from "../../api";
import type { SettingsPreview, SettingsTarget } from "../../api";
import { ChangeGroups, summarise } from "../ConfigDiff";
import { Loading } from "../common";
import type { Fields } from "./form";

/**
 * Review, then save: shows what each AP's config would become before the
 * change is saved. Saving needs active mode.
 */
export function Review({
  target,
  patch,
  active,
  onBack,
  onSaved,
}: {
  target: SettingsTarget;
  patch: Fields;
  active: boolean;
  onBack: () => void;
  onSaved: () => void;
}) {
  const qc = useQueryClient();
  // The preview is asked for once, when the review opens, and forgotten when it closes.
  const preview = useQuery({
    queryKey: keys.settingsPreview(target, patch),
    queryFn: () => changeSettings<SettingsPreview>(target, patch, false),
    gcTime: 0,
    staleTime: Infinity,
    refetchOnWindowFocus: false,
    retry: false,
  });
  const save = useMutation({
    mutationFn: () => changeSettings(target, patch, true),
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: keys.settings() });
      void qc.invalidateQueries({ queryKey: keys.wlans() });
      void qc.invalidateQueries({ queryKey: keys.events() });
      onSaved();
    },
  });
  const error = preview.error ?? save.error;
  const p = preview.data;
  const busy = save.isPending;
  return (
    <div className="review">
      {error ? (
        <div className="error small">{error.message}</div>
      ) : !p ? (
        <Loading />
      ) : (
        <>
          <div className="small">
            <b>{p.what}</b>
          </div>
          {p.aps.map((a) => {
            const { changes, groups } = summarise(a);
            return (
              <div key={a.mac} className="cfg-entry">
                <div className="cfg-head">
                  <b>{a.name ?? a.mac}</b>
                  <span className="muted small">
                    {a.error
                      ? `cannot render its config: ${a.error}`
                      : changes.length === 0
                        ? "no change to its config"
                        : `${changes.length} config line${changes.length === 1 ? "" : "s"} change`}
                  </span>
                </div>
                {changes.length > 0 && <ChangeGroups groups={groups} />}
              </div>
            );
          })}
          {p.aps.length === 0 && (
            <div className="muted small">
              No AP has reported yet, so there is nothing to compare.
            </div>
          )}
        </>
      )}
      <div className="actions-row">
        <button className="btn" onClick={onBack} disabled={busy}>
          Back
        </button>
        <button
          className="btn primary"
          disabled={!active || busy || !!error || !p}
          onClick={() => save.mutate()}
        >
          Save and send to the APs
        </button>
        {!active && (
          <span className="muted small">
            Saving works after the cutover: in shadow mode the settings belong
            to your current controller.
          </span>
        )}
      </div>
    </div>
  );
}

/**
 * What every settings editor shares: the form, then Cancel and Review below
 * it; Review swaps the form for the review of `patch` until Back.
 */
export function EditorShell({
  target,
  active,
  patch,
  invalid,
  onClose,
  children,
}: {
  target: SettingsTarget;
  active: boolean;
  patch: Fields;
  /** Review stays off while the form can't be sent. */
  invalid?: boolean;
  onClose: () => void;
  children: ReactNode;
}) {
  const [review, setReview] = useState<Fields | null>(null);
  if (review)
    return (
      <Review
        target={target}
        patch={review}
        active={active}
        onBack={() => setReview(null)}
        onSaved={onClose}
      />
    );
  const nothing = Object.keys(patch).length === 0;
  return (
    <div className="settings-form">
      {children}
      <div className="actions-row">
        <button className="btn" onClick={onClose}>
          Cancel
        </button>
        <button
          className="btn primary"
          disabled={nothing || invalid}
          onClick={() => setReview(patch)}
        >
          {nothing ? "No changes" : "Review changes"}
        </button>
      </div>
    </div>
  );
}
