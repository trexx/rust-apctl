import { createContext, useContext, useId, useState } from "react";
import type {
  ChangeEvent,
  Dispatch,
  InputHTMLAttributes,
  ReactNode,
  SetStateAction,
} from "react";

/** A settings patch, as sent to the server. */
export type Fields = Record<string, unknown>;

/**
 * The fields of `form` that differ from `original`. An undefined field is
 * left out: JSON drops it, so it would look like a change that sends nothing.
 */
export function changed<F extends object>(original: F, form: F): Partial<F> {
  const out: Partial<F> = {};
  for (const k of Object.keys(form) as (keyof F)[]) {
    const v = form[k];
    if (v !== undefined && JSON.stringify(v) !== JSON.stringify(original[k]))
      out[k] = v;
  }
  return out;
}

type Setter<F> = <K extends keyof F>(k: K, v: F[K]) => void;

/** `{value, onChange}` for one field of a form, to spread into an input. */
export const binder =
  <F,>(form: F, set: Setter<F>) =>
  <K extends keyof F>(k: K) => ({
    value: form[k],
    onChange: (v: F[K]) => set(k, v),
  });

export interface SettingsForm<F> {
  /** What the editor started from; the patch is the difference to it. */
  original: F;
  form: F;
  setForm: Dispatch<SetStateAction<F>>;
  set: Setter<F>;
  bind: ReturnType<typeof binder<F>>;
  /** The fields that differ from `original`. */
  changes: () => Partial<F>;
}

/**
 * An editor's form and its baseline. The baseline is taken once, when the
 * editor opens: a background refetch must not move it, or the patch would no
 * longer be what the user changed.
 */
export function useSettingsForm<F extends object>(
  initial: () => F,
): SettingsForm<F> {
  const [original] = useState(initial);
  const [form, setForm] = useState(original);
  const set: Setter<F> = (k, v) => setForm((f) => ({ ...f, [k]: v }));
  return {
    original,
    form,
    setForm,
    set,
    bind: binder(form, set),
    changes: () => changed(original, form),
  };
}

/** The ids of the enclosing `Row`'s label and hint, which name the controls in it. */
const RowLabel = createContext<{ label?: string; hint?: string }>({});

/** `aria-labelledby` / `aria-describedby` for a control: its `Row`'s label and hint. */
const useRowLabel = () => {
  const { label, hint } = useContext(RowLabel);
  return { "aria-labelledby": label, "aria-describedby": hint };
};

/**
 * A labelled form row. Its label names the group, and the `Select`,
 * `NumberInput`, `ListInput` and `TextInput` in it (screen readers announce
 * it).
 */
export function Row({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: ReactNode;
}) {
  const id = useId();
  const ids = { label: `${id}-label`, hint: hint ? `${id}-hint` : undefined };
  return (
    <div
      className="form-row"
      role="group"
      aria-labelledby={ids.label}
      aria-describedby={ids.hint}
    >
      <div className="form-label">
        <span id={ids.label}>{label}</span>
        {hint && (
          <div className="muted small" id={ids.hint}>
            {hint}
          </div>
        )}
      </div>
      <div className="form-control">
        <RowLabel value={ids}>{children}</RowLabel>
      </div>
    </div>
  );
}

export function Toggle({
  value,
  onChange,
  label,
  disabled,
}: {
  value: boolean | null | undefined;
  onChange: (v: boolean) => void;
  label: string;
  disabled?: boolean;
}) {
  return (
    <label className="check">
      <input
        type="checkbox"
        checked={value === true}
        disabled={disabled}
        onChange={(e) => onChange(e.target.checked)}
      />
      {label}
    </label>
  );
}

/** One choice of a `Select`: its value, its label and whether it is disabled. */
export type Option<T> = readonly [
  value: T,
  label: ReactNode,
  disabled?: boolean,
];

/** A drop-down over typed values; `fallback` is shown while the value is unset. */
export function Select<T extends string | number>({
  value,
  fallback,
  options,
  onChange,
  disabled,
}: {
  value: T | null | undefined;
  fallback?: T;
  options: readonly Option<T>[];
  onChange: (v: T) => void;
  disabled?: boolean;
}) {
  const named = useRowLabel();
  return (
    <select
      {...named}
      value={String(value ?? fallback ?? "")}
      disabled={disabled}
      onChange={(e) => {
        const o = options.find(([v]) => String(v) === e.target.value);
        if (o) onChange(o[0]);
      }}
    >
      {options.map(([v, label, off]) => (
        <option key={v} value={v} disabled={off}>
          {label}
        </option>
      ))}
    </select>
  );
}

/**
 * A whole number between `min` and `max`. The text is kept as typed; the form
 * gets the clamped number, and an empty field leaves the form's value as it
 * was (the field shows it again on leaving).
 */
export function NumberInput({
  value,
  fallback,
  min,
  max,
  onChange,
  disabled,
}: {
  value: number | null | undefined;
  fallback: number;
  min: number;
  max: number;
  onChange: (v: number) => void;
  disabled?: boolean;
}) {
  const named = useRowLabel();
  const shown = value ?? fallback;
  const [text, setText] = useState(String(shown));
  const [last, setLast] = useState(shown);
  // Another field setting this one (Force Wi-Fi 4, the DTIM lock) replaces the text.
  if (!Object.is(shown, last)) {
    setLast(shown);
    setText(String(shown));
  }
  return (
    <input
      {...named}
      type="number"
      className="search num-input"
      min={min}
      max={max}
      disabled={disabled}
      value={text}
      onChange={(e) => {
        setText(e.target.value);
        const n = Math.round(Number(e.target.value));
        if (e.target.value.trim() === "" || !Number.isFinite(n)) return;
        const v = Math.min(max, Math.max(min, n));
        setLast(v);
        onChange(v);
      }}
      onBlur={() => setText(String(shown))}
    />
  );
}

/**
 * A text field (class "search" unless given), named by its `Row`'s label, or
 * by its own `aria-label` where a row holds several; `onChange` gets the text.
 */
export function TextInput({
  value,
  onChange,
  className,
  ...props
}: Omit<InputHTMLAttributes<HTMLInputElement>, "value" | "onChange"> & {
  value: string | null | undefined;
  onChange: (v: string) => void;
}) {
  const named = useRowLabel();
  return (
    <input
      aria-labelledby={
        props["aria-label"] ? undefined : named["aria-labelledby"]
      }
      aria-describedby={named["aria-describedby"]}
      className={className ?? "search"}
      {...props}
      value={value ?? ""}
      onChange={(e) => onChange(e.target.value)}
    />
  );
}

/**
 * A time of day, "HH:MM". The text is kept as typed; the form only gets a
 * complete time, so a cleared field leaves the time as it was (shown again on
 * leaving) instead of becoming midnight.
 */
export function TimeInput({
  value,
  onChange,
  disabled,
}: {
  value: string;
  onChange: (t: string) => void;
  disabled?: boolean;
}) {
  const [text, setText] = useState(value);
  const [last, setLast] = useState(value);
  if (value !== last) {
    setLast(value);
    setText(value);
  }
  return (
    <input
      type="time"
      className="search time-input"
      value={text}
      disabled={disabled}
      onChange={(e) => {
        setText(e.target.value);
        if (!e.target.value) return;
        setLast(e.target.value);
        onChange(e.target.value);
      }}
      onBlur={() => setText(value)}
    />
  );
}

/** Splits on white space, commas and semicolons: MAC addresses, servers. */
export const words = (text: string) =>
  text
    .split(/[\s,;]+/)
    .map((m) => m.trim())
    .filter(Boolean);

/** The non-empty lines, trimmed. */
export const lines = (text: string) =>
  text
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean);

export const onePerLine = (v: string[]) => v.join("\n");

/**
 * A list edited as text: a textarea with `rows`, else a one-line input. The
 * text is kept as typed (so Enter and spaces work), and the form gets
 * `parse(text)` on every change.
 */
export function ListInput<T>({
  value,
  parse,
  format,
  onChange,
  rows,
  placeholder,
}: {
  value: T[] | null | undefined;
  parse: (text: string) => T[];
  format: (v: T[]) => string;
  onChange: (v: T[]) => void;
  rows?: number;
  placeholder?: string;
}) {
  const named = useRowLabel();
  const [text, setText] = useState(() => format(value ?? []));
  const props = {
    ...named,
    className: "search mono",
    placeholder,
    value: text,
    onChange: (e: ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => {
      setText(e.target.value);
      onChange(parse(e.target.value));
    },
  };
  return rows ? <textarea rows={rows} {...props} /> : <input {...props} />;
}
