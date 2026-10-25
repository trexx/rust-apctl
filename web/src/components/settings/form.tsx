import { createContext, useContext, useId, useState } from "react";
import type {
  ChangeEvent,
  Dispatch,
  InputHTMLAttributes,
  ReactNode,
  SetStateAction,
} from "react";
import { TextField, Toggle } from "../common";
import { canonicalMac } from "../../format";

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

/**
 * The name and description of a control in a `Row`: the row's label and hint.
 * A control given its own `aria-label` (one of several in a row) is named by
 * that instead, and still described by the hint.
 */
const useRowLabel = (own?: string) => {
  const { label, hint } = useContext(RowLabel);
  return {
    "aria-label": own,
    "aria-labelledby": own ? undefined : label,
    "aria-describedby": hint,
  };
};

/**
 * A labelled form row. Its label names the group, and the `Select`,
 * `NumberInput`, `ListInput` and `TextInput` in it (screen readers announce
 * it); where a row holds several of them, each but one gets its own
 * `aria-label`.
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

// In common.tsx, so the pages outside the settings needn't load this module.
export { Toggle };

/** One choice of a `Select`: its value, its label and whether it is disabled. */
export type Option<T> = readonly [
  value: T,
  label: ReactNode,
  disabled?: boolean,
];

/**
 * A drop-down over typed values; `fallback` is shown while the value is unset.
 * A value none of the options has is shown as it is, first (labelled by
 * `stray`, else as the value's text), not as the first option: the browser
 * would show that one, and picking it would change nothing.
 */
export function Select<T extends string | number>({
  value,
  fallback,
  options,
  onChange,
  stray,
  disabled,
  "aria-label": label,
}: {
  value: T | null | undefined;
  fallback?: T;
  options: readonly Option<T>[];
  onChange: (v: T) => void;
  /** The label of a value no option has (`""` when unset). */
  stray?: (v: string) => ReactNode;
  disabled?: boolean;
  "aria-label"?: string;
}) {
  const named = useRowLabel(label);
  const current = String(value ?? fallback ?? "");
  const known = options.some(([v]) => String(v) === current);
  return (
    <select
      {...named}
      value={current}
      disabled={disabled}
      onChange={(e) => {
        const o = options.find(([v]) => String(v) === e.target.value);
        if (o) onChange(o[0]);
      }}
    >
      {/* Shown only while it is the value: picking another option takes it away. */}
      {!known && (
        <option value={current}>
          {stray ? stray(current) : current || "(not set)"}
        </option>
      )}
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
  "aria-label": label,
}: {
  value: number | null | undefined;
  fallback: number;
  min: number;
  max: number;
  onChange: (v: number) => void;
  disabled?: boolean;
  "aria-label"?: string;
}) {
  const named = useRowLabel(label);
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
 * A slider from `min` to `max`, after `prefix` and with its value and `unit`
 * ("%", " dBm") beside it.
 */
export function RangeInput({
  value,
  fallback,
  min,
  max,
  unit,
  prefix,
  onChange,
  "aria-label": label,
}: {
  value: number | null | undefined;
  fallback: number;
  min: number;
  max: number;
  unit: string;
  prefix?: string;
  onChange: (v: number) => void;
  "aria-label": string;
}) {
  const named = useRowLabel(label);
  const shown = value ?? fallback;
  return (
    <label className="small">
      {prefix && `${prefix} `}
      <input
        {...named}
        type="range"
        min={min}
        max={max}
        value={shown}
        onChange={(e) => onChange(Number(e.target.value))}
      />{" "}
      {shown}
      {unit}
    </label>
  );
}

/**
 * A text field (class "search" unless given), named by its `Row`'s label, or
 * by its own `aria-label` where a row holds several; `onChange` gets the text.
 */
export function TextInput(
  props: Omit<InputHTMLAttributes<HTMLInputElement>, "value" | "onChange"> & {
    value: string | null | undefined;
    onChange: (v: string) => void;
  },
) {
  const named = useRowLabel(props["aria-label"]);
  return <TextField {...named} {...props} />;
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

/** `list` with `x` added (`on`, once) or removed: what a checkbox per item edits. */
export const toggled = <T,>(list: readonly T[], x: T, on: boolean): T[] =>
  on
    ? [...list, ...(list.includes(x) ? [] : [x])]
    : list.filter((y) => y !== x);

/**
 * A checkbox per AP; those in `value` are ticked. `value`'s MACs are read in any
 * form the server accepts, and a change sends them all as "aa:bb:…". An entry of
 * `value` that isn't one of `aps` (a forgotten AP) shows ticked, by its MAC, so
 * it can be unticked.
 */
export function ApChecklist({
  aps,
  value,
  onChange,
  disabled,
}: {
  aps: readonly { mac: string; name: string | null }[];
  value: readonly string[];
  onChange: (v: string[]) => void;
  disabled?: boolean;
}) {
  const macs = [...new Set(value.map(canonicalMac))];
  const stray = macs.filter((m) => !aps.some((a) => a.mac === m));
  return [
    ...aps.map((a) => ({ mac: a.mac, label: a.name ?? a.mac })),
    ...stray.map((m) => ({ mac: m, label: `${m} (not a known AP)` })),
  ].map((a) => (
    <Toggle
      key={a.mac}
      value={macs.includes(a.mac)}
      onChange={(on) => onChange(toggled(macs, a.mac, on))}
      disabled={disabled}
      label={a.label}
    />
  ));
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
  "aria-label": label,
}: {
  value: T[] | null | undefined;
  parse: (text: string) => T[];
  format: (v: T[]) => string;
  onChange: (v: T[]) => void;
  rows?: number;
  placeholder?: string;
  "aria-label"?: string;
}) {
  const named = useRowLabel(label);
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
