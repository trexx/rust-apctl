import { useRef } from "react";
import type { ReactNode } from "react";

/**
 * A button that opens the file picker: a real button, so the keyboard reaches
 * it and `disabled` greys it out (a `<label>` around a hidden input does
 * neither). The same file can be chosen again, e.g. after a failed upload.
 */
export function FileButton({
  accept,
  disabled,
  className,
  onFile,
  children,
}: {
  accept: string;
  disabled?: boolean;
  className?: string;
  onFile: (f: File) => void;
  children: ReactNode;
}) {
  const input = useRef<HTMLInputElement>(null);
  return (
    <>
      <button
        className={className ?? "btn"}
        disabled={disabled}
        onClick={() => input.current?.click()}
      >
        {children}
      </button>
      <input
        ref={input}
        type="file"
        accept={accept}
        hidden
        disabled={disabled}
        onChange={(e) => {
          const f = e.target.files?.[0];
          e.target.value = "";
          if (f) onFile(f);
        }}
      />
    </>
  );
}
