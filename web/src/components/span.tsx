import { createContext } from "react";
import type { ReactNode } from "react";
import type { TimeSpan } from "../api";

// Apart from Chart.tsx, which loads Plot.tsx (and uPlot) on demand: Plot.tsx
// reads these, and importing them from Chart.tsx would be a cycle.

/** The page's time span: charts show exactly this window, gaps included. */
export const SpanContext = createContext<TimeSpan | null>(null);

/** When provided, dragging across a chart selects that time window for the whole page. */
export const ZoomContext = createContext<
  ((from: number, to: number) => void) | null
>(null);

/** Charts inside show `span`, and dragging across one sets it (`onSpan`). */
export function SpanScope({
  span,
  onSpan,
  children,
}: {
  span: TimeSpan;
  onSpan: (s: TimeSpan) => void;
  children: ReactNode;
}) {
  return (
    <ZoomContext.Provider value={(from, to) => onSpan({ from, to })}>
      <SpanContext.Provider value={span}>{children}</SpanContext.Provider>
    </ZoomContext.Provider>
  );
}
