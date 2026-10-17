/** Keys from what identifies each row, numbered when two rows share one. */
export function stableKeys<T>(rows: T[], id: (row: T) => string): string[] {
  const seen = new Map<string, number>();
  return rows.map((row) => {
    const k = id(row);
    const n = seen.get(k) ?? 0;
    seen.set(k, n + 1);
    return n ? `${k}#${n}` : k;
  });
}
