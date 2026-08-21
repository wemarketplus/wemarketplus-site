import { useEffect, useRef, type ReactNode } from 'react';
import { Checkbox } from '@/shared/ui/core';
import { cn } from '@/shared/utils/cn';

export interface Column<T> {
  key: string;
  header: ReactNode;
  // Cell renderer. Receives the row and its index.
  cell: (row: T, index: number) => ReactNode;
  // Applied to every <td> in this column.
  className?: string;
  // Applied to the <th>. Alignment is inherited from `className` automatically
  // (see alignmentOf) — set it here only to OVERRIDE that, or for width.
  headerClassName?: string;
}

/**
 * A column's text alignment, so the header can follow its cells.
 *
 * Headers were hardcoded `text-left` while cells were free to set `text-right`
 * via `className`, so any right-aligned column had its heading drifting off to
 * the opposite edge from the values underneath it. Every table declared the
 * alignment once, on the cells, and reasonably expected the header to match;
 * making each of 30-odd tables repeat itself in `headerClassName` would have
 * been the same bug waiting on the next column anyone adds.
 *
 * `headerClassName` still wins when it names an alignment of its own — cn()
 * runs tailwind-merge, so the later class replaces this one.
 */
function alignmentOf(className?: string): string | undefined {
  if (!className) return undefined;
  if (/\btext-right\b/.test(className)) return 'text-right';
  if (/\btext-center\b/.test(className)) return 'text-center';
  return undefined;
}

// Optional row-selection support. When passed, the table renders a leading
// checkbox column (header selects/clears the whole page, each row toggles
// itself). Entirely opt-in — omit `selection` and the table is unchanged, so
// existing consumers keep their exact markup.
export interface DataTableSelection {
  isSelected: (id: string) => boolean;
  toggle: (id: string) => void;
  // Header checkbox state, computed by the caller against the visible page ids.
  allSelected: boolean;
  someSelected: boolean;
  toggleAll: () => void;
}

interface DataTableProps<T> {
  columns: ReadonlyArray<Column<T>>;
  rows: readonly T[];
  rowKey: (row: T, index: number) => string;
  empty?: ReactNode;
  // Opt-in multi-select. The row id comes from `rowKey`.
  selection?: DataTableSelection;
}

// `.tbl`: 12px text, tinted header row, hairline row borders, 8-9px/11px cell
// padding, 12px radius, overflow hidden. Originally a light table islanded on
// the navy canvas with a blue-grey tint (#f2f6fc / #2563eb); now token-driven
// so it shares the neutral hairlines and green accent of the editorial theme.
export function DataTable<T>({ columns, rows, rowKey, empty, selection }: DataTableProps<T>) {
  // Native checkboxes have no `indeterminate` attribute — it's a DOM property.
  const headerCheckbox = useRef<HTMLInputElement>(null);
  useEffect(() => {
    if (headerCheckbox.current) {
      headerCheckbox.current.indeterminate = selection?.someSelected ?? false;
    }
  }, [selection?.someSelected, rows]);

  if (rows.length === 0) {
    return (
      <div className="rounded-[14px] border border-border/[0.09] bg-surface p-10 text-center text-[13px] text-muted">
        {empty ?? 'Nothing to show yet.'}
      </div>
    );
  }

  return (
    /**
     * `overflow-x-auto`, not `overflow-hidden`. Every list table has 7-10
     * columns (the tour scheduler runs to ten, actions included), which does
     * not fit a tablet viewport — `overflow-hidden` was silently cutting off
     * every column past Duration rather than making them reachable, so
     * Confirmation/Status/Outcome/actions simply did not exist below ~900px.
     * Scrolling the table horizontally keeps every column reachable without
     * touching the page's own layout — the body itself still never scrolls
     * sideways, only this element does.
     */
    <div className="overflow-x-auto rounded-[14px]">
      <table className="w-full min-w-max border-collapse bg-surface text-[12px] text-foreground">
        <thead>
          <tr>
            {selection && (
              <th className="w-9 border-b border-border/[0.09] bg-surface-elevated px-[11px] py-2 text-left">
                {/* The shared control, not a bare input with an
                    `accent-color`: see Checkbox for why the native widget read
                    as a black square once it was checked. */}
                <Checkbox
                  ref={headerCheckbox}
                  checked={selection.allSelected}
                  onChange={selection.toggleAll}
                  aria-label="Select all rows on this page"
                />
              </th>
            )}
            {columns.map((c) => (
              <th
                key={c.key}
                className={cn(
                  'border-b border-border/[0.09] bg-surface-elevated px-[11px] py-2 text-left align-middle text-[10px] font-extrabold uppercase tracking-[0.06em] text-muted',
                  alignmentOf(c.className),
                  c.headerClassName,
                )}
              >
                {c.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, i) => {
            const id = rowKey(row, i);
            const isSelected = selection?.isSelected(id) ?? false;
            return (
              <tr
                key={id}
                className={cn('hover:bg-primary/[0.03]', isSelected && 'bg-primary/[0.06]')}
              >
                {selection && (
                  <td className="border-b border-border/[0.07] px-[11px] py-[9px]">
                    <Checkbox
                      checked={isSelected}
                      onChange={() => selection.toggle(id)}
                      aria-label="Select row"
                    />
                  </td>
                )}
                {columns.map((c) => (
                  <td
                    key={c.key}
                    // `align-middle` so a cell holding a badge or an icon button
                    // sits on the same line as the plain-text cells beside it;
                    // without it a taller control pushes its row's text to the
                    // top and the row reads as two half-rows.
                    className={cn(
                      'border-b border-border/[0.07] px-[11px] py-[9px] align-middle',
                      c.className,
                    )}
                  >
                    {c.cell(row, i)}
                  </td>
                ))}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
