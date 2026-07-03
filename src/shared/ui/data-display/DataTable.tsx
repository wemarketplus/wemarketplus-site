import { useEffect, useRef, type ReactNode } from 'react';
import { cn } from '@/shared/utils/cn';

export interface Column<T> {
  key: string;
  header: ReactNode;
  // Cell renderer. Receives the row and its index.
  cell: (row: T, index: number) => ReactNode;
  className?: string;
  headerClassName?: string;
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

// Shared checkbox styling for the selection column — a compact box tuned for
// the light table (matches the #111 / #e4ecf5 palette of DataTable).
const CHECKBOX_CLASS =
  'h-3.5 w-3.5 cursor-pointer rounded border-[#c4d0e0] text-[#2563eb] accent-[#2563eb] focus:ring-1 focus:ring-[#2563eb]';

// Mirrors wemarketplus-site `.tbl`: a LIGHT (#fff / #111) table sitting inside
// the dark theme, 12px text, #f2f6fc header, hairline #edf2f9 row borders,
// 8-9px/11px cell padding, 12px radius, overflow hidden. This is a signature
// detail of the CRM — the data tables are white cards on the navy canvas.
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
      <div className="rounded-[12px] border border-white/[0.09] bg-surface p-10 text-center text-[13px] text-muted">
        {empty ?? 'Nothing to show yet.'}
      </div>
    );
  }

  return (
    <div className="overflow-hidden rounded-[12px]">
      <table className="w-full border-collapse bg-white text-[12px] text-[#111]">
        <thead>
          <tr>
            {selection && (
              <th className="w-9 border-b border-[#e4ecf5] bg-[#f2f6fc] px-[11px] py-2 text-left">
                <input
                  ref={headerCheckbox}
                  type="checkbox"
                  className={CHECKBOX_CLASS}
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
                  'border-b border-[#e4ecf5] bg-[#f2f6fc] px-[11px] py-2 text-left text-[10px] font-extrabold uppercase text-[#445]',
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
                className={cn('hover:bg-[#f8fbff]', isSelected && 'bg-[#eef5ff]')}
              >
                {selection && (
                  <td className="border-b border-[#edf2f9] px-[11px] py-[9px]">
                    <input
                      type="checkbox"
                      className={CHECKBOX_CLASS}
                      checked={isSelected}
                      onChange={() => selection.toggle(id)}
                      aria-label="Select row"
                    />
                  </td>
                )}
                {columns.map((c) => (
                  <td
                    key={c.key}
                    className={cn('border-b border-[#edf2f9] px-[11px] py-[9px]', c.className)}
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
