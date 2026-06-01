import type { ReactNode } from 'react';
import { cn } from '@/shared/utils/cn';

export interface Column<T> {
  key: string;
  header: ReactNode;
  // Cell renderer. Receives the row and its index.
  cell: (row: T, index: number) => ReactNode;
  className?: string;
  headerClassName?: string;
}

interface DataTableProps<T> {
  columns: ReadonlyArray<Column<T>>;
  rows: readonly T[];
  rowKey: (row: T, index: number) => string;
  empty?: ReactNode;
}

// Mirrors wemarketplus-site `.tbl`: a LIGHT (#fff / #111) table sitting inside
// the dark theme, 12px text, #f2f6fc header, hairline #edf2f9 row borders,
// 8-9px/11px cell padding, 12px radius, overflow hidden. This is a signature
// detail of the CRM — the data tables are white cards on the navy canvas.
export function DataTable<T>({ columns, rows, rowKey, empty }: DataTableProps<T>) {
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
          {rows.map((row, i) => (
            <tr key={rowKey(row, i)} className="hover:bg-[#f8fbff]">
              {columns.map((c) => (
                <td
                  key={c.key}
                  className={cn('border-b border-[#edf2f9] px-[11px] py-[9px]', c.className)}
                >
                  {c.cell(row, i)}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
