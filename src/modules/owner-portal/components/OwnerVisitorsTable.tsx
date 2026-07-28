import { DataTable, Pill, type Column } from '@/shared/ui/data-display';
import { formatRelative } from '@/shared/utils/dateFormatter';
import type { OwnerVisitor, OwnerVisitorsTableProps } from '../types/ownerPortalTypes';

const columns: ReadonlyArray<Column<OwnerVisitor>> = [
  { key: 'source', header: 'Source', cell: (v) => v.source },
  {
    key: 'landing',
    header: 'Landing page',
    cell: (v) => <span className="font-mono text-[11px] text-muted">{v.landingPage}</span>,
  },
  {
    key: 'session',
    header: 'Session',
    cell: (v) => `${Math.round(v.sessionLengthSec / 60)}m ${v.sessionLengthSec % 60}s`,
  },
  {
    key: 'converted',
    header: 'Converted',
    cell: (v) =>
      v.converted ? <Pill tone="g">Converted</Pill> : <Pill tone="b">Browsing</Pill>,
  },
  { key: 'when', header: 'When', cell: (v) => formatRelative(v.visitedAt) },
];

export function OwnerVisitorsTable({ visitors }: OwnerVisitorsTableProps) {
  return <DataTable columns={columns} rows={visitors} rowKey={(v) => v.id} />;
}
