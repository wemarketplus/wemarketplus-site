import { DataTable, type Column } from '@/shared/ui/data-display';
import { formatDateTime } from '@/shared/utils/dateFormatter';
import type { AuditLogEntry, AuditLogTableProps } from '../types/complianceTypes';

const columns: ReadonlyArray<Column<AuditLogEntry>> = [
  {
    key: 'when',
    header: 'When',
    cell: (e) => (
      <span className="whitespace-nowrap text-muted">{formatDateTime(e.occurredAt)}</span>
    ),
  },
  {
    key: 'actor',
    header: 'Actor',
    cell: (e) => (
      <div className="min-w-0">
        <span className="block truncate text-[12.5px] font-semibold text-foreground">
          {e.actor}
        </span>
        {e.actorEmail && (
          <span className="block truncate text-[11px] text-muted">{e.actorEmail}</span>
        )}
      </div>
    ),
  },
  { key: 'action', header: 'Action', cell: (e) => e.action },
  { key: 'resource', header: 'Resource', cell: (e) => e.resource },
  {
    key: 'target',
    header: 'Record ID',
    cell: (e) => <span className="font-mono text-[11px] text-muted">{e.target}</span>,
  },
  {
    key: 'meta',
    header: 'Details',
    cell: (e) => <span className="text-[11px] text-muted">{e.meta}</span>,
  },
  {
    key: 'ip',
    header: 'IP',
    cell: (e) => <span className="font-mono text-[11px] text-muted">{e.ipAddress}</span>,
  },
];

export function AuditLogTable({ entries, loading, empty }: AuditLogTableProps) {
  if (loading) {
    return (
      <div className="rounded-card border border-border/[0.09] bg-surface p-10 text-center text-[13px] text-muted">
        Loading audit entries…
      </div>
    );
  }

  return (
    <DataTable
      columns={columns}
      rows={entries}
      rowKey={(e) => e.id}
      empty={empty ?? 'No audit entries match your filters.'}
    />
  );
}
