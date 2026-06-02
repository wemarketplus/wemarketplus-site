import { DataTable, type Column } from '@/shared/ui/data-display';
import { formatDateTime } from '@/shared/utils/dateFormatter';
import type { AuditLogEntry, AuditLogTableProps } from '../types/complianceTypes';

const columns: ReadonlyArray<Column<AuditLogEntry>> = [
  {
    key: 'actor',
    header: 'Actor',
    cell: (e) => <span className="font-bold text-[#111]">{e.actor}</span>,
  },
  { key: 'action', header: 'Action', cell: (e) => e.action },
  { key: 'target', header: 'Target', cell: (e) => e.target },
  {
    key: 'ip',
    header: 'IP',
    cell: (e) => <span className="font-mono text-[11px] text-[#667]">{e.ipAddress}</span>,
  },
  { key: 'when', header: 'When', cell: (e) => formatDateTime(e.occurredAt) },
];

export function AuditLogTable({ entries }: AuditLogTableProps) {
  return (
    <DataTable
      columns={columns}
      rows={entries}
      rowKey={(e) => e.id}
      empty="No audit entries match your search."
    />
  );
}
