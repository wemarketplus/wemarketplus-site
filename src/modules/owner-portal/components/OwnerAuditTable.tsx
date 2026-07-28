import { DataTable, type Column } from '@/shared/ui/data-display';
import { formatDateTime } from '@/shared/utils/dateFormatter';
import type { OwnerAuditEntry, OwnerAuditTableProps } from '../types/ownerPortalTypes';

const columns: ReadonlyArray<Column<OwnerAuditEntry>> = [
  {
    key: 'actor',
    header: 'Actor',
    cell: (a) => <span className="font-bold text-foreground">{a.actor}</span>,
  },
  { key: 'action', header: 'Action', cell: (a) => a.action },
  { key: 'target', header: 'Target', cell: (a) => a.target },
  {
    key: 'ip',
    header: 'IP',
    cell: (a) => <span className="font-mono text-[11px] text-muted">{a.ipAddress}</span>,
  },
  { key: 'when', header: 'When', cell: (a) => formatDateTime(a.occurredAt) },
];

export function OwnerAuditTable({ entries }: OwnerAuditTableProps) {
  return <DataTable columns={columns} rows={entries} rowKey={(a) => a.id} />;
}
