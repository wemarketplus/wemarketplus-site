import { DataTable, type Column } from '@/shared/ui/data-display';
import { formatDateTime } from '@/shared/utils/dateFormatter';
import { OwnerScreenHeader } from '../components/OwnerScreenHeader';
import { OWNER_AUDIT } from '../constants/ownerFixtures';
import type { OwnerAuditEntry } from '../types/ownerPortalTypes';

const columns: ReadonlyArray<Column<OwnerAuditEntry>> = [
  {
    key: 'actor',
    header: 'Actor',
    cell: (a) => <span className="font-bold text-[#111]">{a.actor}</span>,
  },
  { key: 'action', header: 'Action', cell: (a) => a.action },
  { key: 'target', header: 'Target', cell: (a) => a.target },
  {
    key: 'ip',
    header: 'IP',
    cell: (a) => <span className="font-mono text-[11px] text-[#667]">{a.ipAddress}</span>,
  },
  { key: 'when', header: 'When', cell: (a) => formatDateTime(a.occurredAt) },
];

export function OwnerSecurityPage() {
  return (
    <div className="space-y-6">
      <OwnerScreenHeader
        eyebrow="Owner portal"
        title="Security & audit"
        description="Every privileged action across the platform."
      />
      <DataTable columns={columns} rows={OWNER_AUDIT} rowKey={(a) => a.id} />
    </div>
  );
}
