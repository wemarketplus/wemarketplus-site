import { DataTable, Pill, type Column } from '@/shared/ui/data-display';
import { formatDate } from '@/shared/utils/dateFormatter';
import { PortalShell } from '../components/PortalShell';
import { BAA_RECORDS_FIXTURE } from '../constants/portalContent';
import type { BaaRecord } from '../types/complianceTypes';

const columns: ReadonlyArray<Column<BaaRecord>> = [
  {
    key: 'org',
    header: 'Organization',
    cell: (r) => <span className="font-bold text-[#111]">{r.organization}</span>,
  },
  { key: 'signer', header: 'Signer', cell: (r) => r.signer },
  { key: 'signed', header: 'Signed', cell: (r) => formatDate(r.signedAt) },
  {
    key: 'status',
    header: 'Status',
    cell: (r) => <Pill tone={r.status === 'active' ? 'g' : 'y'}>{r.status}</Pill>,
  },
];

export function BaaRecordsPage() {
  return (
    <PortalShell
      title="Business Associate Agreements"
      description="HIPAA requires a signed BAA before any PHI access. Records stored permanently."
    >
      <DataTable columns={columns} rows={BAA_RECORDS_FIXTURE} rowKey={(r) => r.id} />
    </PortalShell>
  );
}
