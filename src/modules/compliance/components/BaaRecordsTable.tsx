import { DataTable, Pill, type Column } from '@/shared/ui/data-display';
import { formatDate } from '@/shared/utils/dateFormatter';
import type { BaaRecord, BaaRecordsTableProps } from '../types/complianceTypes';

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

export function BaaRecordsTable({ records }: BaaRecordsTableProps) {
  return <DataTable columns={columns} rows={records} rowKey={(r) => r.id} />;
}
