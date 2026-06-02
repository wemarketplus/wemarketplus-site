import { DataTable, Pill, type Column } from '@/shared/ui/data-display';
import { type Apartment } from '@/shared/types';
import { APARTMENT_STATUS_LABEL, APARTMENT_STATUS_PILL } from '../constants/clOperationsConstants';

const columns: ReadonlyArray<Column<Apartment>> = [
  {
    key: 'unit',
    header: 'Unit',
    cell: (a) => <span className="font-bold text-[#111]">{a.unitNumber}</span>,
  },
  { key: 'type', header: 'Type', cell: (a) => a.unitType },
  { key: 'care', header: 'Care', cell: (a) => a.careLevel },
  {
    key: 'status',
    header: 'Status',
    cell: (a) => <Pill tone={APARTMENT_STATUS_PILL[a.status]}>{APARTMENT_STATUS_LABEL[a.status]}</Pill>,
  },
  { key: 'resident', header: 'Resident', cell: (a) => a.residentName ?? '—' },
  { key: 'rate', header: 'Rate', cell: (a) => `$${a.monthlyRate.toLocaleString()}` },
];

export function ApartmentsTable({ apartments }: { apartments: readonly Apartment[] }) {
  return <DataTable columns={columns} rows={apartments} rowKey={(a) => a.id} />;
}
